// Package shell emulates an Ubuntu bash session well enough to keep bots
// talking after they "log in". Nothing is ever executed: every command is
// interpreted against an in-memory filesystem and canned system state.
package shell

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	maxSegments = 64       // commands per line
	maxOutput   = 64 << 10 // bytes of output per line
	maxDepth    = 3        // nested sh -c
)

// Result is what a command line produced.
type Result struct {
	Output string
	Exit   bool // the attacker typed exit/logout
}

type Shell struct {
	host    string
	user    string
	home    string
	cwd     string
	env     map[string]string
	fs      *vfs
	history []string
	status  int
	started time.Time
	depth   int
}

// New creates a shell for user on a machine called host.
func New(host, user string) *Shell {
	home := "/root"
	if user != "root" {
		home = "/home/" + user
	}
	s := &Shell{
		host:    host,
		user:    user,
		home:    home,
		cwd:     home,
		started: time.Now(),
		env: map[string]string{
			"HOME":  home,
			"USER":  user,
			"SHELL": "/bin/bash",
			"PATH":  "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"PWD":   home,
			"TERM":  "xterm-256color",
			"LANG":  "C.UTF-8",
		},
	}
	s.fs = newVFS(host, user, home)
	return s
}

// Prompt returns the bash PS1 for the current directory.
func (s *Shell) Prompt() string {
	dir := s.cwd
	if dir == s.home {
		dir = "~"
	} else if strings.HasPrefix(dir, s.home+"/") {
		dir = "~" + dir[len(s.home):]
	}
	sign := "$"
	if s.user == "root" {
		sign = "#"
	}
	return fmt.Sprintf("%s@%s:%s%s ", s.user, s.host, dir, sign)
}

// Motd is printed right after login.
func (s *Shell) Motd(lastLoginIP string) string {
	return "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux " + kernelRelease + " x86_64)\n\n" +
		" * Documentation:  https://help.ubuntu.com\n" +
		" * Management:     https://landscape.canonical.com\n" +
		" * Support:        https://ubuntu.com/pro\n\n" +
		"  System information as of " + time.Now().UTC().Format("Mon Jan _2 15:04:05 MST 2006") + "\n\n" +
		"  System load:  0.08               Processes:             132\n" +
		"  Usage of /:   41.7% of 77.39GB   Users logged in:       0\n" +
		"  Memory usage: 31%                IPv4 address for eth0: 10.0.2.15\n" +
		"  Swap usage:   0%\n\n" +
		"Last login: " + time.Now().UTC().Add(-26*time.Hour).Format("Mon Jan _2 15:04:05 2006") + " from " + lastLoginIP + "\n"
}

func (s *Shell) getenv(k string) string {
	if k == "?" {
		return strconv.Itoa(s.status)
	}
	return s.env[k]
}

// Exec runs one command line.
func (s *Shell) Exec(line string) Result {
	if s.depth == 0 {
		s.history = append(s.history, line)
		if len(s.history) > 500 {
			s.history = s.history[1:]
		}
	}
	var out strings.Builder
	segments := 0
	for _, p := range parse(line, s.getenv) {
		if p.op == "&&" && s.status != 0 || p.op == "||" && s.status == 0 {
			continue
		}
		var (
			stdin string
			exit  bool
		)
		for _, c := range p.cmds {
			if segments++; segments > maxSegments {
				return Result{Output: out.String()}
			}
			var o string
			o, s.status, exit = s.run(c.args, stdin)
			if c.redirect != "" {
				if c.redirect != "/dev/null" && !s.fs.write(s.abs(c.redirect), o, c.appendTo, s.user) {
					o = "-bash: " + c.redirect + ": No such file or directory\n"
				} else {
					o = ""
				}
			}
			stdin = o
			if exit {
				break
			}
		}
		out.WriteString(stdin)
		if out.Len() > maxOutput || exit {
			return Result{Output: truncate(out.String()), Exit: exit}
		}
	}
	return Result{Output: truncate(out.String())}
}

func truncate(s string) string {
	if len(s) > maxOutput {
		return s[:maxOutput]
	}
	return s
}

func (s *Shell) abs(p string) string {
	switch {
	case p == "~":
		p = s.home
	case strings.HasPrefix(p, "~/"):
		p = s.home + p[1:]
	case !strings.HasPrefix(p, "/"):
		p = s.cwd + "/" + p
	}
	return path.Clean(p)
}

// run executes a single command and returns its output, exit status and
// whether the session should end.
func (s *Shell) run(args []string, stdin string) (string, int, bool) {
	if len(args) == 0 {
		return "", 0, false
	}
	name := args[0]
	// VAR=value prefix: set and continue.
	if i := strings.IndexByte(name, '='); i > 0 && !strings.Contains(name[:i], "/") {
		s.env[name[:i]] = name[i+1:]
		return s.run(args[1:], stdin)
	}
	if strings.Contains(name, "/") {
		p := s.abs(name)
		n, ok := s.fs.get(p)
		switch {
		case !ok:
			return "-bash: " + name + ": No such file or directory\n", 127, false
		case n.dir:
			return "-bash: " + name + ": Is a directory\n", 126, false
		case isBinary(path.Base(p)) && (strings.HasPrefix(p, "/bin/") || strings.HasPrefix(p, "/usr/") || strings.HasPrefix(p, "/sbin/")):
			name = path.Base(p) // /bin/busybox, /usr/bin/wget, ...
		case !n.exec:
			return "-bash: " + name + ": Permission denied\n", 126, false
		case strings.HasPrefix(n.data, "#!") || strings.HasSuffix(p, ".sh"):
			return s.script(n.data), s.status, false
		default:
			return "Segmentation fault (core dumped)\n", 139, false
		}
	}
	if fn, ok := commands[name]; ok {
		return fn(s, args[1:], stdin)
	}
	return "-bash: " + name + ": command not found\n", 127, false
}

// script runs the lines of a "downloaded" shell script.
func (s *Shell) script(data string) string {
	if s.depth >= maxDepth {
		return ""
	}
	s.depth++
	defer func() { s.depth-- }()
	var out strings.Builder
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out.WriteString(s.Exec(line).Output)
	}
	return out.String()
}

// History returns the commands typed so far.
func (s *Shell) History() []string { return append([]string(nil), s.history...) }
