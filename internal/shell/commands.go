package shell

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

type cmdFunc func(s *Shell, args []string, stdin string) (out string, status int, exit bool)

// commands is filled in init to break the initialization cycle
// (sudo, sh and busybox call back into Shell.run, which reads this map).
var (
	commands map[string]cmdFunc
	binaries []string
)

// builtins are shell keywords, not files in /usr/bin.
var builtins = map[string]bool{
	"cd": true, "export": true, "exit": true, "logout": true, "history": true, "set": true,
	"unset": true, "alias": true, "source": true, ".": true, "enable": true, "shell": true, "system": true,
}

func init() {
	commands = map[string]cmdFunc{
		"echo": cmdEcho, "printf": cmdPrintf, "pwd": cmdPwd, "cd": cmdCd, "ls": cmdLs, "dir": cmdLs, "cat": cmdCat,
		"whoami": cmdWhoami, "id": cmdID, "uname": cmdUname, "hostname": cmdHostname,
		"mkdir": cmdMkdir, "touch": cmdTouch, "rm": cmdRm, "cp": cmdCp, "mv": cmdMv, "chmod": cmdChmod,
		"chown": ok, "chattr": ok, "ln": ok, "sleep": ok, "kill": ok, "pkill": ok, "killall": ok,
		"sync": ok, "true": ok, "unset": ok, "alias": ok, "ulimit": ok, "nohup": cmdNohup, "cd..": ok,
		"false": func(*Shell, []string, string) (string, int, bool) { return "", 1, false },
		"exit":  cmdExit, "logout": cmdExit, "quit": cmdExit,
		"wget": cmdWget, "curl": cmdCurl, "tftp": cmdTftp, "ftpget": cmdTftp,
		"sh": cmdSh, "bash": cmdSh, "dash": cmdSh, "source": cmdSource, ".": cmdSource,
		"sudo": cmdSudo, "su": ok, "busybox": cmdBusybox,
		"ps": cmdPs, "top": cmdPs, "w": cmdW, "who": cmdWho, "uptime": cmdUptime, "free": cmdFree,
		"nproc": constant("4\n"), "lscpu": constant(lscpu), "df": cmdDf, "ifconfig": constant(ifconfig),
		"ip": cmdIP, "arch": constant("x86_64\n"), "date": cmdDate, "history": cmdHistory,
		"export": cmdExport, "env": cmdEnv, "set": cmdEnv, "printenv": cmdEnv, "which": cmdWhich, "type": cmdWhich,
		"crontab": cmdCrontab, "passwd": constant("passwd: Authentication token manipulation error\npasswd: password unchanged\n"),
		"chpasswd": ok, "useradd": ok, "usermod": ok,
		"service": ok, "systemctl": ok, "apt": cmdApt, "apt-get": cmdApt, "yum": cmdYum, "dnf": cmdYum,
		"grep": cmdGrep, "egrep": cmdGrep, "wc": cmdWc, "head": cmdHead, "tail": cmdTail, "sort": cmdSort,
		"uniq": cmdUniq, "awk": cmdPassthrough, "sed": cmdPassthrough, "tr": cmdPassthrough, "cut": cmdPassthrough,
		"tee": cmdTee, "base64": ok, "clear": constant("\x1b[H\x1b[2J"), "reset": ok,
		"enable": ok, "shell": ok, "system": ok, "linuxshell": ok,
		"lsb_release": constant("Distributor ID:\tUbuntu\nDescription:\tUbuntu 22.04.4 LTS\nRelease:\t22.04\nCodename:\tjammy\n"),
		"last":        constant("ubuntu   pts/0        10.0.2.2         Mon Apr 15 10:01   still logged in\n\nwtmp begins Mon Apr 15 09:52:04 2024\n"),
		"mount":       constant("/dev/sda1 on / type ext4 (rw,relatime)\nproc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\ntmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"),
	}
	for name := range commands {
		if !builtins[name] && !strings.ContainsAny(name, "./") {
			binaries = append(binaries, name)
		}
	}
	sort.Strings(binaries)
	// Tools a bot hopes for but that "aren't installed". Added after binaries
	// so `which python3` agrees with the error.
	for _, name := range []string{"python", "python3", "perl", "nc", "netcat", "gcc", "make", "docker"} {
		commands[name] = func(*Shell, []string, string) (string, int, bool) {
			return "-bash: " + name + ": command not found\n", 127, false
		}
	}
}

func isBinary(name string) bool {
	i := sort.SearchStrings(binaries, name)
	return i < len(binaries) && binaries[i] == name
}

func ok(*Shell, []string, string) (string, int, bool) { return "", 0, false }

func constant(out string) cmdFunc {
	return func(*Shell, []string, string) (string, int, bool) { return out, 0, false }
}

// flags splits "-la -n 5 file" style args into single-letter flags and operands.
func flags(args []string) (map[rune]bool, []string) {
	f := map[rune]bool{}
	var rest []string
	for i, a := range args {
		if a == "--" {
			rest = append(rest, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' && a[1] != '-' {
			for _, r := range a[1:] {
				f[r] = true
			}
			continue
		}
		if strings.HasPrefix(a, "--") {
			continue
		}
		rest = append(rest, a)
	}
	return f, rest
}

func cmdEcho(_ *Shell, args []string, _ string) (string, int, bool) {
	newline, escapes := true, false
	for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' && strings.Trim(args[0][1:], "neE") == "" {
		newline = newline && !strings.Contains(args[0], "n")
		escapes = escapes || strings.Contains(args[0], "e")
		args = args[1:]
	}
	out := strings.Join(args, " ")
	if escapes {
		out = strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\\`, `\`).Replace(out)
	}
	if newline {
		out += "\n"
	}
	return out, 0, false
}

func cmdPrintf(s *Shell, args []string, stdin string) (string, int, bool) {
	if len(args) == 0 {
		return "printf: usage: printf [-v var] format [arguments]\n", 2, false
	}
	return strings.NewReplacer(`\n`, "\n", `\t`, "\t").Replace(args[0]), 0, false
}

func cmdPwd(s *Shell, _ []string, _ string) (string, int, bool) { return s.cwd + "\n", 0, false }

func cmdCd(s *Shell, args []string, _ string) (string, int, bool) {
	target := s.home
	if len(args) > 0 {
		target = s.abs(args[0])
	}
	if !s.fs.isDir(target) {
		if _, exists := s.fs.get(target); exists {
			return "-bash: cd: " + args[0] + ": Not a directory\n", 1, false
		}
		return "-bash: cd: " + args[0] + ": No such file or directory\n", 1, false
	}
	s.cwd = target
	s.env["PWD"] = target
	return "", 0, false
}

func cmdLs(s *Shell, args []string, _ string) (string, int, bool) {
	f, paths := flags(args)
	if len(paths) == 0 {
		paths = []string{"."}
	}
	var out strings.Builder
	status := 0
	for i, p := range paths {
		abs := s.abs(p)
		n, exists := s.fs.get(abs)
		if !exists {
			fmt.Fprintf(&out, "ls: cannot access '%s': No such file or directory\n", p)
			status = 2
			continue
		}
		if len(paths) > 1 && n.dir {
			if i > 0 {
				out.WriteString("\n")
			}
			out.WriteString(p + ":\n")
		}
		names := []string{path.Base(abs)}
		dir := path.Dir(abs)
		if n.dir {
			dir = abs
			names = s.fs.list(abs)
			if f['a'] {
				names = append([]string{".", ".."}, names...)
			} else {
				names = slicesFilter(names, func(n string) bool { return !strings.HasPrefix(n, ".") })
			}
		}
		if !f['l'] {
			if len(names) > 0 {
				out.WriteString(strings.Join(names, "  ") + "\n")
			}
			continue
		}
		if n.dir {
			fmt.Fprintf(&out, "total %d\n", 4*len(names))
		}
		for _, name := range names {
			node, ok := s.fs.get(path.Join(dir, name))
			if !ok {
				node = &fsNode{dir: true, owner: "root", mtime: bootTime}
			}
			mode, size := "-rw-r--r--", len(node.data)
			if node.dir {
				mode, size = "drwxr-xr-x", 4096
			} else if node.exec {
				mode = "-rwxr-xr-x"
			}
			fmt.Fprintf(&out, "%s 1 %-4s %-4s %6d %s %s\n", mode, node.owner, node.owner, size, node.mtime.Format("Jan _2 15:04"), name)
		}
	}
	return out.String(), status, false
}

func slicesFilter(in []string, keep func(string) bool) []string {
	var out []string
	for _, x := range in {
		if keep(x) {
			out = append(out, x)
		}
	}
	return out
}

func cmdCat(s *Shell, args []string, stdin string) (string, int, bool) {
	_, files := flags(args)
	if len(files) == 0 {
		return stdin, 0, false
	}
	var out strings.Builder
	status := 0
	for _, f := range files {
		if f == "-" {
			out.WriteString(stdin)
			continue
		}
		n, ok := s.fs.get(s.abs(f))
		switch {
		case !ok:
			out.WriteString("cat: " + f + ": No such file or directory\n")
			status = 1
		case n.dir:
			out.WriteString("cat: " + f + ": Is a directory\n")
			status = 1
		case f == "/etc/shadow" && s.user != "root":
			out.WriteString("cat: /etc/shadow: Permission denied\n")
			status = 1
		default:
			out.WriteString(n.data)
		}
	}
	return out.String(), status, false
}

func cmdWhoami(s *Shell, _ []string, _ string) (string, int, bool) { return s.user + "\n", 0, false }

func (s *Shell) uid() int {
	switch s.user {
	case "root":
		return 0
	case "ubuntu":
		return 1000
	}
	return 1001
}

func cmdID(s *Shell, _ []string, _ string) (string, int, bool) {
	u := s.uid()
	if u == 0 {
		return "uid=0(root) gid=0(root) groups=0(root)\n", 0, false
	}
	return fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%d(%s),27(sudo)\n", u, s.user, u, s.user, u, s.user), 0, false
}

func cmdUname(s *Shell, args []string, _ string) (string, int, bool) {
	f, _ := flags(args)
	if f['a'] {
		return "Linux " + s.host + " " + kernelRelease + " " + kernelVersion + " x86_64 x86_64 x86_64 GNU/Linux\n", 0, false
	}
	parts := []struct {
		flag rune
		val  string
	}{{'s', "Linux"}, {'n', s.host}, {'r', kernelRelease}, {'v', kernelVersion}, {'m', "x86_64"}, {'p', "x86_64"}, {'i', "x86_64"}, {'o', "GNU/Linux"}}
	var out []string
	for _, p := range parts {
		if f[p.flag] {
			out = append(out, p.val)
		}
	}
	if len(out) == 0 {
		out = []string{"Linux"}
	}
	return strings.Join(out, " ") + "\n", 0, false
}

func cmdHostname(s *Shell, _ []string, _ string) (string, int, bool) { return s.host + "\n", 0, false }

func cmdMkdir(s *Shell, args []string, _ string) (string, int, bool) {
	f, dirs := flags(args)
	var out strings.Builder
	status := 0
	for _, d := range dirs {
		if !s.fs.mkdir(s.abs(d), s.user, f['p']) {
			out.WriteString("mkdir: cannot create directory '" + d + "': File exists\n")
			status = 1
		}
	}
	return out.String(), status, false
}

func cmdTouch(s *Shell, args []string, _ string) (string, int, bool) {
	_, files := flags(args)
	for _, f := range files {
		p := s.abs(f)
		if _, exists := s.fs.get(p); !exists && !s.fs.write(p, "", false, s.user) {
			return "touch: cannot touch '" + f + "': No such file or directory\n", 1, false
		}
	}
	return "", 0, false
}

func cmdRm(s *Shell, args []string, _ string) (string, int, bool) {
	f, files := flags(args)
	var out strings.Builder
	for _, file := range files {
		p := s.abs(file)
		if s.fs.isDir(p) && !f['r'] && !f['R'] {
			out.WriteString("rm: cannot remove '" + file + "': Is a directory\n")
			continue
		}
		if !s.fs.remove(p, true) && !f['f'] {
			out.WriteString("rm: cannot remove '" + file + "': No such file or directory\n")
		}
	}
	return out.String(), 0, false
}

func cmdCp(s *Shell, args []string, _ string) (string, int, bool) {
	_, ops := flags(args)
	if len(ops) < 2 {
		return "cp: missing destination file operand\n", 1, false
	}
	src, ok := s.fs.get(s.abs(ops[0]))
	if !ok || src.dir {
		return "cp: cannot stat '" + ops[0] + "': No such file or directory\n", 1, false
	}
	dst := s.abs(ops[1])
	if s.fs.isDir(dst) {
		dst = path.Join(dst, path.Base(ops[0]))
	}
	s.fs.write(dst, src.data, false, s.user)
	if n, ok := s.fs.get(dst); ok {
		n.exec = src.exec
	}
	return "", 0, false
}

func cmdMv(s *Shell, args []string, stdin string) (string, int, bool) {
	out, status, _ := cmdCp(s, args, stdin)
	if status == 0 {
		_, ops := flags(args)
		s.fs.remove(s.abs(ops[0]), true)
	}
	return strings.ReplaceAll(out, "cp:", "mv:"), status, false
}

func cmdChmod(s *Shell, args []string, _ string) (string, int, bool) {
	if len(args) < 2 {
		return "chmod: missing operand\n", 1, false
	}
	mode := args[0]
	exec := strings.Contains(mode, "x") || strings.ContainsAny(mode, "1357") && !strings.HasPrefix(mode, "-")
	for _, f := range args[1:] {
		n, ok := s.fs.get(s.abs(f))
		if !ok {
			return "chmod: cannot access '" + f + "': No such file or directory\n", 1, false
		}
		n.exec = exec
	}
	return "", 0, false
}

func cmdExit(*Shell, []string, string) (string, int, bool) { return "logout\n", 0, true }

func cmdNohup(s *Shell, args []string, stdin string) (string, int, bool) {
	out, st, exit := s.run(args, stdin)
	if out != "" {
		out = "nohup: ignoring input and appending output to 'nohup.out'\n"
	}
	return out, st, exit
}

// payload is what every "download" contains. It looks like an ELF header to
// file(1)-style checks and is inert.
const payload = "\x7fELF\x02\x01\x01\x00"

func urlFile(u string) string {
	u = strings.SplitN(u, "?", 2)[0]
	name := path.Base(strings.TrimSuffix(u, "/"))
	if name == "" || name == "." || strings.Contains(name, ":") {
		return "index.html"
	}
	return name
}

func urlHost(u string) string {
	h := u
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?"); i >= 0 {
		h = h[:i]
	}
	return h
}

func cmdWget(s *Shell, args []string, _ string) (string, int, bool) {
	var (
		urls          []string
		outFile       string
		quiet, stdout bool
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-O" && i+1 < len(args):
			i++
			outFile = args[i]
			stdout = outFile == "-"
		case strings.HasPrefix(a, "-O") && len(a) > 2:
			outFile = a[2:]
			stdout = outFile == "-"
		case a == "-q" || a == "-qO-" || a == "--quiet":
			quiet = true
			stdout = stdout || a == "-qO-"
		case strings.HasPrefix(a, "-"):
		default:
			urls = append(urls, a)
		}
	}
	if len(urls) == 0 {
		return "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n", 1, false
	}
	var out strings.Builder
	for _, u := range urls {
		if !strings.Contains(u, "://") {
			u = "http://" + u
		}
		name := outFile
		if name == "" {
			name = urlFile(u)
		}
		host := urlHost(u)
		if !quiet {
			ts := time.Now().UTC().Format("2006-01-02 15:04:05")
			fmt.Fprintf(&out, "--%s--  %s\nResolving %s (%s)... %s\nConnecting to %s (%s)|%s|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: 1342776 (1.3M) [application/octet-stream]\nSaving to: '%s'\n\n%s           100%%[===================>]   1.28M  4.21MB/s    in 0.3s\n\n%s (4.21 MB/s) - '%s' saved [1342776/1342776]\n\n",
				ts, u, host, host, host, host, host, host, name, name, ts, name)
		}
		if stdout {
			continue
		}
		s.fs.write(s.abs(name), payload, false, s.user)
	}
	return out.String(), 0, false
}

func cmdCurl(s *Shell, args []string, _ string) (string, int, bool) {
	var (
		urls    []string
		outFile string
		remote  bool
	)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-o" && i+1 < len(args):
			i++
			outFile = args[i]
		case a == "-O" || a == "--remote-name":
			remote = true
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if strings.Contains(a, "O") {
				remote = true
			}
			if strings.ContainsAny(a, "HdXAeu") && i+1 < len(args) { // flags with a value
				i++
			}
		default:
			urls = append(urls, a)
		}
	}
	if len(urls) == 0 {
		return "curl: try 'curl --help' or 'curl --manual' for more information\n", 2, false
	}
	for _, u := range urls {
		name := outFile
		if name == "" && remote {
			name = urlFile(u)
		}
		if name != "" {
			s.fs.write(s.abs(name), payload, false, s.user)
		}
	}
	return "", 0, false
}

func cmdTftp(s *Shell, args []string, _ string) (string, int, bool) {
	// busybox tftp -g -r FILE HOST
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-r" || args[i] == "-l" {
			s.fs.write(s.abs(path.Base(args[i+1])), payload, false, s.user)
		}
	}
	return "", 0, false
}

func cmdSh(s *Shell, args []string, stdin string) (string, int, bool) {
	if s.depth >= maxDepth {
		return "", 0, false
	}
	for i, a := range args {
		if a == "-c" && i+1 < len(args) {
			s.depth++
			res := s.Exec(args[i+1])
			s.depth--
			return res.Output, s.status, res.Exit
		}
	}
	if len(args) > 0 {
		return cmdSource(s, args, stdin)
	}
	if stdin != "" { // curl ... | sh
		return s.script(stdin), s.status, false
	}
	return "", 0, false
}

func cmdSource(s *Shell, args []string, _ string) (string, int, bool) {
	if len(args) == 0 {
		return "-bash: source: filename argument required\n", 2, false
	}
	n, ok := s.fs.get(s.abs(args[0]))
	if !ok || n.dir {
		return "bash: " + args[0] + ": No such file or directory\n", 127, false
	}
	if strings.HasPrefix(n.data, "\x7fELF") {
		return "bash: " + args[0] + ": cannot execute binary file\n", 126, false
	}
	return s.script(n.data), s.status, false
}

func cmdSudo(s *Shell, args []string, stdin string) (string, int, bool) {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		args = args[1:]
	}
	if len(args) == 0 {
		return "usage: sudo -h | -K | -k | -V\n", 1, false
	}
	return s.run(args, stdin)
}

func cmdBusybox(s *Shell, args []string, stdin string) (string, int, bool) {
	if len(args) == 0 {
		return "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3) multi-call binary.\n", 0, false
	}
	if isBinary(args[0]) {
		return s.run(args, stdin)
	}
	// Mirai-style bots send "/bin/busybox RANDOMWORD" and look for this exact reply.
	return args[0] + ": applet not found\n", 127, false
}

func cmdPs(s *Shell, _ []string, _ string) (string, int, bool) {
	return `    PID TTY          TIME CMD
      1 ?        00:00:04 systemd
    412 ?        00:00:00 systemd-journal
    655 ?        00:00:01 systemd-resolve
    781 ?        00:00:00 cron
    790 ?        00:00:02 rsyslogd
    812 ?        00:00:00 sshd
   1043 ?        00:01:13 mysqld
   1188 ?        00:00:03 nginx
   2214 pts/0    00:00:00 bash
   2290 pts/0    00:00:00 ps
`, 0, false
}

func (s *Shell) uptime() string {
	up := time.Since(bootTime)
	days := int(up.Hours()) / 24
	return fmt.Sprintf(" %s up %d days, %2d:%02d,  1 user,  load average: 0.08, 0.03, 0.01\n",
		time.Now().UTC().Format("15:04:05"), days, int(up.Hours())%24, int(up.Minutes())%60)
}

func cmdUptime(s *Shell, _ []string, _ string) (string, int, bool) { return s.uptime(), 0, false }

func cmdW(s *Shell, _ []string, _ string) (string, int, bool) {
	return s.uptime() + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n" +
		fmt.Sprintf("%-8s pts/0    -                %s    0.00s  0.01s  0.00s w\n", s.user, s.started.UTC().Format("15:04")), 0, false
}

func cmdWho(s *Shell, _ []string, _ string) (string, int, bool) {
	return fmt.Sprintf("%-8s pts/0        %s\n", s.user, s.started.UTC().Format("2006-01-02 15:04")), 0, false
}

func cmdFree(s *Shell, args []string, _ string) (string, int, bool) {
	f, _ := flags(args)
	if f['h'] {
		return "               total        used        free      shared  buff/cache   available\nMem:           7.8Gi       2.4Gi       607Mi        11Mi       4.8Gi       5.2Gi\nSwap:          2.0Gi          0B       2.0Gi\n", 0, false
	}
	if f['m'] {
		return "               total        used        free      shared  buff/cache   available\nMem:            7940        2453         607          11        4879        5286\nSwap:           2047           0        2047\n", 0, false
	}
	return "               total        used        free      shared  buff/cache   available\nMem:         8131380     2512312      622308       11896     4996760     5412872\nSwap:        2097148           0     2097148\n", 0, false
}

func cmdDf(s *Shell, args []string, _ string) (string, int, bool) {
	return "Filesystem      Size  Used Avail Use% Mounted on\ntmpfs           795M  1.1M  794M   1% /run\n/dev/sda1        78G   33G   45G  42% /\ntmpfs           3.9G     0  3.9G   0% /dev/shm\n/dev/sda15      105M  6.1M   99M   6% /boot/efi\n", 0, false
}

func cmdIP(s *Shell, args []string, stdin string) (string, int, bool) {
	if len(args) > 0 && (strings.HasPrefix(args[0], "a") || strings.HasPrefix(args[0], "-")) {
		return ipAddr, 0, false
	}
	if len(args) > 0 && strings.HasPrefix(args[0], "r") {
		return "default via 10.0.2.2 dev eth0 proto dhcp src 10.0.2.15 metric 100\n10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15\n", 0, false
	}
	return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n", 255, false
}

func cmdDate(*Shell, []string, string) (string, int, bool) {
	return time.Now().UTC().Format("Mon Jan _2 15:04:05 MST 2006") + "\n", 0, false
}

func cmdHistory(s *Shell, args []string, _ string) (string, int, bool) {
	if len(args) > 0 && args[0] == "-c" {
		s.history = nil
		return "", 0, false
	}
	var out strings.Builder
	for i, h := range s.history {
		fmt.Fprintf(&out, "%5d  %s\n", i+1, h)
	}
	return out.String(), 0, false
}

func cmdExport(s *Shell, args []string, stdin string) (string, int, bool) {
	for _, a := range args {
		if k, v, found := strings.Cut(a, "="); found {
			s.env[k] = v
		}
	}
	if len(args) == 0 {
		return cmdEnv(s, nil, stdin)
	}
	return "", 0, false
}

func cmdEnv(s *Shell, _ []string, _ string) (string, int, bool) {
	keys := make([]string, 0, len(s.env))
	for k := range s.env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, k := range keys {
		out.WriteString(k + "=" + s.env[k] + "\n")
	}
	return out.String(), 0, false
}

func cmdWhich(s *Shell, args []string, _ string) (string, int, bool) {
	var out strings.Builder
	status := 0
	for _, a := range args {
		if isBinary(a) {
			out.WriteString("/usr/bin/" + a + "\n")
		} else {
			status = 1
		}
	}
	return out.String(), status, false
}

func cmdCrontab(s *Shell, args []string, stdin string) (string, int, bool) {
	f, rest := flags(args)
	switch {
	case f['l']:
		if n, ok := s.fs.get("/var/spool/cron/" + s.user); ok {
			return n.data, 0, false
		}
		return "no crontab for " + s.user + "\n", 1, false
	case f['r']:
		s.fs.remove("/var/spool/cron/"+s.user, false)
		return "", 0, false
	}
	data := stdin
	if len(rest) > 0 && rest[0] != "-" {
		if n, ok := s.fs.get(s.abs(rest[0])); ok {
			data = n.data
		}
	}
	s.fs.mkdir("/var/spool/cron", "root", true)
	s.fs.write("/var/spool/cron/"+s.user, data, false, s.user)
	return "", 0, false
}

func cmdApt(s *Shell, args []string, _ string) (string, int, bool) {
	if s.uid() != 0 {
		return "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\nE: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n", 100, false
	}
	_, ops := flags(args)
	if len(ops) > 1 && ops[0] == "install" {
		return "Reading package lists... Done\nBuilding dependency tree... Done\nReading state information... Done\nE: Unable to locate package " + ops[1] + "\n", 100, false
	}
	return "Reading package lists... Done\n", 0, false
}

func cmdYum(*Shell, []string, string) (string, int, bool) {
	return "-bash: yum: command not found\n", 127, false
}

// input returns the text a filter command works on: files if given, else stdin.
func (s *Shell) input(files []string, stdin string) string {
	if len(files) == 0 {
		return stdin
	}
	var b strings.Builder
	for _, f := range files {
		if n, ok := s.fs.get(s.abs(f)); ok && !n.dir {
			b.WriteString(n.data)
		}
	}
	return b.String()
}

func lines(text string) []string {
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func joinLines(ls []string) string {
	if len(ls) == 0 {
		return ""
	}
	return strings.Join(ls, "\n") + "\n"
}

func cmdGrep(s *Shell, args []string, stdin string) (string, int, bool) {
	var (
		pattern string
		files   []string
		f       = map[rune]bool{}
	)
	for _, a := range args {
		switch {
		case len(a) > 1 && a[0] == '-' && pattern == "":
			for _, r := range a[1:] {
				f[r] = true
			}
		case pattern == "":
			pattern = a
		default:
			files = append(files, a)
		}
	}
	if pattern == "" {
		return "Usage: grep [OPTION]... PATTERNS [FILE]...\n", 2, false
	}
	var matched []string
	for _, l := range lines(s.input(files, stdin)) {
		hay, needle := l, pattern
		if f['i'] {
			hay, needle = strings.ToLower(l), strings.ToLower(pattern)
		}
		if strings.Contains(hay, needle) != f['v'] {
			matched = append(matched, l)
		}
	}
	if f['c'] {
		return strconv.Itoa(len(matched)) + "\n", 0, false
	}
	if len(matched) == 0 {
		return "", 1, false
	}
	return joinLines(matched), 0, false
}

func cmdWc(s *Shell, args []string, stdin string) (string, int, bool) {
	f, files := flags(args)
	text := s.input(files, stdin)
	l, w, c := strings.Count(text, "\n"), len(strings.Fields(text)), len(text)
	switch {
	case f['l']:
		return strconv.Itoa(l) + "\n", 0, false
	case f['w']:
		return strconv.Itoa(w) + "\n", 0, false
	case f['c'] || f['m']:
		return strconv.Itoa(c) + "\n", 0, false
	}
	return fmt.Sprintf("%7d %7d %7d\n", l, w, c), 0, false
}

// count parses "-n 5", "-n5" and "-5".
func count(args []string) (int, []string) {
	n := 10
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-n" && i+1 < len(args):
			n, _ = strconv.Atoi(args[i+1])
			i++
		case strings.HasPrefix(a, "-n"):
			n, _ = strconv.Atoi(a[2:])
		case strings.HasPrefix(a, "-") && len(a) > 1:
			if v, err := strconv.Atoi(a[1:]); err == nil {
				n = v
			}
		default:
			rest = append(rest, a)
		}
	}
	return n, rest
}

func cmdHead(s *Shell, args []string, stdin string) (string, int, bool) {
	n, files := count(args)
	ls := lines(s.input(files, stdin))
	if n < len(ls) {
		ls = ls[:n]
	}
	return joinLines(ls), 0, false
}

func cmdTail(s *Shell, args []string, stdin string) (string, int, bool) {
	n, files := count(args)
	ls := lines(s.input(files, stdin))
	if n < len(ls) {
		ls = ls[len(ls)-n:]
	}
	return joinLines(ls), 0, false
}

func cmdSort(s *Shell, args []string, stdin string) (string, int, bool) {
	f, files := flags(args)
	ls := lines(s.input(files, stdin))
	sort.Strings(ls)
	if f['r'] {
		for i, j := 0, len(ls)-1; i < j; i, j = i+1, j-1 {
			ls[i], ls[j] = ls[j], ls[i]
		}
	}
	return joinLines(ls), 0, false
}

func cmdUniq(s *Shell, args []string, stdin string) (string, int, bool) {
	_, files := flags(args)
	var out []string
	for _, l := range lines(s.input(files, stdin)) {
		if len(out) == 0 || out[len(out)-1] != l {
			out = append(out, l)
		}
	}
	return joinLines(out), 0, false
}

// cmdPassthrough stands in for text tools we don't model (awk, sed, ...).
func cmdPassthrough(s *Shell, args []string, stdin string) (string, int, bool) {
	return stdin, 0, false
}

func cmdTee(s *Shell, args []string, stdin string) (string, int, bool) {
	f, files := flags(args)
	for _, file := range files {
		s.fs.write(s.abs(file), stdin, f['a'], s.user)
	}
	return stdin, 0, false
}

const lscpu = `Architecture:            x86_64
  CPU op-mode(s):        32-bit, 64-bit
  Address sizes:         46 bits physical, 48 bits virtual
  Byte Order:            Little Endian
CPU(s):                  4
  On-line CPU(s) list:   0-3
Vendor ID:               GenuineIntel
  Model name:            Intel(R) Xeon(R) Gold 6230R CPU @ 2.10GHz
    CPU family:          6
    Model:               85
    Thread(s) per core:  1
    Core(s) per socket:  4
    Socket(s):           1
Virtualization features:
  Hypervisor vendor:     KVM
  Virtualization type:   full
`

const ifconfig = `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::a00:27ff:fe8d:c04d  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:8d:c0:4d  txqueuelen 1000  (Ethernet)
        RX packets 1584216  bytes 1832517719 (1.8 GB)
        TX packets 812554  bytes 97713461 (97.7 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
`

const ipAddr = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:8d:c0:4d brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 metric 100 brd 10.0.2.255 scope global dynamic eth0
       valid_lft 85234sec preferred_lft 85234sec
`
