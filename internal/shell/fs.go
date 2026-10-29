package shell

import (
	"path"
	"sort"
	"strings"
	"time"
)

const (
	maxFiles    = 1000
	maxFileSize = 64 << 10
)

// fsNode is a file or directory in the in-memory filesystem. Nothing ever
// touches the real disk: writes by the attacker only live for the session.
type fsNode struct {
	dir   bool
	exec  bool
	data  string
	owner string
	mtime time.Time
}

type vfs struct {
	nodes map[string]*fsNode
}

var bootTime = time.Date(2024, 4, 15, 9, 52, 4, 0, time.UTC)

func newVFS(host, user, home string) *vfs {
	fs := &vfs{nodes: map[string]*fsNode{}}
	for _, d := range []string{
		"/", "/bin", "/boot", "/dev", "/dev/shm", "/etc", "/home", "/home/ubuntu", "/lib", "/opt",
		"/proc", "/root", "/root/.ssh", "/run", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/usr/bin",
		"/usr/local", "/usr/local/bin", "/usr/sbin", "/var", "/var/log", "/var/tmp", "/var/www", "/var/www/html", home,
	} {
		fs.nodes[d] = &fsNode{dir: true, owner: "root", mtime: bootTime}
	}
	files := map[string]string{
		"/etc/hostname":              host + "\n",
		"/etc/os-release":            osRelease,
		"/etc/issue":                 "Ubuntu 22.04.4 LTS \\n \\l\n\n",
		"/etc/passwd":                passwd(user),
		"/etc/shadow":                "",
		"/etc/resolv.conf":           "nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n",
		"/proc/cpuinfo":              cpuinfo(),
		"/proc/meminfo":              meminfo,
		"/proc/version":              "Linux version " + kernelRelease + " (buildd@lcy02-amd64-086) (x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38) " + kernelVersion + "\n",
		"/root/.bashrc":              "# ~/.bashrc: executed by bash(1) for non-login shells.\n",
		"/root/.ssh/authorized_keys": "",
		"/var/www/html/index.html":   "<html><body><h1>It works!</h1></body></html>\n",
		"/var/log/auth.log":          "",
		"/var/log/syslog":            "",
	}
	for p, data := range files {
		fs.nodes[p] = &fsNode{data: data, owner: "root", mtime: bootTime}
	}
	for _, b := range binaries {
		fs.nodes["/usr/bin/"+b] = &fsNode{exec: true, owner: "root", mtime: bootTime, data: "\x7fELF"}
	}
	fs.nodes["/bin/busybox"] = &fsNode{exec: true, owner: "root", mtime: bootTime, data: "\x7fELF"}
	return fs
}

func (fs *vfs) get(p string) (*fsNode, bool) {
	n, ok := fs.nodes[p]
	return n, ok
}

func (fs *vfs) isDir(p string) bool {
	n, ok := fs.nodes[p]
	return ok && n.dir
}

// write creates or replaces a regular file. It fails if the parent is missing.
func (fs *vfs) write(p, data string, appendTo bool, owner string) bool {
	if !fs.isDir(path.Dir(p)) {
		return false
	}
	n, ok := fs.nodes[p]
	if ok && n.dir {
		return false
	}
	if !ok {
		if len(fs.nodes) >= maxFiles {
			return false
		}
		n = &fsNode{owner: owner}
		fs.nodes[p] = n
	}
	if appendTo {
		data = n.data + data
	}
	if len(data) > maxFileSize {
		data = data[:maxFileSize]
	}
	n.data = data
	n.mtime = time.Now().UTC()
	return true
}

func (fs *vfs) mkdir(p, owner string, parents bool) bool {
	if fs.isDir(p) {
		return parents
	}
	if _, exists := fs.nodes[p]; exists || len(fs.nodes) >= maxFiles {
		return false
	}
	parent := path.Dir(p)
	if !fs.isDir(parent) {
		if !parents || !fs.mkdir(parent, owner, true) {
			return false
		}
	}
	fs.nodes[p] = &fsNode{dir: true, owner: owner, mtime: time.Now().UTC()}
	return true
}

func (fs *vfs) remove(p string, recursive bool) bool {
	n, ok := fs.nodes[p]
	if !ok || p == "/" {
		return false
	}
	if n.dir {
		children := fs.list(p)
		if len(children) > 0 && !recursive {
			return false
		}
		for _, c := range children {
			fs.remove(path.Join(p, c), true)
		}
	}
	delete(fs.nodes, p)
	return true
}

// list returns the sorted names of a directory's direct children.
func (fs *vfs) list(dir string) []string {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	var out []string
	for p := range fs.nodes {
		if p != "/" && strings.HasPrefix(p, prefix) && !strings.Contains(p[len(prefix):], "/") {
			out = append(out, p[len(prefix):])
		}
	}
	sort.Strings(out)
	return out
}

const (
	kernelRelease = "5.15.0-105-generic"
	kernelVersion = "#115-Ubuntu SMP Mon Apr 15 09:52:04 UTC 2024"
)

const osRelease = `PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
UBUNTU_CODENAME=jammy
`

const meminfo = `MemTotal:        8131380 kB
MemFree:          622308 kB
MemAvailable:    5412872 kB
Buffers:          208712 kB
Cached:          4386560 kB
SwapCached:            0 kB
Active:          3102620 kB
Inactive:        3633232 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
`

func passwd(user string) string {
	s := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
`
	if user != "root" && user != "ubuntu" {
		s += user + ":x:1001:1001::/home/" + user + ":/bin/bash\n"
	}
	return s
}

func cpuinfo() string {
	var b strings.Builder
	for i := range 4 {
		b.WriteString("processor\t: " + string(rune('0'+i)) + "\n")
		b.WriteString(`vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) Gold 6230R CPU @ 2.10GHz
stepping	: 7
cpu MHz		: 2095.078
cache size	: 36608 KB
cpu cores	: 4
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch avx2 avx512f
bogomips	: 4190.15

`)
	}
	return b.String()
}
