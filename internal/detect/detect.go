// Package detect tags attacker input with the technique it most likely
// represents. The rules are deliberately simple regular expressions: they're
// for triage on the dashboard, not a replacement for a real IDS.
package detect

import (
	"net/url"
	"regexp"
	"sort"
	"unicode/utf8"
)

type rule struct {
	tag string
	re  *regexp.Regexp
}

func rules(pairs ...string) []rule {
	out := make([]rule, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, rule{pairs[i], regexp.MustCompile(pairs[i+1])})
	}
	return out
}

// HTTP tags: matched against the decoded request line and body.
var httpRules = rules(
	"sqli", `(?i)(union[\s(/*+]+(all[\s(/*+]+)?select|'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+|\b(sleep|benchmark|pg_sleep)\s*\(|information_schema|waitfor\s+delay|'\s*--)`,
	"xss", `(?i)(<script|javascript:|\bon(error|load|mouseover)\s*=|<svg[\s/]|<img[^>]+src\s*=)`,
	"path_traversal", `(?i)(\.\./|\.\.\\|/etc/(passwd|shadow)|win\.ini|boot\.ini)`,
	"cmd_injection", `(?i)([;|&]\s*(wget|curl|sh|bash|nc|cat|id|uname|chmod|busybox)\b|\$\(|`+"`"+`[^`+"`"+`]+`+"`"+`)`,
	"secrets_probe", `(?i)/(\.env|\.git/(config|HEAD)|\.aws/|\.ssh/|\.docker/|config\.(json|php|yml)|wp-config\.php|\.htpasswd|id_rsa|credentials)`,
	"recon_probe", `(?i)/(phpinfo|server-status|server-info|actuator|_profiler|debug|console|\.DS_Store|telescope)`,
	"wordpress", `(?i)/(wp-login\.php|wp-admin|wp-content|wp-includes|xmlrpc\.php|wp-json)`,
	"iot_exploit", `(?i)/(cgi-bin/|boaform/|HNAP1|GponForm|setup\.cgi|shell\?|goform/|tmUnblock\.cgi|device\.rsp)`,
	"php_exploit", `(?i)(phpunit/.*eval-stdin\.php|allow_url_include|auto_prepend_file|php://input|/vendor/)`,
)

var log4shell = regexp.MustCompile(`(?i)\$\{(jndi|\$\{lower:j\}|env:|sys:)`)

// Scanner user agents.
var scannerUA = regexp.MustCompile(`(?i)(zgrab|masscan|nmap|nikto|sqlmap|nuclei|censys|shodan|expanse|internet-measurement|python-requests|go-http-client|libwww-perl|curl/|wget/|httpx|fuzz)`)

// HTTP classifies a request. headers should contain values attackers commonly
// abuse (User-Agent, Referer, X-Api-Version, ...), they're scanned for log4shell.
func HTTP(method, uri, body string, headers ...string) []string {
	text := decode(uri) + "\n" + decode(body)
	tags := map[string]bool{}
	for _, r := range httpRules {
		if r.re.MatchString(text) {
			tags[r.tag] = true
		}
	}
	if log4shell.MatchString(text) {
		tags["log4shell"] = true
	}
	for _, h := range headers {
		if log4shell.MatchString(h) { // log4shell payloads hide in headers
			tags["log4shell"] = true
		}
		if scannerUA.MatchString(h) {
			tags["scanner"] = true
		}
	}
	if method != "GET" && method != "POST" && method != "HEAD" && method != "OPTIONS" {
		tags["unusual_method"] = true
	}
	return sorted(tags)
}

// Command tags: what a post-login shell command is trying to achieve,
// loosely following MITRE ATT&CK tactics.
var commandRules = rules(
	"download", `(?i)\b(wget|curl|tftp|ftpget|scp)\b|/dev/tcp/`,
	"recon", `(?i)(\buname\b|/proc/(cpuinfo|meminfo|version)|\bnproc\b|\blscpu\b|\bfree\b|\bwhoami\b|^\s*id\b|[;&|]\s*id\b|\bifconfig\b|\bip\s+(a|addr)\b|\bw\b\s*$|\bhostname\b|\bdf\b|\bps\b|\bcat\s+/etc/(passwd|issue|os-release))`,
	"persistence", `(?i)(crontab|authorized_keys|/etc/rc\.local|systemctl\s+enable|\.bashrc|\.profile|/etc/init\.d/|useradd|adduser|chpasswd|passwd\b)`,
	"cryptominer", `(?i)(xmrig|minerd|stratum\+tcp|cryptonight|kdevtmpfsi|kinsing|c3pool|nanopool|monero)`,
	"defense_evasion", `(?i)(history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null|rm\s+-rf\s+/var/log|chattr\s|pkill|killall|kill\s+-9|ufw\s+disable|iptables\s+-F|setenforce\s+0)`,
	"execution", `(?i)(chmod\s+(\+x|[0-7]*7[0-7]*)\b|\b(sh|bash)\s+\S+\.sh|\./\S+|\b(python3?|perl)\s+-[ec]|base64\s+-d)`,
	"botnet", `(?i)(/bin/busybox|\bbusybox\b|\bmirai\b|\benable\b\s*$|\bshell\b\s*$|\bsystem\b\s*$|\blinuxshell\b)`,
	"lateral", `(?i)(\bssh\s+\S+@|sshpass|\bnmap\b|\bmasscan\b|\bzmap\b)`,
)

// Command classifies a shell command line.
func Command(line string) []string {
	tags := map[string]bool{}
	for _, r := range commandRules {
		if r.re.MatchString(line) {
			tags[r.tag] = true
		}
	}
	return sorted(tags)
}

// URLs extracts http(s)/ftp URLs from a command, e.g. the payload a bot tries to fetch.
var urlRe = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://[^\s'"|;&<>` + "`" + `]+`)

func URLs(line string) []string {
	return urlRe.FindAllString(line, 10)
}

func decode(s string) string {
	// Attackers double-encode to slip past naive filters, so unescape twice.
	for range 2 {
		d, err := url.QueryUnescape(s)
		if err != nil || d == s {
			break
		}
		s = d
	}
	return s
}

func sorted(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
