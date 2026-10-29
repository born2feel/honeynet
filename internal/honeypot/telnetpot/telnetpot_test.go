package telnetpot

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/honeypot"
	"github.com/born2feel/honeynet/internal/netutil"
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

func (c *collector) snapshot() []event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event.Event(nil), c.events...)
}

func readUntil(t *testing.T, conn net.Conn, want string) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var buf bytes.Buffer
	tmp := make([]byte, 1024)
	for !strings.Contains(buf.String(), want) {
		n, err := conn.Read(tmp)
		buf.Write(tmp[:n])
		if err != nil {
			t.Fatalf("waiting for %q: %v; got %q", want, err, buf.String())
		}
	}
	return buf.String()
}

func TestMiraiStyleSession(t *testing.T) {
	c := &collector{}
	srv := New(Config{Hostname: "cam-01", Limits: honeypot.Limits{Idle: 5 * time.Second, MaxDuration: time.Minute, MaxCommands: 10}},
		c, netutil.NewLimiter(4, 4), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	readUntil(t, conn, "login: ")
	// Client-side negotiation bytes must be ignored; CRLF line endings must work.
	conn.Write([]byte{iac, do, optEcho, iac, will, 31})
	conn.Write([]byte("root\r\n"))
	readUntil(t, conn, "Password: ")
	conn.Write([]byte("xc3511\r\n"))
	readUntil(t, conn, "Login incorrect")
	readUntil(t, conn, "login: ")
	conn.Write([]byte("root\r\x00"))
	readUntil(t, conn, "Password: ")
	conn.Write([]byte("root\n"))
	readUntil(t, conn, "root@cam-01:~# ")
	conn.Write([]byte("/bin/busybox MIRAI\r\n"))
	out := readUntil(t, conn, "MIRAI: applet not found")
	if strings.Contains(out, "\x00") {
		t.Errorf("NUL leaked into output: %q", out)
	}
	conn.Write([]byte("exit\r\n"))

	deadline := time.Now().Add(5 * time.Second)
	for {
		evs := c.snapshot()
		if len(evs) > 0 && evs[len(evs)-1].Kind == event.KindDisconnect {
			var kinds []string
			for _, e := range evs {
				kinds = append(kinds, string(e.Kind))
			}
			want := "connect auth auth command command disconnect"
			if strings.Join(kinds, " ") != want {
				t.Fatalf("event kinds: %v, want %s", kinds, want)
			}
			if evs[1].Password != "xc3511" || evs[1].Success || !evs[2].Success {
				t.Errorf("auth events: %+v %+v", evs[1], evs[2])
			}
			if evs[3].Tags[0] != "botnet" {
				t.Errorf("busybox not tagged: %v", evs[3].Tags)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no disconnect; events: %+v", evs)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFilter(t *testing.T) {
	in := []byte{'a', iac, will, 1, 'b', iac, sb, 24, 0, 'x', 't', iac, se, 'c', iac, iac, '\r', '\n', 'd', '\n'}
	f := &filter{r: bytes.NewReader(in)}
	got, _ := io.ReadAll(f)
	want := []byte{'a', 'b', 'c', iac, '\r', 'd', '\r'}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
