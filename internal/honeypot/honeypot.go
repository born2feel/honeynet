// Package honeypot contains the pieces shared by the interactive sensors
// (SSH and Telnet): the login policy, the accept loop and the shell loop.
package honeypot

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/born2feel/honeynet/internal/detect"
	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/netutil"
	"github.com/born2feel/honeynet/internal/shell"
)

// Limits apply to every interactive session.
type Limits struct {
	Idle        time.Duration // close after this much silence
	MaxDuration time.Duration // close after this long no matter what
	MaxCommands int
}

var DefaultLimits = Limits{Idle: 2 * time.Minute, MaxDuration: 10 * time.Minute, MaxCommands: 300}

const maxStoredOutput = 4 << 10

// weakPasswords are accepted immediately. Bots try these first, and letting
// them in is what turns a login attempt into a session worth watching.
var weakPasswords = map[string]bool{
	"123456": true, "password": true, "admin": true, "root": true, "12345678": true,
	"123456789": true, "1234": true, "12345": true, "qwerty": true, "toor": true,
	"raspberry": true, "ubuntu": true, "test": true, "1q2w3e4r": true, "default": true,
	"pass": true, "changeme": true, "P@ssw0rd": true, "000000": true, "111111": true,
	"password1": true, "admin123": true, "root123": true, "123123": true, "abc123": true,
}

// AcceptLogin decides whether a login succeeds. Weak passwords work at once;
// anything else works on the third try, like a sloppy admin's server. Empty
// passwords never work.
func AcceptLogin(user, password string, attempt int) bool {
	if password == "" || user == "" {
		return false
	}
	return weakPasswords[password] || attempt >= 3
}

// NewSessionID returns a random 16-hex-char id.
func NewSessionID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Terminal is what an interactive session reads lines from and writes to.
type Terminal interface {
	io.Writer
	ReadLine() (string, error)
	SetPrompt(string)
}

// RunShell drives a logged-in session: read a line, interpret it, record it.
func RunShell(t Terminal, sh *shell.Shell, base event.Event, emit event.Emitter, max int) {
	t.SetPrompt(sh.Prompt())
	for range max {
		line, err := t.ReadLine()
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		res := sh.Exec(line)
		RecordCommand(emit, base, line, res.Output)
		io.WriteString(t, res.Output)
		if res.Exit {
			return
		}
		t.SetPrompt(sh.Prompt())
	}
}

// RecordCommand emits a command event with tags and any URLs it references.
func RecordCommand(emit event.Emitter, base event.Event, line, output string) {
	e := base
	e.Kind = event.KindCommand
	e.Command = detect.Truncate(line, 2048)
	e.Output = detect.Truncate(output, maxStoredOutput)
	e.Tags = detect.Command(line)
	if urls := detect.URLs(line); len(urls) > 0 {
		e.Detail = strings.Join(urls, " ")
	}
	emit.Emit(e)
}

// Serve accepts connections on ln and runs handle for each in its own
// goroutine, enforcing the limiter. It returns when ctx is cancelled.
func Serve(ctx context.Context, ln net.Listener, lim *netutil.Limiter, log *slog.Logger, handle func(net.Conn)) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		ip, _ := netutil.SplitAddr(c.RemoteAddr())
		if !lim.Acquire(ip) {
			c.Close()
			continue
		}
		go func() {
			defer lim.Release(ip)
			defer c.Close()
			defer func() {
				if r := recover(); r != nil {
					log.Error("session panic", "remote", ip, "panic", r)
				}
			}()
			handle(c)
		}()
	}
}
