// Package telnetpot is a Telnet honeypot. Telnet is where IoT botnets
// (Mirai and its descendants) live: they log in with factory credentials and
// probe for busybox. This sensor speaks just enough of RFC 854 to keep them going.
package telnetpot

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/honeypot"
	"github.com/born2feel/honeynet/internal/netutil"
	"github.com/born2feel/honeynet/internal/shell"
	"golang.org/x/term"
)

type Config struct {
	Addr     string
	Hostname string
	Limits   honeypot.Limits
}

type Server struct {
	cfg  Config
	emit event.Emitter
	lim  *netutil.Limiter
	log  *slog.Logger
}

func New(cfg Config, emit event.Emitter, lim *netutil.Limiter, log *slog.Logger) *Server {
	if cfg.Limits == (honeypot.Limits{}) {
		cfg.Limits = honeypot.DefaultLimits
	}
	return &Server{cfg: cfg, emit: emit, lim: lim, log: log}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.log.Info("telnet honeypot listening", "addr", ln.Addr().String())
	return s.Serve(ctx, ln)
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	return honeypot.Serve(ctx, ln, s.lim, s.log, s.handle)
}

// Telnet protocol bytes (RFC 854/857/858).
const (
	se   = 240
	sb   = 250
	will = 251
	wont = 252
	do   = 253
	dont = 254
	iac  = 255

	optEcho = 1
	optSGA  = 3
)

func (s *Server) handle(nc net.Conn) {
	ip, port := netutil.SplitAddr(nc.RemoteAddr())
	base := event.Event{Sensor: event.SensorTelnet, SessionID: honeypot.NewSessionID(), SrcIP: ip, SrcPort: port}
	e := base
	e.Kind = event.KindConnect
	s.emit.Emit(e)
	defer func() {
		e := base
		e.Kind = event.KindDisconnect
		s.emit.Emit(e)
	}()

	conn := netutil.NewDeadlineConn(nc, s.cfg.Limits.Idle, time.Now().Add(s.cfg.Limits.MaxDuration))
	// We echo, client goes into character mode: what a real telnetd negotiates.
	conn.Write([]byte{iac, will, optEcho, iac, will, optSGA, iac, do, optSGA})

	rw := struct {
		io.Reader
		io.Writer
	}{&filter{r: conn}, conn}
	t := term.NewTerminal(rw, "")
	fmt.Fprint(t, "Ubuntu 22.04.4 LTS\n")

	var user string
	ok := false
	for attempt := 1; attempt <= 3 && !ok; attempt++ {
		t.SetPrompt(s.cfg.Hostname + " login: ")
		var err error
		if user, err = t.ReadLine(); err != nil {
			return
		}
		pw, err := t.ReadPassword("Password: ")
		if err != nil {
			return
		}
		ok = honeypot.AcceptLogin(user, pw, attempt)
		e := base
		e.Kind = event.KindAuth
		e.Username, e.Password, e.Success = user, pw, ok
		e.Detail = "password"
		s.emit.Emit(e)
		if !ok {
			time.Sleep(time.Second) // login(1) delays after a failure too
			fmt.Fprint(t, "\nLogin incorrect\n")
		}
	}
	if !ok {
		return
	}
	sh := shell.New(s.cfg.Hostname, user)
	fmt.Fprint(t, sh.Motd("10.0.2.2"))
	honeypot.RunShell(t, sh, base, s.emit, s.cfg.Limits.MaxCommands)
}

// filter strips Telnet negotiation from the client stream and normalises line
// endings ("\r\n", "\r\x00", "\n") to the "\r" that term.Terminal treats as Enter.
type filter struct {
	r     io.Reader
	state int // 0 data, 1 after IAC, 2 after IAC+verb, 3 in subnegotiation, 4 IAC in SB, 5 after CR
	buf   [512]byte
}

func (f *filter) Read(p []byte) (int, error) {
	for {
		n, err := f.r.Read(f.buf[:min(len(p), len(f.buf))])
		out := 0
		for _, b := range f.buf[:n] {
			switch f.state {
			case 0, 5:
				prevCR := f.state == 5
				f.state = 0
				switch {
				case b == iac:
					f.state = 1
				case b == '\r':
					p[out] = '\r'
					out++
					f.state = 5
				case (b == '\n' || b == 0) && prevCR:
					// second half of CR LF / CR NUL
				case b == '\n':
					p[out] = '\r'
					out++
				default:
					p[out] = b
					out++
				}
			case 1:
				switch b {
				case iac: // escaped 0xFF data byte
					p[out] = b
					out++
					f.state = 0
				case will, wont, do, dont:
					f.state = 2
				case sb:
					f.state = 3
				default:
					f.state = 0
				}
			case 2:
				f.state = 0
			case 3:
				if b == iac {
					f.state = 4
				}
			case 4:
				if b == se {
					f.state = 0
				} else {
					f.state = 3
				}
			}
		}
		if out > 0 || err != nil {
			return out, err
		}
	}
}
