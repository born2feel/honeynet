// Package sshpot is a medium-interaction SSH honeypot: it completes the real
// SSH handshake (golang.org/x/crypto/ssh), records every credential, then
// hands logged-in clients a fake bash.
package sshpot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/honeypot"
	"github.com/born2feel/honeynet/internal/netutil"
	"github.com/born2feel/honeynet/internal/shell"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Config struct {
	Addr       string
	HostKeyDir string // keys are generated here on first run and reused after
	Hostname   string
	// Banner mimics a stock Ubuntu 22.04 OpenSSH so scanners fingerprint us as one.
	ServerVersion string
	Limits        honeypot.Limits
}

type Server struct {
	cfg     Config
	signers []ssh.Signer
	emit    event.Emitter
	lim     *netutil.Limiter
	log     *slog.Logger
}

func New(cfg Config, emit event.Emitter, lim *netutil.Limiter, log *slog.Logger) (*Server, error) {
	if cfg.ServerVersion == "" {
		cfg.ServerVersion = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
	}
	if cfg.Limits == (honeypot.Limits{}) {
		cfg.Limits = honeypot.DefaultLimits
	}
	signers, err := loadHostKeys(cfg.HostKeyDir)
	if err != nil {
		return nil, fmt.Errorf("host keys: %w", err)
	}
	return &Server{cfg: cfg, signers: signers, emit: emit, lim: lim, log: log}, nil
}

// ListenAndServe blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.log.Info("ssh honeypot listening", "addr", ln.Addr().String())
	return s.Serve(ctx, ln)
}

func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	return honeypot.Serve(ctx, ln, s.lim, s.log, s.handle)
}

func (s *Server) handle(nc net.Conn) {
	ip, port := netutil.SplitAddr(nc.RemoteAddr())
	base := event.Event{Sensor: event.SensorSSH, SessionID: honeypot.NewSessionID(), SrcIP: ip, SrcPort: port}

	connect := base
	connect.Kind = event.KindConnect
	s.emit.Emit(connect)
	defer func() {
		e := base
		e.Kind = event.KindDisconnect
		s.emit.Emit(e)
	}()

	conn := &netutil.DeadlineConn{
		Conn:     nc,
		Idle:     30 * time.Second, // handshake + auth must be quick
		HardStop: time.Now().Add(s.cfg.Limits.MaxDuration),
	}

	attempts := 0
	auth := func(md ssh.ConnMetadata, password, detail string, ok bool) {
		e := base
		e.Kind = event.KindAuth
		e.Client = string(md.ClientVersion())
		e.Username = md.User()
		e.Password = password
		e.Success = ok
		e.Detail = detail
		s.emit.Emit(e)
	}
	checkPassword := func(md ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		attempts++
		ok := honeypot.AcceptLogin(md.User(), string(pw), attempts)
		auth(md, string(pw), "password", ok)
		if !ok {
			return nil, errors.New("denied")
		}
		return &ssh.Permissions{}, nil
	}
	cfg := &ssh.ServerConfig{
		ServerVersion:    s.cfg.ServerVersion,
		MaxAuthTries:     6,
		PasswordCallback: checkPassword,
		PublicKeyCallback: func(md ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Key fingerprints identify botnets across IPs: record, always refuse.
			auth(md, "", "publickey "+key.Type()+" "+ssh.FingerprintSHA256(key), false)
			return nil, errors.New("denied")
		},
		KeyboardInteractiveCallback: func(md ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := client("", "", []string{"Password: "}, []bool{false})
			if err != nil || len(answers) != 1 {
				return nil, errors.New("denied")
			}
			return checkPassword(md, []byte(answers[0]))
		},
	}
	for _, k := range s.signers {
		cfg.AddHostKey(k)
	}

	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return // scanners that only grab the banner, failed auth, etc.
	}
	defer sconn.Close()
	conn.Idle = s.cfg.Limits.Idle
	go ssh.DiscardRequests(reqs)

	user := sconn.User()
	for nch := range chans {
		switch nch.ChannelType() {
		case "session":
			ch, creqs, err := nch.Accept()
			if err != nil {
				continue
			}
			go s.session(ch, creqs, user, base)
		case "direct-tcpip":
			// Port forwarding: bots use compromised boxes as SOCKS proxies for spam and
			// credential stuffing. Record where they wanted to go and refuse.
			var p struct {
				Host       string
				Port       uint32
				OriginHost string
				OriginPort uint32
			}
			e := base
			e.Kind = event.KindTunnel
			if ssh.Unmarshal(nch.ExtraData(), &p) == nil {
				e.Detail = net.JoinHostPort(p.Host, fmt.Sprint(p.Port))
			}
			s.emit.Emit(e)
			nch.Reject(ssh.Prohibited, "administratively prohibited")
		default:
			nch.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request, user string, base event.Event) {
	defer ch.Close()
	sh := shell.New(s.cfg.Hostname, user)
	done := make(chan struct{})
	started := false

	for {
		var req *ssh.Request
		select {
		case req = <-reqs:
		case <-done:
			return
		}
		if req == nil {
			return
		}
		switch req.Type {
		case "pty-req", "env", "window-change", "auth-agent-req@openssh.com":
			req.Reply(true, nil)
		case "shell":
			req.Reply(true, nil)
			if started {
				continue
			}
			started = true
			go func() {
				defer close(done)
				t := term.NewTerminal(ch, "")
				fmt.Fprint(t, sh.Motd("10.0.2.2"))
				honeypot.RunShell(t, sh, base, s.emit, s.cfg.Limits.MaxCommands)
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			}()
		case "exec":
			// "ssh host 'uname -a'": the most common bot behaviour.
			var p struct{ Command string }
			if ssh.Unmarshal(req.Payload, &p) != nil {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			res := sh.Exec(p.Command)
			honeypot.RecordCommand(s.emit, base, p.Command, res.Output)
			ch.Write([]byte(res.Output))
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return
		case "subsystem":
			var p struct{ Name string }
			ssh.Unmarshal(req.Payload, &p)
			honeypot.RecordCommand(s.emit, base, "[subsystem "+p.Name+"]", "")
			req.Reply(false, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

// loadHostKeys reads ed25519 and RSA host keys from dir, generating any that
// are missing. Persisting them matters: a honeypot whose host key changes on
// every restart is trivially fingerprinted.
func loadHostKeys(dir string) ([]ssh.Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	gens := []struct {
		file string
		gen  func() (any, error)
	}{
		{"ssh_host_ed25519_key", func() (any, error) {
			_, k, err := ed25519.GenerateKey(rand.Reader)
			return k, err
		}},
		{"ssh_host_rsa_key", func() (any, error) { return rsa.GenerateKey(rand.Reader, 3072) }},
	}
	var signers []ssh.Signer
	for _, g := range gens {
		path := filepath.Join(dir, g.file)
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			key, err := g.gen()
			if err != nil {
				return nil, err
			}
			block, err := ssh.MarshalPrivateKey(key, "")
			if err != nil {
				return nil, err
			}
			data = pem.EncodeToMemory(block)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		signers = append(signers, signer)
	}
	return signers, nil
}
