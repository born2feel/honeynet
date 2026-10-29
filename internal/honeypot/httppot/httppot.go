// Package httppot is a low-interaction web honeypot. It looks like an Ubuntu
// Apache box with a WordPress install and a few admin panels, logs every
// request, tags it with the attack technique and captures posted credentials.
package httppot

import (
	"context"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/born2feel/honeynet/internal/detect"
	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/netutil"
)

const (
	maxBody = 8 << 10
	maxPath = 2048
)

type Config struct {
	Addr     string
	Hostname string
}

type Server struct {
	cfg  Config
	emit event.Emitter
	log  *slog.Logger
}

func New(cfg Config, emit event.Emitter, log *slog.Logger) *Server {
	return &Server{cfg: cfg, emit: emit, log: log}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Addr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	s.log.Info("http honeypot listening", "addr", s.cfg.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// credentialFields are form field names login pages commonly use.
var (
	userFields = []string{"log", "username", "user", "login", "email", "pma_username", "uname"}
	passFields = []string{"pwd", "password", "pass", "passwd", "pma_password", "psw"}
)

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip, port := netutil.SplitAddr(remoteAddr(r))
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxBody))

	e := event.Event{
		Sensor:    event.SensorHTTP,
		Kind:      event.KindRequest,
		SrcIP:     ip,
		SrcPort:   port,
		Method:    detect.Truncate(r.Method, 16),
		Path:      detect.Truncate(r.URL.RequestURI(), maxPath),
		UserAgent: detect.Truncate(r.UserAgent(), 512),
		Body:      detect.Truncate(string(body), maxBody),
	}
	e.Tags = detect.HTTP(r.Method, r.URL.RequestURI(), string(body),
		r.UserAgent(), r.Referer(), r.Header.Get("X-Api-Version"), r.Header.Get("X-Forwarded-For"), r.Header.Get("Cookie"))

	if r.Method == http.MethodPost {
		if form, err := url.ParseQuery(string(body)); err == nil {
			e.Username = detect.Truncate(firstField(form, userFields), 256)
			e.Password = detect.Truncate(firstField(form, passFields), 256)
			if e.Username != "" || e.Password != "" {
				e.Tags = appendTag(e.Tags, "credential_capture")
			}
		}
	}
	if r.Header.Get("Authorization") != "" {
		if u, p, ok := r.BasicAuth(); ok {
			e.Username, e.Password = detect.Truncate(u, 256), detect.Truncate(p, 256)
			e.Tags = appendTag(e.Tags, "credential_capture")
		}
	}
	s.emit.Emit(e)

	h := w.Header()
	h.Set("Server", "Apache/2.4.52 (Ubuntu)")
	h.Set("Content-Type", "text/html; charset=UTF-8")
	s.respond(w, r)
}

func remoteAddr(r *http.Request) net.Addr {
	if a, err := net.ResolveTCPAddr("tcp", r.RemoteAddr); err == nil {
		return a
	}
	return &net.TCPAddr{}
}

func firstField(form url.Values, names []string) string {
	for _, n := range names {
		if v := form.Get(n); v != "" {
			return v
		}
	}
	return ""
}

func appendTag(tags []string, t string) []string {
	for _, x := range tags {
		if x == t {
			return tags
		}
	}
	return append(tags, t)
}

func (s *Server) respond(w http.ResponseWriter, r *http.Request) {
	p := strings.ToLower(r.URL.Path)
	failed := r.Method == http.MethodPost
	switch {
	case p == "/" || p == "/index.html":
		pages.ExecuteTemplate(w, "apache", s.cfg.Hostname)
	case strings.HasPrefix(p, "/wp-login.php") || strings.HasPrefix(p, "/wp-admin"):
		pages.ExecuteTemplate(w, "wordpress", failed)
	case strings.HasPrefix(p, "/phpmyadmin") || strings.HasPrefix(p, "/pma"):
		pages.ExecuteTemplate(w, "phpmyadmin", failed)
	case p == "/admin" || p == "/login" || p == "/administrator" || strings.HasPrefix(p, "/admin/") || p == "/user/login":
		pages.ExecuteTemplate(w, "login", failed)
	case p == "/xmlrpc.php":
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "XML-RPC server accepts POST requests only.")
	case p == "/.env":
		// Bait: obviously fake values attackers will try to use elsewhere.
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, fakeEnv)
	case p == "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "User-agent: *\nDisallow: /wp-admin/\nDisallow: /backup/\n")
	default:
		w.WriteHeader(http.StatusNotFound)
		pages.ExecuteTemplate(w, "notfound", map[string]string{"Path": r.URL.Path, "Host": s.cfg.Hostname})
	}
}

const fakeEnv = `APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:Zm9yLWhvbmV5cG90LXVzZS1vbmx5LW5vdC1hLXJlYWwta2V5
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=wordpress
DB_USERNAME=wp_admin
DB_PASSWORD=Summer2024!
AWS_ACCESS_KEY_ID=AKIAHONEYPOTEXAMPLE0
AWS_SECRET_ACCESS_KEY=honeypot/example/not+a+real+secret+key00
`

var pages = template.Must(template.New("").Parse(`
{{define "apache"}}<!DOCTYPE html>
<html><head><title>Apache2 Ubuntu Default Page: It works</title></head>
<body><h1>Apache2 Default Page</h1><p><b>It works!</b></p>
<p>This is the default welcome page used to test the correct operation of the Apache2 server after installation on Ubuntu systems.</p>
</body></html>{{end}}

{{define "wordpress"}}<!DOCTYPE html>
<html lang="en-US"><head><meta charset="UTF-8"><title>Log In &lsaquo; Company Blog &#8212; WordPress</title></head>
<body class="login wp-core-ui"><div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
{{if .}}<div id="login_error"><strong>Error:</strong> The password you entered for the username is incorrect. <a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>{{end}}
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login"></p>
<p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass"></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" value="Log In"></p>
</form></div></body></html>{{end}}

{{define "phpmyadmin"}}<!DOCTYPE html>
<html><head><title>phpMyAdmin</title></head><body>
<h1>Welcome to phpMyAdmin</h1>
{{if .}}<div class="alert alert-danger">mysqli::real_connect(): (HY000/1045): Access denied for user</div>{{end}}
<form method="post" action="/phpmyadmin/index.php">
<input type="text" name="pma_username" placeholder="Username"><input type="password" name="pma_password" placeholder="Password">
<input type="submit" value="Go"></form></body></html>{{end}}

{{define "login"}}<!DOCTYPE html>
<html><head><title>Admin Login</title></head><body>
<h2>Administration</h2>
{{if .}}<p style="color:red">Invalid username or password.</p>{{end}}
<form method="post"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button>Sign in</button></form>
</body></html>{{end}}

{{define "notfound"}}<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body>
<h1>Not Found</h1><p>The requested URL {{.Path}} was not found on this server.</p>
<hr><address>Apache/2.4.52 (Ubuntu) Server at {{.Host}} Port 80</address>
</body></html>{{end}}
`))
