// Package api serves the dashboard: a JSON API over the store, a WebSocket
// live feed off the event bus, and the embedded single-page app.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/store"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type Config struct {
	// Token, when set, is required as "Authorization: Bearer <token>" or ?token=.
	Token string
	// OriginPatterns lists extra origins allowed to open the WebSocket (dev servers).
	OriginPatterns []string
	// Sensors are shown on the dashboard header.
	Sensors  []string
	Hostname string
	Demo     bool
}

type Server struct {
	cache  *cache
	cfg    Config
	store  *store.Store
	bus    *event.Bus
	static fs.FS
	log    *slog.Logger
	start  time.Time
}

func New(cfg Config, st *store.Store, bus *event.Bus, static fs.FS, log *slog.Logger) *Server {
	return &Server{cfg: cfg, store: st, bus: bus, static: static, log: log, start: time.Now(), cache: newCache(3 * time.Second)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/stats", s.stats)
	mux.HandleFunc("GET /api/map", s.mapPoints)
	mux.HandleFunc("GET /api/events", s.events)
	mux.HandleFunc("GET /api/sessions", s.sessions)
	mux.HandleFunc("GET /api/sessions/{id}", s.session)
	mux.HandleFunc("GET /api/live", s.live)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	mux.Handle("/", s.spa())
	return securityHeaders(s.auth(mux))
}

// windows are the time ranges the dashboard offers.
var windows = map[string]time.Duration{
	"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
}

// since parses ?window=; "all" (or anything unknown) returns the zero time.
func since(r *http.Request, def string) time.Time {
	w := r.URL.Query().Get("window")
	if w == "" {
		w = def
	}
	if d, ok := windows[w]; ok {
		return time.Now().UTC().Add(-d)
	}
	return time.Time{}
}

func intParam(r *http.Request, name string, def, min, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return def
	}
	return clamp(v, min, max)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	s.log.Error("api", "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"status":      "ok",
		"uptime_s":    int(time.Since(s.start).Seconds()),
		"sensors":     s.cfg.Sensors,
		"hostname":    s.cfg.Hostname,
		"demo":        s.cfg.Demo,
		"subscribers": s.bus.Subscribers(),
	})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	st, err := s.cache.get(r.URL.RawQuery, func() (any, error) {
		return s.store.Stats(r.Context(), since(r, "24h"), intParam(r, "buckets", 48, 6, 200), intParam(r, "top", 10, 1, 50))
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, st)
}

func (s *Server) mapPoints(w http.ResponseWriter, r *http.Request) {
	pts, err := s.cache.get("map?"+r.URL.RawQuery, func() (any, error) {
		return s.store.MapPoints(r.Context(), since(r, "24h"), intParam(r, "limit", 500, 1, 2000))
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, pts)
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	evs, err := s.store.Recent(r.Context(), intParam(r, "limit", 50, 1, 500), before)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if evs == nil {
		evs = []event.Event{}
	}
	writeJSON(w, evs)
}

func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	list, total, err := s.store.Sessions(r.Context(), store.SessionFilter{
		Since:        since(r, "all"),
		LoggedInOnly: r.URL.Query().Get("logged_in") == "1",
		Limit:        intParam(r, "limit", 25, 1, 200),
		Offset:       intParam(r, "offset", 0, 0, 1<<30),
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, map[string]any{"total": total, "sessions": list})
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	sess, evs, err := s.store.Session(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, map[string]any{"session": sess, "events": evs})
}

// live streams new events as they're recorded. Slow clients drop events
// (see event.Bus) rather than slowing the pipeline down.
func (s *Server) live(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: s.cfg.OriginPatterns})
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := c.CloseRead(r.Context()) // we never read; this handles pings and close frames

	events, cancel := s.bus.Subscribe(256)
	defer cancel()
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case e := <-events:
			wctx, done := context.WithTimeout(ctx, 5*time.Second)
			err := wsjson.Write(wctx, c, e)
			done()
			if err != nil {
				return
			}
		case <-ping.C:
			if err := c.Ping(ctx); err != nil {
				return
			}
		}
	}
}

// auth enforces the dashboard token. The token is checked in constant time
// and can come from a header (API clients) or the query (browsers' WebSocket).
func (s *Server) auth(next http.Handler) http.Handler {
	if s.cfg.Token == "" {
		return next
	}
	want := []byte(s.cfg.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r) // the SPA shell itself is public; it asks for the token
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders matter more than usual here: every string the dashboard
// renders was typed by an attacker.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// spa serves the built dashboard, falling back to index.html for client routes.
func (s *Server) spa() http.Handler {
	files := http.FileServerFS(s.static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.static, p); err != nil {
			if _, err := fs.Stat(s.static, "index.html"); err != nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("Dashboard is not built. Run `npm ci && npm run build` in web/, or use the Docker image.\n"))
				return
			}
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}
