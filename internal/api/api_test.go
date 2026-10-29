package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/born2feel/honeynet/internal/event"
	"github.com/born2feel/honeynet/internal/store"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func setup(t *testing.T, cfg Config) (*httptest.Server, *store.Store, *event.Bus) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := event.NewBus()
	static := fstest.MapFS{
		"index.html":    {Data: []byte("<!doctype html><title>honeynet</title>")},
		"assets/app.js": {Data: []byte("console.log(1)")},
	}
	srv := httptest.NewServer(New(cfg, st, bus, static, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(srv.Close)
	return srv, st, bus
}

func get(t *testing.T, url string, headers ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestStatsAndSessions(t *testing.T) {
	srv, st, _ := setup(t, Config{})
	now := time.Now().UTC()
	st.InsertBatch(context.Background(), []event.Event{
		{Time: now, Sensor: event.SensorSSH, Kind: event.KindConnect, SessionID: "abc", SrcIP: "192.0.2.1"},
		{Time: now, Sensor: event.SensorSSH, Kind: event.KindAuth, SessionID: "abc", SrcIP: "192.0.2.1", Username: "root", Password: "x"},
	})

	resp, body := get(t, srv.URL+"/api/stats?window=1h")
	if resp.StatusCode != 200 {
		t.Fatalf("stats: %d %s", resp.StatusCode, body)
	}
	var stats store.Stats
	json.Unmarshal([]byte(body), &stats)
	if stats.Totals.AuthAttempts != 1 || len(stats.Timeline) != 48 {
		t.Errorf("stats: %+v", stats.Totals)
	}

	_, body = get(t, srv.URL+"/api/sessions/abc")
	if !strings.Contains(body, `"username":"root"`) {
		t.Errorf("session detail: %s", body)
	}
	resp, _ = get(t, srv.URL+"/api/sessions/missing")
	if resp.StatusCode != 404 {
		t.Errorf("missing session: %d", resp.StatusCode)
	}
	resp, _ = get(t, srv.URL+"/api/nope")
	if resp.StatusCode != 404 {
		t.Errorf("unknown api route: %d", resp.StatusCode)
	}
}

func TestTokenAuth(t *testing.T) {
	srv, _, _ := setup(t, Config{Token: "s3cret"})
	if resp, _ := get(t, srv.URL+"/api/stats"); resp.StatusCode != 401 {
		t.Errorf("no token: %d", resp.StatusCode)
	}
	if resp, _ := get(t, srv.URL+"/api/stats", "Authorization", "Bearer wrong"); resp.StatusCode != 401 {
		t.Errorf("wrong token: %d", resp.StatusCode)
	}
	if resp, _ := get(t, srv.URL+"/api/stats", "Authorization", "Bearer s3cret"); resp.StatusCode != 200 {
		t.Errorf("header token: %d", resp.StatusCode)
	}
	if resp, _ := get(t, srv.URL+"/api/stats?token=s3cret"); resp.StatusCode != 200 {
		t.Errorf("query token: %d", resp.StatusCode)
	}
	if resp, _ := get(t, srv.URL+"/"); resp.StatusCode != 200 {
		t.Errorf("SPA shell must stay public: %d", resp.StatusCode)
	}
}

func TestSPAAndSecurityHeaders(t *testing.T) {
	srv, _, _ := setup(t, Config{})
	resp, body := get(t, srv.URL+"/sessions/some-client-route")
	if resp.StatusCode != 200 || !strings.Contains(body, "<title>honeynet</title>") {
		t.Errorf("SPA fallback: %d %q", resp.StatusCode, body)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP: %q", csp)
	}
	resp, _ = get(t, srv.URL+"/assets/app.js")
	if !strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("assets cache: %q", resp.Header.Get("Cache-Control"))
	}
}

func TestLiveFeed(t *testing.T) {
	srv, _, bus := setup(t, Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/api/live", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	for bus.Subscribers() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	bus.Publish(event.Event{ID: 7, Sensor: event.SensorHTTP, Kind: event.KindRequest, SrcIP: "192.0.2.9", Path: "/.env"})
	var got event.Event
	if err := wsjson.Read(ctx, c, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != 7 || got.Path != "/.env" {
		t.Errorf("live event: %+v", got)
	}
}

func TestLiveRejectsForeignOrigin(t *testing.T) {
	srv, _, _ := setup(t, Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/api/live", &websocket.DialOptions{
		HTTPHeader: http.Header{"Origin": []string{"https://evil.example"}},
	})
	if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site WebSocket must be refused: %v", err)
	}
}
