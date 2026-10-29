package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/born2feel/honeynet/internal/event"
)

func open(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestSessionLifecycleAndStats(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Minute)
	geo := event.Geo{CountryCode: "NL", Country: "Netherlands", City: "Amsterdam", Lat: 52.37, Lon: 4.9}
	base := event.Event{Sensor: event.SensorSSH, SessionID: "s1", SrcIP: "198.51.100.7", Geo: geo}
	at := func(i int, e event.Event) event.Event { e.Time = now.Add(time.Duration(i) * time.Second); return e }

	evs := []event.Event{
		at(0, with(base, func(e *event.Event) { e.Kind = event.KindConnect })),
		at(1, with(base, func(e *event.Event) {
			e.Kind, e.Username, e.Password, e.Client = event.KindAuth, "root", "toor1", "SSH-2.0-Go"
		})),
		at(2, with(base, func(e *event.Event) {
			e.Kind, e.Username, e.Password, e.Success = event.KindAuth, "root", "123456", true
		})),
		at(3, with(base, func(e *event.Event) {
			e.Kind, e.Command, e.Tags = event.KindCommand, "uname -a", []string{"recon"}
		})),
		at(4, with(base, func(e *event.Event) {
			e.Kind, e.Command, e.Tags = event.KindCommand, "wget http://x/y", []string{"download"}
		})),
		at(5, with(base, func(e *event.Event) { e.Kind = event.KindDisconnect })),
		at(6, event.Event{Sensor: event.SensorHTTP, Kind: event.KindRequest, SrcIP: "203.0.113.1", Path: "/.env",
			Method: "GET", Tags: []string{"secrets_probe"}}),
	}
	saved, err := st.InsertBatch(ctx, evs)
	if err != nil {
		t.Fatal(err)
	}
	if saved[0].ID == 0 || saved[6].ID <= saved[0].ID {
		t.Fatalf("ids not assigned: %d %d", saved[0].ID, saved[6].ID)
	}

	sess, events, err := st.Session(ctx, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if !sess.LoggedIn || sess.AuthAttempts != 2 || sess.Commands != 2 || sess.Password != "123456" ||
		sess.Client != "SSH-2.0-Go" || sess.EndedAt == nil || sess.Geo.City != "Amsterdam" {
		t.Errorf("session: %+v", sess)
	}
	if len(events) != 6 || events[3].Tags[0] != "recon" {
		t.Errorf("session events: %d %+v", len(events), events)
	}

	stats, err := st.Stats(ctx, now.Add(-time.Hour), 12, 5)
	if err != nil {
		t.Fatal(err)
	}
	tot := stats.Totals
	if tot.Attacks != 5 || tot.Connections != 1 || tot.AuthAttempts != 2 || tot.Logins != 1 ||
		tot.Commands != 2 || tot.Requests != 1 || tot.UniqueIPs != 2 || tot.Countries != 1 {
		t.Errorf("totals: %+v", tot)
	}
	if stats.TopUsernames[0] != (Count{Key: "root", Count: 2}) {
		t.Errorf("top usernames: %+v", stats.TopUsernames)
	}
	if stats.TopCountries[0] != (Count{Key: "NL", Label: "Netherlands", Count: 1}) {
		t.Errorf("top countries: %+v", stats.TopCountries)
	}
	if len(stats.TopTags) != 3 || stats.TopPaths[0].Key != "/.env" {
		t.Errorf("tags/paths: %+v %+v", stats.TopTags, stats.TopPaths)
	}
	var sum int64
	for _, b := range stats.Timeline {
		sum += b.SSH + b.Telnet + b.HTTP
	}
	if len(stats.Timeline) != 12 || sum != 5 {
		t.Errorf("timeline: %d buckets, %d attacks", len(stats.Timeline), sum)
	}

	pts, err := st.MapPoints(ctx, now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 1 || pts[0].CountryCode != "NL" || pts[0].Attacks != 4 {
		t.Errorf("map points: %+v", pts)
	}

	list, total, err := st.Sessions(ctx, SessionFilter{LoggedInOnly: true, Limit: 10})
	if err != nil || total != 1 || list[0].ID != "s1" {
		t.Errorf("sessions: %v %d %+v", err, total, list)
	}

	recent, err := st.Recent(ctx, 2, 0)
	if err != nil || len(recent) != 2 || recent[0].Path != "/.env" {
		t.Errorf("recent: %v %+v", err, recent)
	}
}

func TestSessionNotFound(t *testing.T) {
	if _, _, err := open(t).Session(context.Background(), "nope"); err != ErrNotFound {
		t.Fatalf("got %v", err)
	}
}

func TestPrune(t *testing.T) {
	st := open(t)
	ctx := context.Background()
	old := event.Event{Time: time.Now().Add(-48 * time.Hour), Sensor: event.SensorSSH, Kind: event.KindConnect, SessionID: "old", SrcIP: "192.0.2.1"}
	fresh := event.Event{Time: time.Now(), Sensor: event.SensorHTTP, Kind: event.KindRequest, SrcIP: "192.0.2.2", Tags: []string{"x"}}
	if _, err := st.InsertBatch(ctx, []event.Event{old, fresh}); err != nil {
		t.Fatal(err)
	}
	n, err := st.Prune(ctx, time.Now().Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, err %v", n, err)
	}
	if _, _, err := st.Session(ctx, "old"); err != ErrNotFound {
		t.Errorf("old session survived: %v", err)
	}
}

func TestEmptyStats(t *testing.T) {
	stats, err := open(t).Stats(context.Background(), time.Time{}, 24, 10)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Totals.Attacks != 0 || stats.TopUsernames == nil {
		t.Errorf("empty stats should be zeroed with non-nil lists: %+v", stats)
	}
}

func with(e event.Event, f func(*event.Event)) event.Event {
	f(&e)
	return e
}
