package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/born2feel/honeynet/internal/event"
)

// attackKinds are the events counted as "attacks". Connect/disconnect are
// bookkeeping and would double-count every session.
const attackKinds = `('auth','command','request','tunnel')`

// Count is one row of a top-N list. Label carries a second value where it
// makes sense: the country name for a country code, the password for a username.
type Count struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
	Count int64  `json:"count"`
}

type Totals struct {
	Attacks      int64 `json:"attacks"`
	Connections  int64 `json:"connections"`
	AuthAttempts int64 `json:"auth_attempts"`
	Logins       int64 `json:"logins"`
	Commands     int64 `json:"commands"`
	Requests     int64 `json:"requests"`
	Tunnels      int64 `json:"tunnels"`
	UniqueIPs    int64 `json:"unique_ips"`
	Countries    int64 `json:"countries"`
}

type Bucket struct {
	Start  time.Time `json:"start"`
	SSH    int64     `json:"ssh"`
	Telnet int64     `json:"telnet"`
	HTTP   int64     `json:"http"`
}

type Stats struct {
	Since          time.Time `json:"since"`
	Until          time.Time `json:"until"`
	Totals         Totals    `json:"totals"`
	Timeline       []Bucket  `json:"timeline"`
	TopUsernames   []Count   `json:"top_usernames"`
	TopPasswords   []Count   `json:"top_passwords"`
	TopCredentials []Count   `json:"top_credentials"`
	TopCommands    []Count   `json:"top_commands"`
	TopCountries   []Count   `json:"top_countries"`
	TopIPs         []Count   `json:"top_ips"`
	TopPaths       []Count   `json:"top_paths"`
	TopTags        []Count   `json:"top_tags"`
	TopClients     []Count   `json:"top_clients"`
}

// Stats aggregates everything the dashboard overview needs for [since, now].
// A zero since means "since the first event".
func (s *Store) Stats(ctx context.Context, since time.Time, buckets, topN int) (Stats, error) {
	now := time.Now().UTC()
	if since.IsZero() {
		var first sql.NullInt64
		if err := s.db.QueryRowContext(ctx, `SELECT MIN(ts) FROM events`).Scan(&first); err != nil {
			return Stats{}, err
		}
		since = now.Add(-time.Hour)
		if first.Valid {
			since = time.UnixMilli(first.Int64).UTC()
		}
	}
	from := since.UnixMilli()
	st := Stats{Since: since, Until: now}

	// The aggregates are independent full-range scans: run them concurrently
	// on the pool's read connections (WAL lets readers proceed in parallel).
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	run := func(f func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}

	run(func() error {
		return s.db.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(kind IN `+attackKinds+`), 0),
		COALESCE(SUM(kind = 'connect'), 0),
		COALESCE(SUM(kind = 'auth'), 0),
		COALESCE(SUM(kind = 'auth' AND success), 0),
		COALESCE(SUM(kind = 'command'), 0),
		COALESCE(SUM(kind = 'request'), 0),
		COALESCE(SUM(kind = 'tunnel'), 0),
		COUNT(DISTINCT src_ip),
		COUNT(DISTINCT NULLIF(country_code, ''))
		FROM events WHERE ts >= ?`, from).Scan(
			&st.Totals.Attacks, &st.Totals.Connections, &st.Totals.AuthAttempts, &st.Totals.Logins,
			&st.Totals.Commands, &st.Totals.Requests, &st.Totals.Tunnels,
			&st.Totals.UniqueIPs, &st.Totals.Countries)
	})
	run(func() (err error) {
		st.Timeline, err = s.timeline(ctx, since, now, buckets)
		return err
	})

	tops := []struct {
		dst *[]Count
		q   string
	}{
		{&st.TopUsernames, `SELECT username, '', COUNT(*) c FROM events
			WHERE ts >= ? AND username <> '' GROUP BY username ORDER BY c DESC, username LIMIT ?`},
		{&st.TopPasswords, `SELECT password, '', COUNT(*) c FROM events
			WHERE ts >= ? AND password <> '' GROUP BY password ORDER BY c DESC, password LIMIT ?`},
		{&st.TopCredentials, `SELECT username, password, COUNT(*) c FROM events
			WHERE ts >= ? AND username <> '' AND password <> ''
			GROUP BY username, password ORDER BY c DESC, username LIMIT ?`},
		{&st.TopCommands, `SELECT command, '', COUNT(*) c FROM events
			WHERE ts >= ? AND kind = 'command' GROUP BY command ORDER BY c DESC, command LIMIT ?`},
		{&st.TopCountries, `SELECT country_code, MAX(country), COUNT(DISTINCT src_ip) c FROM events
			WHERE ts >= ? AND country_code <> '' GROUP BY country_code ORDER BY c DESC, country_code LIMIT ?`},
		{&st.TopIPs, `SELECT src_ip, MAX(country_code), COUNT(*) c FROM events
			WHERE ts >= ? AND kind IN ` + attackKinds + ` GROUP BY src_ip ORDER BY c DESC, src_ip LIMIT ?`},
		{&st.TopPaths, `SELECT path, '', COUNT(*) c FROM events
			WHERE ts >= ? AND kind = 'request' GROUP BY path ORDER BY c DESC, path LIMIT ?`},
		{&st.TopTags, `SELECT tag, '', COUNT(*) c FROM event_tags
			WHERE ts >= ? GROUP BY tag ORDER BY c DESC, tag LIMIT ?`},
		{&st.TopClients, `SELECT client, '', COUNT(DISTINCT session_id) c FROM events
			WHERE ts >= ? AND client <> '' GROUP BY client ORDER BY c DESC, client LIMIT ?`},
	}
	for _, t := range tops {
		run(func() (err error) {
			*t.dst, err = s.counts(ctx, t.q, from, topN)
			return err
		})
	}
	wg.Wait()
	if len(errs) > 0 {
		return Stats{}, errors.Join(errs...)
	}
	return st, nil
}

func (s *Store) counts(ctx context.Context, q string, args ...any) ([]Count, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Count{}
	for rows.Next() {
		var c Count
		if err := rows.Scan(&c.Key, &c.Label, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) timeline(ctx context.Context, since, until time.Time, n int) ([]Bucket, error) {
	if n <= 0 {
		n = 24
	}
	width := until.Sub(since) / time.Duration(n)
	if width < time.Second {
		width = time.Second
	}
	out := make([]Bucket, n)
	for i := range out {
		out[i].Start = since.Add(time.Duration(i) * width)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT (ts - ?) / ? AS b, sensor, COUNT(*) FROM events
		WHERE ts >= ? AND kind IN `+attackKinds+` GROUP BY b, sensor`,
		since.UnixMilli(), width.Milliseconds(), since.UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			b      int64
			sensor string
			c      int64
		)
		if err := rows.Scan(&b, &sensor, &c); err != nil {
			return nil, err
		}
		if b >= int64(n) {
			b = int64(n) - 1 // events from the last partial millisecond window
		}
		switch event.Sensor(sensor) {
		case event.SensorSSH:
			out[b].SSH += c
		case event.SensorTelnet:
			out[b].Telnet += c
		case event.SensorHTTP:
			out[b].HTTP += c
		}
	}
	return out, rows.Err()
}

// Point is an aggregated attack origin for the world map.
type Point struct {
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city,omitempty"`
	IPs         int64   `json:"ips"`
	Attacks     int64   `json:"attacks"`
}

// MapPoints groups attack sources by location rounded to ~10 km.
func (s *Store) MapPoints(ctx context.Context, since time.Time, limit int) ([]Point, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ROUND(lat, 1) la, ROUND(lon, 1) lo,
		MAX(country_code), MAX(city), COUNT(DISTINCT src_ip), SUM(kind IN `+attackKinds+`) a
		FROM events WHERE ts >= ? AND country_code <> ''
		GROUP BY la, lo ORDER BY a DESC LIMIT ?`, since.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Point{}
	for rows.Next() {
		var p Point
		if err := rows.Scan(&p.Lat, &p.Lon, &p.CountryCode, &p.City, &p.IPs, &p.Attacks); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

type Session struct {
	ID           string     `json:"id"`
	Sensor       string     `json:"sensor"`
	SrcIP        string     `json:"src_ip"`
	SrcPort      int        `json:"src_port"`
	StartedAt    time.Time  `json:"started_at"`
	EndedAt      *time.Time `json:"ended_at,omitempty"`
	Geo          event.Geo  `json:"geo"`
	Client       string     `json:"client,omitempty"`
	AuthAttempts int        `json:"auth_attempts"`
	LoggedIn     bool       `json:"logged_in"`
	Username     string     `json:"username,omitempty"`
	Password     string     `json:"password,omitempty"`
	Commands     int        `json:"commands"`
}

const sessionColumns = `id, sensor, src_ip, src_port, started_at, ended_at, country_code, country, city, lat, lon,
	client, auth_attempts, logged_in, username, password, commands`

func scanSession(sc interface{ Scan(...any) error }) (Session, error) {
	var (
		s              Session
		started, ended int64
	)
	err := sc.Scan(&s.ID, &s.Sensor, &s.SrcIP, &s.SrcPort, &started, &ended,
		&s.Geo.CountryCode, &s.Geo.Country, &s.Geo.City, &s.Geo.Lat, &s.Geo.Lon,
		&s.Client, &s.AuthAttempts, &s.LoggedIn, &s.Username, &s.Password, &s.Commands)
	if err != nil {
		return s, err
	}
	s.StartedAt = time.UnixMilli(started).UTC()
	if ended > 0 {
		t := time.UnixMilli(ended).UTC()
		s.EndedAt = &t
	}
	return s, nil
}

// SessionFilter narrows the sessions list.
type SessionFilter struct {
	Since        time.Time
	LoggedInOnly bool
	Limit        int
	Offset       int
}

// Sessions returns sessions newest first and the total matching count.
func (s *Store) Sessions(ctx context.Context, f SessionFilter) ([]Session, int64, error) {
	where := `started_at >= ?`
	args := []any{f.Since.UnixMilli()}
	if f.LoggedInOnly {
		where += ` AND logged_in`
	}
	var total int64
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE `+where+`
		ORDER BY started_at DESC, id LIMIT ? OFFSET ?`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, sess)
	}
	return out, total, rows.Err()
}

// Session returns one session with all its events in chronological order.
func (s *Store) Session(ctx context.Context, id string) (Session, []event.Event, error) {
	sess, err := scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, nil, ErrNotFound
	}
	if err != nil {
		return Session{}, nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+eventColumns+` FROM events WHERE session_id = ? ORDER BY ts, id`, id)
	if err != nil {
		return Session{}, nil, err
	}
	events, err := scanEvents(rows)
	return sess, events, err
}
