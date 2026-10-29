// Package store persists events in SQLite and answers the dashboard's
// aggregate queries. It uses the pure-Go modernc.org/sqlite driver, so the
// binary builds without cgo and runs in a distroless container.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/born2feel/honeynet/internal/event"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// ErrNotFound is returned when a session doesn't exist.
var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

// Open opens (or creates) the database at path and applies the schema.
func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)&_pragma=temp_store(MEMORY)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One writer (the recorder) plus a few concurrent dashboard readers; WAL makes this safe.
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// InsertBatch writes events in one transaction, keeps the sessions table in
// sync and returns the events with their database IDs set.
func (s *Store) InsertBatch(ctx context.Context, events []event.Event) ([]event.Event, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	insEvent, err := tx.PrepareContext(ctx, `INSERT INTO events
		(ts, sensor, kind, session_id, src_ip, src_port, country_code, country, city, lat, lon,
		 client, username, password, success, command, output, method, path, user_agent, body, detail)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return nil, err
	}
	defer insEvent.Close()
	insTag, err := tx.PrepareContext(ctx, `INSERT INTO event_tags (event_id, ts, tag) VALUES (?, ?, ?)`)
	if err != nil {
		return nil, err
	}
	defer insTag.Close()

	out := make([]event.Event, 0, len(events))
	for _, e := range events {
		res, err := insEvent.ExecContext(ctx,
			e.Time.UnixMilli(), e.Sensor, e.Kind, e.SessionID, e.SrcIP, e.SrcPort,
			e.CountryCode, e.Country, e.City, e.Lat, e.Lon,
			e.Client, e.Username, e.Password, e.Success, e.Command, e.Output,
			e.Method, e.Path, e.UserAgent, e.Body, e.Detail)
		if err != nil {
			return nil, fmt.Errorf("insert event: %w", err)
		}
		if e.ID, err = res.LastInsertId(); err != nil {
			return nil, err
		}
		for _, tag := range e.Tags {
			if _, err := insTag.ExecContext(ctx, e.ID, e.Time.UnixMilli(), tag); err != nil {
				return nil, fmt.Errorf("insert tag: %w", err)
			}
		}
		if e.SessionID != "" {
			if err := updateSession(ctx, tx, e); err != nil {
				return nil, fmt.Errorf("update session: %w", err)
			}
		}
		out = append(out, e)
	}
	return out, tx.Commit()
}

func updateSession(ctx context.Context, tx *sql.Tx, e event.Event) error {
	ts := e.Time.UnixMilli()
	var err error
	switch e.Kind {
	case event.KindConnect:
		_, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO sessions
			(id, sensor, src_ip, src_port, started_at, country_code, country, city, lat, lon)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			e.SessionID, e.Sensor, e.SrcIP, e.SrcPort, ts, e.CountryCode, e.Country, e.City, e.Lat, e.Lon)
	case event.KindAuth:
		_, err = tx.ExecContext(ctx, `UPDATE sessions SET
			auth_attempts = auth_attempts + 1,
			client   = CASE WHEN client = '' THEN ? ELSE client END,
			logged_in = logged_in OR ?,
			username = CASE WHEN ? THEN ? ELSE username END,
			password = CASE WHEN ? THEN ? ELSE password END
			WHERE id = ?`,
			e.Client, e.Success, e.Success, e.Username, e.Success, e.Password, e.SessionID)
	case event.KindCommand:
		_, err = tx.ExecContext(ctx, `UPDATE sessions SET commands = commands + 1 WHERE id = ?`, e.SessionID)
	case event.KindDisconnect:
		_, err = tx.ExecContext(ctx, `UPDATE sessions SET ended_at = ? WHERE id = ?`, ts, e.SessionID)
	}
	return err
}

// Prune deletes events and sessions older than the cutoff. Returns deleted event count.
func (s *Store) Prune(ctx context.Context, before time.Time) (int64, error) {
	ms := before.UnixMilli()
	res, err := s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, ms)
	if err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE started_at < ?`, ms); err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

const eventColumns = `id, ts, sensor, kind, session_id, src_ip, src_port, country_code, country, city, lat, lon,
	client, username, password, success, command, output, method, path, user_agent, body, detail,
	COALESCE((SELECT group_concat(tag, ',') FROM event_tags t WHERE t.event_id = events.id), '')`

func scanEvents(rows *sql.Rows) ([]event.Event, error) {
	defer rows.Close()
	var out []event.Event
	for rows.Next() {
		var (
			e    event.Event
			ts   int64
			tags string
		)
		if err := rows.Scan(&e.ID, &ts, &e.Sensor, &e.Kind, &e.SessionID, &e.SrcIP, &e.SrcPort,
			&e.CountryCode, &e.Country, &e.City, &e.Lat, &e.Lon,
			&e.Client, &e.Username, &e.Password, &e.Success, &e.Command, &e.Output,
			&e.Method, &e.Path, &e.UserAgent, &e.Body, &e.Detail, &tags); err != nil {
			return nil, err
		}
		e.Time = time.UnixMilli(ts).UTC()
		if tags != "" {
			e.Tags = strings.Split(tags, ",")
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Recent returns the newest events, optionally only those with ID < before.
func (s *Store) Recent(ctx context.Context, limit int, before int64) ([]event.Event, error) {
	q := `SELECT ` + eventColumns + ` FROM events`
	args := []any{}
	if before > 0 {
		q += ` WHERE id < ?`
		args = append(args, before)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	return scanEvents(rows)
}
