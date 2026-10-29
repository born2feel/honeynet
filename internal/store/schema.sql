CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,             -- unix milliseconds, UTC
    sensor       TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    session_id   TEXT    NOT NULL DEFAULT '',
    src_ip       TEXT    NOT NULL,
    src_port     INTEGER NOT NULL DEFAULT 0,
    country_code TEXT    NOT NULL DEFAULT '',
    country      TEXT    NOT NULL DEFAULT '',
    city         TEXT    NOT NULL DEFAULT '',
    lat          REAL    NOT NULL DEFAULT 0,
    lon          REAL    NOT NULL DEFAULT 0,
    client       TEXT    NOT NULL DEFAULT '',
    username     TEXT    NOT NULL DEFAULT '',
    password     TEXT    NOT NULL DEFAULT '',
    success      INTEGER NOT NULL DEFAULT 0,
    command      TEXT    NOT NULL DEFAULT '',
    output       TEXT    NOT NULL DEFAULT '',
    method       TEXT    NOT NULL DEFAULT '',
    path         TEXT    NOT NULL DEFAULT '',
    user_agent   TEXT    NOT NULL DEFAULT '',
    body         TEXT    NOT NULL DEFAULT '',
    detail       TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events (session_id) WHERE session_id <> '';

-- Covering indexes for the dashboard aggregates. Rows carry bulky attacker
-- payloads (command output, request bodies), so scanning the table itself is
-- several times slower than scanning these narrow indexes.
CREATE INDEX IF NOT EXISTS idx_events_overview ON events (ts, kind, sensor, success, src_ip, country_code, country);
CREATE INDEX IF NOT EXISTS idx_events_creds    ON events (ts, username, password);
CREATE INDEX IF NOT EXISTS idx_events_kind_ts  ON events (kind, ts, command, path);
CREATE INDEX IF NOT EXISTS idx_events_clients  ON events (ts, client, session_id) WHERE client <> '';
CREATE INDEX IF NOT EXISTS idx_events_geo      ON events (ts, lat, lon, country_code, city, src_ip, kind) WHERE country_code <> '';

CREATE TABLE IF NOT EXISTS event_tags (
    event_id INTEGER NOT NULL REFERENCES events (id) ON DELETE CASCADE,
    ts       INTEGER NOT NULL, -- copied from events so tag stats don't need a join
    tag      TEXT    NOT NULL,
    PRIMARY KEY (event_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_event_tags_ts ON event_tags (ts, tag);

-- One row per SSH/Telnet connection, maintained from events at insert time
-- so the sessions list doesn't have to aggregate the whole events table.
CREATE TABLE IF NOT EXISTS sessions (
    id            TEXT    PRIMARY KEY,
    sensor        TEXT    NOT NULL,
    src_ip        TEXT    NOT NULL,
    src_port      INTEGER NOT NULL DEFAULT 0,
    started_at    INTEGER NOT NULL,
    ended_at      INTEGER NOT NULL DEFAULT 0,
    country_code  TEXT    NOT NULL DEFAULT '',
    country       TEXT    NOT NULL DEFAULT '',
    city          TEXT    NOT NULL DEFAULT '',
    lat           REAL    NOT NULL DEFAULT 0,
    lon           REAL    NOT NULL DEFAULT 0,
    client        TEXT    NOT NULL DEFAULT '',
    auth_attempts INTEGER NOT NULL DEFAULT 0,
    logged_in     INTEGER NOT NULL DEFAULT 0,
    username      TEXT    NOT NULL DEFAULT '',
    password      TEXT    NOT NULL DEFAULT '',
    commands      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions (started_at);
