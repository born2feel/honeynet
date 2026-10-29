import { useCallback, useEffect, useRef, useState } from "react";
import { api, setToken, type HoneyEvent, type Window } from "./api";
import { usePoll, useLive } from "./hooks";
import { clean, flag, num, pct, tagLabel } from "./format";
import { AttackMap, type Ping } from "./components/AttackMap";
import { Timeline } from "./components/Timeline";
import { TopList } from "./components/TopList";
import { LiveFeed } from "./components/LiveFeed";
import { Sessions } from "./components/Sessions";
import { Replay } from "./components/Replay";

const WINDOWS: Window[] = ["1h", "24h", "7d", "30d", "all"];
const FEED_SIZE = 80;
const PING_MS = 2400;

function sessionFromHash(): string | null {
  const m = /^#session=([\w-]+)$/.exec(location.hash);
  return m ? m[1] : null;
}

function readWindow(): Window {
  try {
    const w = localStorage.getItem("honeynet.window") as Window | null;
    if (w && WINDOWS.includes(w)) return w;
  } catch {
    /* storage unavailable */
  }
  return "24h";
}

export default function App() {
  const [win, setWin] = useState<Window>(readWindow);
  const [needToken, setNeedToken] = useState(false);
  const [authNonce, setAuthNonce] = useState(0);
  // The open replay lives in the URL hash so a session can be linked to.
  const [replay, setReplayState] = useState<string | null>(() => sessionFromHash());
  const setReplay = useCallback((id: string | null) => {
    setReplayState(id);
    history.replaceState(null, "", id ? `#session=${encodeURIComponent(id)}` : location.pathname + location.search);
  }, []);
  const [feed, setFeed] = useState<HoneyEvent[]>([]);
  const [pings, setPings] = useState<Ping[]>([]);
  const [rate, setRate] = useState(0);
  const arrivals = useRef<number[]>([]);

  const unauthorized = useCallback(() => setNeedToken(true), []);
  const deps = [win, authNonce];
  const { data: stats, error } = usePoll(() => api.stats(win), 10000, deps, unauthorized);
  const { data: points } = usePoll(() => api.map(win), 30000, deps, unauthorized);
  const { data: health } = usePoll(() => api.health(), 60000, [authNonce], unauthorized);

  useEffect(() => {
    try {
      localStorage.setItem("honeynet.window", win);
    } catch {
      /* ignore */
    }
  }, [win]);

  // Seed the feed with recent history so it isn't empty on load.
  useEffect(() => {
    api.events(FEED_SIZE).then(
      (evs) => setFeed(evs.filter((e) => e.kind !== "disconnect")),
      () => {},
    );
  }, [authNonce]);

  const onEvent = useCallback((e: HoneyEvent) => {
    arrivals.current.push(Date.now());
    if (e.kind === "disconnect") return;
    setFeed((f) => [e, ...f].slice(0, FEED_SIZE));
    if (e.lat !== undefined && e.lon !== undefined && e.kind !== "connect") {
      const ping = { id: e.id, lat: e.lat, lon: e.lon, sensor: e.sensor };
      setPings((p) => [...p.slice(-40), ping]);
      setTimeout(() => setPings((p) => p.filter((x) => x.id !== ping.id)), PING_MS);
    }
  }, []);
  const live = useLive(onEvent, !needToken);

  useEffect(() => {
    const t = setInterval(() => {
      const cutoff = Date.now() - 60_000;
      arrivals.current = arrivals.current.filter((x) => x > cutoff);
      setRate(arrivals.current.length);
    }, 2000);
    return () => clearInterval(t);
  }, []);

  const t = stats?.totals;
  const host = health?.hostname ?? "srv";

  return (
    <div className="app">
      <header className="top-bar">
        <div className="brand">
          <svg viewBox="0 0 32 32" width="26" height="26" aria-hidden>
            <path d="M16 2 28 9v14L16 30 4 23V9z" fill="none" stroke="currentColor" strokeWidth="2" />
            <path d="M16 9 22 12.5v7L16 23l-6-3.5v-7z" fill="currentColor" />
          </svg>
          <h1>honeynet</h1>
          {health?.demo && <span className="demo-badge" title="Synthetic traffic from documentation IP ranges">demo data</span>}
        </div>
        <div className="sensors">
          {(health?.sensors ?? []).map((s) => (
            <span key={s} className={`badge badge-${s}`}>
              {s}
            </span>
          ))}
        </div>
        <div className={`live live-${live}`}>
          <i />
          {live === "live" ? `live · ${rate}/min` : live}
        </div>
        <nav className="windows" aria-label="Time range">
          {WINDOWS.map((w) => (
            <button key={w} className={w === win ? "active" : ""} onClick={() => setWin(w)}>
              {w}
            </button>
          ))}
        </nav>
      </header>

      {error && <div className="error-bar">Can't reach the API: {error}</div>}

      <section className="kpis">
        <Kpi label="Attacks" value={t?.attacks} hint="auth, commands, requests, tunnels" accent />
        <Kpi label="Unique IPs" value={t?.unique_ips} />
        <Kpi label="Countries" value={t?.countries} />
        <Kpi label="Login attempts" value={t?.auth_attempts} />
        <Kpi label="Successful logins" value={t?.logins} hint={t ? `${pct(t.logins, t.auth_attempts)} of attempts` : ""} />
        <Kpi label="Shell commands" value={t?.commands} />
        <Kpi label="HTTP requests" value={t?.requests} />
        <Kpi label="Tunnel attempts" value={t?.tunnels} />
      </section>

      <div className="grid-main">
        <section className="panel map-panel">
          <h3>Attack origins</h3>
          <AttackMap points={points ?? []} pings={pings} />
        </section>
        <LiveFeed events={feed} onOpenSession={setReplay} />
      </div>

      <section className="panel">
        <h3>Activity</h3>
        <Timeline buckets={stats?.timeline ?? []} />
      </section>

      <div className="grid-tops">
        <TopList
          title="Credential pairs"
          items={stats?.top_credentials}
          render={(c) => (
            <>
              {clean(c.key, 30)} <span className="muted">/</span> {clean(c.label, 30)}
            </>
          )}
        />
        <TopList title="Passwords" items={stats?.top_passwords} />
        <TopList title="Usernames" items={stats?.top_usernames} />
        <TopList
          title="Countries (by IPs)"
          items={stats?.top_countries}
          mono={false}
          render={(c) => (
            <>
              {flag(c.key)} {c.label || c.key}
            </>
          )}
        />
        <TopList title="Techniques" items={stats?.top_tags} mono={false} render={(c) => tagLabel(c.key)} />
        <TopList
          title="Noisiest IPs"
          items={stats?.top_ips}
          render={(c) => (
            <>
              {flag(c.label)} {c.key}
            </>
          )}
        />
      </div>

      <div className="grid-wide">
        <TopList title="Shell commands" items={stats?.top_commands} />
        <TopList title="HTTP paths" items={stats?.top_paths} />
        <TopList title="SSH clients" items={stats?.top_clients} />
      </div>

      <Sessions onOpen={setReplay} onUnauthorized={unauthorized} key={authNonce} />

      <footer className="foot muted">
        honeynet · {t ? `${num(t.connections)} connections in view` : "loading"} · every string on this page was typed by an attacker
      </footer>

      {replay && <Replay id={replay} host={host} onClose={() => setReplay(null)} />}
      {needToken && (
        <TokenPrompt
          onSubmit={(tok) => {
            setToken(tok);
            setNeedToken(false);
            setAuthNonce((n) => n + 1);
          }}
        />
      )}
    </div>
  );
}

function Kpi({ label, value, hint, accent }: { label: string; value?: number; hint?: string; accent?: boolean }) {
  return (
    <div className={accent ? "kpi accent" : "kpi"}>
      <span className="kpi-label">{label}</span>
      <span className="kpi-value">{value === undefined ? "—" : num(value)}</span>
      {hint && <span className="kpi-hint">{hint}</span>}
    </div>
  );
}

function TokenPrompt({ onSubmit }: { onSubmit: (t: string) => void }) {
  const [v, setV] = useState("");
  return (
    <div className="modal-backdrop">
      <form
        className="modal token"
        onSubmit={(e) => {
          e.preventDefault();
          if (v) onSubmit(v);
        }}
      >
        <h2>Dashboard token</h2>
        <p className="muted">This honeynet requires the token set in HONEYNET_DASHBOARD_TOKEN.</p>
        <input type="password" autoFocus value={v} onChange={(e) => setV(e.target.value)} placeholder="token" />
        <button type="submit">Unlock</button>
      </form>
    </div>
  );
}
