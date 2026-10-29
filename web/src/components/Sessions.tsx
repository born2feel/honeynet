import { useState } from "react";
import { api, type Session } from "../api";
import { usePoll, useNow } from "../hooks";
import { ago, clean, duration, flag } from "../format";

const PAGE = 12;

export function Sessions({ onOpen, onUnauthorized }: { onOpen: (id: string) => void; onUnauthorized: () => void }) {
  const [offset, setOffset] = useState(0);
  const [loggedIn, setLoggedIn] = useState(true);
  const now = useNow();
  const { data } = usePoll(() => api.sessions(offset, loggedIn, PAGE), 10000, [offset, loggedIn], onUnauthorized);
  const total = data?.total ?? 0;

  return (
    <section className="panel sessions">
      <div className="panel-head">
        <h3>Sessions</h3>
        <label className="toggle">
          <input
            type="checkbox"
            checked={loggedIn}
            onChange={(e) => {
              setLoggedIn(e.target.checked);
              setOffset(0);
            }}
          />
          logged in only
        </label>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Started</th>
              <th>Sensor</th>
              <th>Source</th>
              <th>Client</th>
              <th className="num">Tries</th>
              <th>Credentials</th>
              <th className="num">Cmds</th>
              <th>Duration</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data?.sessions.map((s: Session) => (
              <tr key={s.id} onClick={() => onOpen(s.id)} className="clickable">
                <td className="muted">{ago(s.started_at, now)}</td>
                <td>
                  <span className={`badge badge-${s.sensor}`}>{s.sensor}</span>
                </td>
                <td className="mono">
                  {flag(s.geo.country_code)} {s.src_ip}
                </td>
                <td className="mono muted ellipsis">{clean(s.client, 40) || "—"}</td>
                <td className="num">{s.auth_attempts}</td>
                <td className="mono">
                  {s.logged_in ? (
                    <span className="cred-ok">
                      {clean(s.username, 24)} / {clean(s.password, 24)}
                    </span>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td className="num">{s.commands}</td>
                <td className="muted">{duration(s.started_at, s.ended_at)}</td>
                <td>{s.commands > 0 && <span className="replay-link">▶ replay</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && data.sessions.length === 0 && <p className="empty">No sessions in this view</p>}
      </div>
      <div className="pager">
        <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
          ← newer
        </button>
        <span className="muted">
          {total === 0 ? 0 : offset + 1}–{Math.min(offset + PAGE, total)} of {total}
        </span>
        <button disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>
          older →
        </button>
      </div>
    </section>
  );
}
