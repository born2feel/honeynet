import type { HoneyEvent } from "../api";
import { clock, flag, summary, tagLabel } from "../format";

export function LiveFeed({ events, onOpenSession }: { events: HoneyEvent[]; onOpenSession: (id: string) => void }) {
  return (
    <section className="panel feed">
      <h3>Live feed</h3>
      {events.length === 0 ? (
        <p className="empty">Waiting for attackers…</p>
      ) : (
        <ul>
          {events.map((e) => (
            <li
              key={e.id}
              className={`ev ev-${e.kind}${e.success ? " ev-success" : ""}${e.session_id ? " clickable" : ""}`}
              onClick={() => e.session_id && onOpenSession(e.session_id)}
            >
              <span className="t mono">{clock(e.time)}</span>
              <span className={`badge badge-${e.sensor}`}>{e.sensor}</span>
              <span className="src mono" title={e.country ?? ""}>
                {flag(e.country_code)} {e.src_ip}
              </span>
              <span className="what mono">{summary(e)}</span>
              {e.tags && e.tags.length > 0 && (
                <span className="tags">
                  {e.tags.slice(0, 2).map((t) => (
                    <span key={t} className="tag">
                      {tagLabel(t)}
                    </span>
                  ))}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
