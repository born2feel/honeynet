import { useEffect, useMemo, useRef, useState } from "react";
import { api, type HoneyEvent, type Session } from "../api";
import { clean, duration, flag, tagLabel } from "../format";
import { buildFrames, totalDuration } from "../replay";

const SPEEDS = [1, 4, 16];

export function Replay({ id, host, onClose }: { id: string; host: string; onClose: () => void }) {
  const [data, setData] = useState<{ session: Session; events: HoneyEvent[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pos, setPos] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState(4);
  const screen = useRef<HTMLPreElement>(null);

  useEffect(() => {
    api.session(id).then(setData, (e) => setError(String(e)));
  }, [id]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const frames = useMemo(() => (data ? buildFrames(data.events, host) : []), [data, host]);

  useEffect(() => {
    if (!playing || pos >= frames.length) return;
    const t = setTimeout(() => setPos((p) => p + 1), frames[pos].delay / speed);
    return () => clearTimeout(t);
  }, [playing, pos, frames, speed]);

  useEffect(() => {
    screen.current?.scrollTo({ top: screen.current.scrollHeight });
  }, [pos]);

  const tags = useMemo(() => {
    const s = new Set<string>();
    data?.events.forEach((e) => e.tags?.forEach((t) => s.add(t)));
    return [...s];
  }, [data]);

  const done = pos >= frames.length;
  const s = data?.session;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} role="dialog" aria-label="Session replay">
        <header className="modal-head">
          <div>
            <h2>Session replay</h2>
            {s && (
              <p className="muted mono">
                <span className={`badge badge-${s.sensor}`}>{s.sensor}</span> {flag(s.geo.country_code)} {s.src_ip}
                {s.geo.city ? ` · ${s.geo.city}, ${s.geo.country}` : ""} · {clean(s.client, 40) || "unknown client"} ·{" "}
                {duration(s.started_at, s.ended_at)}
              </p>
            )}
          </div>
          <button className="icon" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        {tags.length > 0 && (
          <div className="replay-tags">
            {tags.map((t) => (
              <span key={t} className="tag">
                {tagLabel(t)}
              </span>
            ))}
          </div>
        )}
        {/* Rendered as text nodes only: everything here was typed by an attacker. */}
        <pre className="terminal" ref={screen}>
          {error && <span className="t-fail">{error}</span>}
          {frames.slice(0, pos).map((f, i) => (
            <span key={i} className={`t-${f.kind}`}>
              {f.text}
            </span>
          ))}
          {!done && <span className="cursor">▌</span>}
        </pre>
        <footer className="controls">
          <button onClick={() => (done ? (setPos(0), setPlaying(true)) : setPlaying(!playing))}>
            {done ? "↺ replay" : playing ? "❚❚ pause" : "▶ play"}
          </button>
          <button onClick={() => setPos(frames.length)} disabled={done}>
            ⏭ skip to end
          </button>
          <div className="speeds">
            {SPEEDS.map((v) => (
              <button key={v} className={v === speed ? "active" : ""} onClick={() => setSpeed(v)}>
                {v}×
              </button>
            ))}
          </div>
          <progress value={pos} max={Math.max(1, frames.length)} />
          <span className="muted mono">{Math.round(totalDuration(frames) / 1000)}s</span>
        </footer>
      </div>
    </div>
  );
}
