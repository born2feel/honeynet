import { useState } from "react";
import type { Bucket } from "../api";
import { num } from "../format";

const W = 900;
const H = 150;
const PAD_B = 18;
const SENSORS = ["ssh", "telnet", "http"] as const;

function label(iso: string, spanMs: number): string {
  const d = new Date(iso);
  if (spanMs <= 2 * 86400_000) return d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
}

export function Timeline({ buckets }: { buckets: Bucket[] }) {
  const [hover, setHover] = useState<number | null>(null);
  if (buckets.length === 0) return null;
  const totals = buckets.map((b) => b.ssh + b.telnet + b.http);
  const max = Math.max(1, ...totals);
  const bw = W / buckets.length;
  const span = new Date(buckets[buckets.length - 1].start).getTime() - new Date(buckets[0].start).getTime();
  const plotH = H - PAD_B;
  const h = hover !== null ? buckets[hover] : null;

  return (
    <div className="timeline">
      <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" onMouseLeave={() => setHover(null)}>
        {[0.25, 0.5, 0.75].map((f) => (
          <line key={f} x1={0} x2={W} y1={plotH * f} y2={plotH * f} className="grid" />
        ))}
        {buckets.map((b, i) => {
          let y = plotH;
          return (
            <g key={b.start} onMouseEnter={() => setHover(i)} className={hover === i ? "bar hover" : "bar"}>
              <rect x={i * bw} y={0} width={bw} height={plotH} className="hit" />
              {SENSORS.map((s) => {
                const bh = (b[s] / max) * (plotH - 4);
                y -= bh;
                return bh > 0 ? <rect key={s} x={i * bw + 1} y={y} width={Math.max(1, bw - 2)} height={bh} className={`seg seg-${s}`} /> : null;
              })}
            </g>
          );
        })}
        {buckets.map((b, i) =>
          i % Math.ceil(buckets.length / 8) === 0 ? (
            <text key={b.start} x={i * bw + 2} y={H - 4} className="axis">
              {label(b.start, span)}
            </text>
          ) : null,
        )}
      </svg>
      <div className="timeline-legend">
        {h ? (
          <>
            <span className="muted">{new Date(h.start).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" })}</span>
            {SENSORS.map((s) => (
              <span key={s}>
                <i className={`dot dot-${s}`} /> {s} {num(h[s])}
              </span>
            ))}
          </>
        ) : (
          <>
            <span className="muted">peak {num(max)} / bucket</span>
            {SENSORS.map((s) => (
              <span key={s}>
                <i className={`dot dot-${s}`} /> {s}
              </span>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
