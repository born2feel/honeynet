import type { ReactNode } from "react";
import type { Count } from "../api";
import { clean, num } from "../format";

interface Props {
  title: string;
  items: Count[] | undefined;
  render?: (c: Count) => ReactNode;
  mono?: boolean;
}

export function TopList({ title, items, render, mono = true }: Props) {
  const max = Math.max(1, ...(items ?? []).map((c) => c.count));
  return (
    <section className="panel top">
      <h3>{title}</h3>
      {!items || items.length === 0 ? (
        <p className="empty">Nothing yet</p>
      ) : (
        <ol>
          {items.map((c, i) => (
            <li key={`${c.key}\u0000${c.label ?? ""}`}>
              <span className="bar-fill" style={{ width: `${(c.count / max) * 100}%` }} />
              <span className="rank">{i + 1}</span>
              <span className={mono ? "key mono" : "key"} title={c.key}>
                {render ? render(c) : clean(c.key, 80) || <em>(empty)</em>}
              </span>
              <span className="count">{num(c.count)}</span>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
