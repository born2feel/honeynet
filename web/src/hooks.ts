import { useEffect, useRef, useState } from "react";
import { liveURL, Unauthorized, type HoneyEvent } from "./api";

/** Polls fn every intervalMs; refetches immediately when deps change. */
export function usePoll<T>(fn: () => Promise<T>, intervalMs: number, deps: unknown[], onUnauthorized: () => void) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const d = await fnRef.current();
        if (alive) {
          setData(d);
          setError(null);
        }
      } catch (e) {
        if (!alive) return;
        if (e instanceof Unauthorized) onUnauthorized();
        else setError(String(e));
      }
      if (alive) timer = setTimeout(tick, intervalMs);
    };
    tick();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { data, error };
}

export type LiveStatus = "connecting" | "live" | "offline";

/** Subscribes to the WebSocket feed, reconnecting with backoff. */
export function useLive(onEvent: (e: HoneyEvent) => void, enabled: boolean): LiveStatus {
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const cb = useRef(onEvent);
  cb.current = onEvent;

  useEffect(() => {
    if (!enabled) return;
    let ws: WebSocket | null = null;
    let retry = 0;
    let timer: ReturnType<typeof setTimeout>;
    let closed = false;

    const connect = () => {
      setStatus("connecting");
      ws = new WebSocket(liveURL());
      ws.onopen = () => {
        retry = 0;
        setStatus("live");
      };
      ws.onmessage = (m) => {
        try {
          cb.current(JSON.parse(m.data as string) as HoneyEvent);
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        if (closed) return;
        setStatus("offline");
        timer = setTimeout(connect, Math.min(15000, 1000 * 2 ** retry++));
      };
    };
    connect();
    return () => {
      closed = true;
      clearTimeout(timer);
      ws?.close();
    };
  }, [enabled]);

  return status;
}

/** Re-renders every intervalMs (for "x seconds ago" labels). */
export function useNow(intervalMs = 5000): number {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(t);
  }, [intervalMs]);
  return now;
}
