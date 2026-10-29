// Types mirror the Go structs in internal/event and internal/store.

export type Sensor = "ssh" | "telnet" | "http";
export type Kind = "connect" | "auth" | "command" | "request" | "tunnel" | "disconnect";

export interface HoneyEvent {
  id: number;
  time: string;
  sensor: Sensor;
  kind: Kind;
  session_id?: string;
  src_ip: string;
  src_port?: number;
  country_code?: string;
  country?: string;
  city?: string;
  lat?: number;
  lon?: number;
  client?: string;
  username?: string;
  password?: string;
  success?: boolean;
  command?: string;
  output?: string;
  method?: string;
  path?: string;
  user_agent?: string;
  body?: string;
  tags?: string[];
  detail?: string;
}

export interface Count {
  key: string;
  label?: string;
  count: number;
}

export interface Totals {
  attacks: number;
  connections: number;
  auth_attempts: number;
  logins: number;
  commands: number;
  requests: number;
  tunnels: number;
  unique_ips: number;
  countries: number;
}

export interface Bucket {
  start: string;
  ssh: number;
  telnet: number;
  http: number;
}

export interface Stats {
  since: string;
  until: string;
  totals: Totals;
  timeline: Bucket[];
  top_usernames: Count[];
  top_passwords: Count[];
  top_credentials: Count[];
  top_commands: Count[];
  top_countries: Count[];
  top_ips: Count[];
  top_paths: Count[];
  top_tags: Count[];
  top_clients: Count[];
}

export interface MapPoint {
  lat: number;
  lon: number;
  country_code: string;
  city?: string;
  ips: number;
  attacks: number;
}

export interface Session {
  id: string;
  sensor: Sensor;
  src_ip: string;
  src_port: number;
  started_at: string;
  ended_at?: string;
  geo: { country_code?: string; country?: string; city?: string };
  client?: string;
  auth_attempts: number;
  logged_in: boolean;
  username?: string;
  password?: string;
  commands: number;
}

export interface Health {
  status: string;
  uptime_s: number;
  sensors: string[];
  hostname: string;
  demo: boolean;
}

export type Window = "1h" | "24h" | "7d" | "30d" | "all";

const TOKEN_KEY = "honeynet.token";

export function getToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setToken(t: string) {
  try {
    sessionStorage.setItem(TOKEN_KEY, t);
  } catch {
    /* storage unavailable: token lives for this page only */
  }
}

export class Unauthorized extends Error {}

async function get<T>(path: string, params: Record<string, string | number | undefined> = {}): Promise<T> {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined) q.set(k, String(v));
  const token = getToken();
  const res = await fetch(`/api/${path}${q.size ? `?${q}` : ""}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (res.status === 401) throw new Unauthorized();
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => get<Health>("health"),
  stats: (window: Window) => get<Stats>("stats", { window, buckets: 48, top: 10 }),
  map: (window: Window) => get<MapPoint[]>("map", { window, limit: 800 }),
  events: (limit = 60) => get<HoneyEvent[]>("events", { limit }),
  sessions: (offset: number, loggedIn: boolean, limit = 12) =>
    get<{ total: number; sessions: Session[] }>("sessions", { offset, limit, logged_in: loggedIn ? 1 : undefined }),
  session: (id: string) => get<{ session: Session; events: HoneyEvent[] }>(`sessions/${encodeURIComponent(id)}`),
};

export function liveURL(): string {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const token = getToken();
  return `${proto}//${location.host}/api/live${token ? `?token=${encodeURIComponent(token)}` : ""}`;
}
