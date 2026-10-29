import type { HoneyEvent } from "./api";

const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
const full = new Intl.NumberFormat("en");

export function num(n: number): string {
  return n >= 10_000 ? compact.format(n) : full.format(n);
}

export function pct(part: number, whole: number): string {
  if (!whole) return "0%";
  const p = (part / whole) * 100;
  return `${p < 10 ? p.toFixed(1) : Math.round(p)}%`;
}

export function ago(iso: string, now = Date.now()): string {
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function duration(fromIso: string, toIso?: string): string {
  if (!toIso) return "open";
  const s = Math.max(0, Math.round((new Date(toIso).getTime() - new Date(fromIso).getTime()) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

export function clock(iso: string): string {
  return new Date(iso).toLocaleTimeString("en-GB", { hour12: false });
}

// Strip control characters so attacker input can't mess with the layout
// (React already escapes HTML; this handles ANSI escapes and the like).
export function clean(s: string | undefined, max = 200): string {
  if (!s) return "";
  // eslint-disable-next-line no-control-regex
  const t = s.replace(/\x1b\[[0-9;?]*[A-Za-z]/g, "").replace(/[\x00-\x08\x0b-\x1f\x7f]/g, "·");
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

export const tagLabels: Record<string, string> = {
  sqli: "SQL injection",
  xss: "XSS",
  path_traversal: "Path traversal",
  cmd_injection: "Command injection",
  log4shell: "Log4Shell",
  secrets_probe: "Secrets probe",
  recon_probe: "Recon probe",
  wordpress: "WordPress",
  iot_exploit: "IoT exploit",
  php_exploit: "PHP exploit",
  scanner: "Scanner",
  unusual_method: "Unusual method",
  credential_capture: "Credential capture",
  download: "Malware download",
  recon: "Discovery",
  persistence: "Persistence",
  cryptominer: "Cryptominer",
  defense_evasion: "Defense evasion",
  execution: "Execution",
  botnet: "Botnet probe",
  lateral: "Lateral movement",
};

export function tagLabel(t: string): string {
  return tagLabels[t] ?? t.replace(/_/g, " ");
}

/** One-line human summary of an event for the live feed. */
export function summary(e: HoneyEvent): string {
  switch (e.kind) {
    case "connect":
      return "connected";
    case "disconnect":
      return "disconnected";
    case "auth":
      if (e.detail?.startsWith("publickey")) return `pubkey ${clean(e.username, 32)} ${e.detail.split(" ")[1] ?? ""}`;
      return `${e.success ? "LOGIN" : "login"} ${clean(e.username, 32)} / ${clean(e.password, 32)}`;
    case "command":
      return `$ ${clean(e.command, 120)}`;
    case "request":
      return `${clean(e.method, 10)} ${clean(e.path, 120)}`;
    case "tunnel":
      return `tunnel → ${clean(e.detail, 80)}`;
  }
}

/** Flag emoji from an ISO country code (renders as letters where unsupported). */
export function flag(cc?: string): string {
  if (!cc || cc.length !== 2) return "";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}
