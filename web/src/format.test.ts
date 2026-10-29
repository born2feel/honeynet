import { describe, expect, it } from "vitest";
import { ago, clean, duration, flag, num, pct, summary } from "./format";
import { buildFrames } from "./replay";
import type { HoneyEvent } from "./api";

describe("format", () => {
  it("formats numbers compactly only when large", () => {
    expect(num(999)).toBe("999");
    expect(num(12_345)).toBe("12.3K");
    expect(pct(1, 3)).toBe("33%");
    expect(pct(1, 30)).toBe("3.3%");
    expect(pct(1, 0)).toBe("0%");
  });

  it("formats relative times and durations", () => {
    const now = Date.parse("2026-01-01T12:00:00Z");
    expect(ago("2026-01-01T11:59:30Z", now)).toBe("30s ago");
    expect(ago("2026-01-01T09:00:00Z", now)).toBe("3h ago");
    expect(duration("2026-01-01T12:00:00Z", "2026-01-01T12:01:05Z")).toBe("1m 5s");
    expect(duration("2026-01-01T12:00:00Z")).toBe("open");
  });

  it("neutralises control characters in attacker input", () => {
    expect(clean("\x1b[31mred\x1b[0m")).toBe("red");
    expect(clean("a\x07b")).toBe("a·b");
    expect(clean("x".repeat(10), 4)).toBe("xxxx…");
  });

  it("builds flags from country codes", () => {
    expect(flag("NL")).toBe("🇳🇱");
    expect(flag("")).toBe("");
  });

  it("summarises events", () => {
    const base = { id: 1, time: "", sensor: "ssh", src_ip: "192.0.2.1" } as const;
    expect(summary({ ...base, kind: "auth", username: "root", password: "toor", success: true })).toBe("LOGIN root / toor");
    expect(summary({ ...base, kind: "command", command: "uname -a" })).toBe("$ uname -a");
  });
});

describe("replay", () => {
  it("turns a session into terminal frames with bounded gaps", () => {
    const t = (s: number) => new Date(Date.UTC(2026, 0, 1, 0, 0, s)).toISOString();
    const events: HoneyEvent[] = [
      { id: 1, time: t(0), sensor: "ssh", kind: "connect", src_ip: "192.0.2.1", src_port: 5000 },
      { id: 2, time: t(1), sensor: "ssh", kind: "auth", src_ip: "192.0.2.1", username: "admin", password: "admin", success: true },
      { id: 3, time: t(50), sensor: "ssh", kind: "command", src_ip: "192.0.2.1", command: "id", output: "uid=1001(admin)" },
    ];
    const frames = buildFrames(events, "srv");
    const text = frames.map((f) => f.text).join("");
    expect(text).toContain("login as: admin");
    expect(text).toContain("admin@srv:~$ id\nuid=1001(admin)\n");
    expect(Math.max(...frames.map((f) => f.delay))).toBeLessThanOrEqual(2500);
  });
});
