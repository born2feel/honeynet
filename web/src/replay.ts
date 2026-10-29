import type { HoneyEvent } from "./api";

// A replay turns a session's events into terminal frames: each frame is text
// appended to the screen after a delay that mirrors the real gap between events.

export interface Frame {
  delay: number; // ms after the previous frame, at 1x speed
  text: string;
  kind: "meta" | "prompt" | "input" | "output" | "ok" | "fail";
}

const MAX_GAP = 2500; // long pauses are compressed so replays stay watchable
const TYPE_MS = 28; // per typed character

export function buildFrames(events: HoneyEvent[], host: string): Frame[] {
  const frames: Frame[] = [];
  let prev = events.length ? new Date(events[0].time).getTime() : 0;
  let user = "root";
  let loggedIn = false;
  const gap = (e: HoneyEvent) => {
    const t = new Date(e.time).getTime();
    const d = Math.min(MAX_GAP, Math.max(0, t - prev));
    prev = t;
    return d;
  };
  const prompt = () => `${user}@${host}:~${user === "root" ? "#" : "$"} `;

  for (const e of events) {
    const d = gap(e);
    switch (e.kind) {
      case "connect":
        frames.push({ delay: 0, kind: "meta", text: `# ${e.sensor} connection from ${e.src_ip}:${e.src_port ?? ""}\n` });
        break;
      case "auth":
        if (e.detail?.startsWith("publickey")) {
          frames.push({ delay: d, kind: "fail", text: `# public key offered: ${e.detail.slice(10)}\n` });
          break;
        }
        frames.push({ delay: d, kind: "meta", text: `login as: ${e.username ?? ""}\n` });
        frames.push({ delay: 200, kind: "meta", text: `password: ${e.password ?? ""}\n` });
        if (e.success) {
          user = e.username || user;
          loggedIn = true;
          frames.push({ delay: 300, kind: "ok", text: "# access granted\n" });
        } else {
          frames.push({ delay: 300, kind: "fail", text: "Permission denied, please try again.\n" });
        }
        break;
      case "command": {
        if (!loggedIn) loggedIn = true;
        frames.push({ delay: d, kind: "prompt", text: prompt() });
        // Typed character by character, like the attacker (or their script) sent it.
        const cmd = e.command ?? "";
        const chunk = Math.max(1, Math.ceil(cmd.length / 60));
        for (let i = 0; i < cmd.length; i += chunk) {
          frames.push({ delay: TYPE_MS, kind: "input", text: cmd.slice(i, i + chunk) });
        }
        frames.push({ delay: TYPE_MS, kind: "input", text: "\n" });
        if (e.output) frames.push({ delay: 120, kind: "output", text: e.output.endsWith("\n") ? e.output : `${e.output}\n` });
        break;
      }
      case "tunnel":
        frames.push({ delay: d, kind: "fail", text: `# port forward to ${e.detail ?? "?"} refused\n` });
        break;
      case "disconnect":
        frames.push({ delay: d, kind: "meta", text: "# connection closed\n" });
        break;
    }
  }
  return frames;
}

export function totalDuration(frames: Frame[]): number {
  return frames.reduce((s, f) => s + f.delay, 0);
}
