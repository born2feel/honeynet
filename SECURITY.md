# Security

honeynet is meant to be attacked. This document describes what it defends, how, and where its limits are.

## Threat model

| Asset | Threat | Mitigation |
|---|---|---|
| Host running the honeypot | Escape from the "shell" into the real system | There is no real shell. `internal/shell` is an interpreter over in-memory state and never calls `os/exec` or touches the disk. The container is distroless, non-root, read-only, with all capabilities dropped. |
| Host resources | Connection floods, slowloris, huge payloads | Global and per-IP connection limits, idle and absolute deadlines on every socket, caps on commands per session, output, virtual files and HTTP bodies, a non-blocking event queue that drops under load instead of stalling. |
| Third parties | Honeypot used as a proxy or for malware distribution | SSH port forwarding is refused (and recorded). Downloads in the fake shell are never fetched. The HTTP sensor serves only static pages. |
| Dashboard viewer | Stored XSS via usernames, commands, paths or user agents | React escaping, control-character stripping, no raw HTML rendering, strict CSP (`script-src 'self'`), `X-Frame-Options: DENY`. |
| Collected data | Unauthorized access to the dashboard or API | Binds to localhost by default, optional bearer token (constant-time compare), WebSocket origin check, a warning on startup when exposed without a token. |

## Known limitations

- **A skilled human will spot the emulation.** This is a medium-interaction honeypot aimed at automated attacks.
  Missing tools, canned `/proc` and the lack of real networking give it away to a person who looks closely.
- **Fingerprintable by design choices:** every weak password works at once, and any password works on the third
  attempt. This is intentional, to capture post-login behaviour.
- **No TLS on the dashboard.** Put it behind an SSH tunnel or a reverse proxy with TLS; don't expose it directly.
- **The token in the WebSocket URL** (`?token=`) can end up in reverse-proxy access logs. Browsers can't set
  headers on WebSocket connections; use a tunnel if this matters to you.
- **Retention** defaults to 30 days. Captured passwords may include real credentials that users mistyped into the
  wrong host. Treat the database as sensitive.

## Reporting

Please report vulnerabilities in honeynet itself privately via GitHub's "Report a vulnerability" on this repository.
