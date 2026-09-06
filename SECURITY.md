# Security Policy

## Reporting a Vulnerability

Please **do not** open a public issue for security problems. Report them privately so they can be fixed before they are disclosed.

**How to report:**

1. **Preferred:** use the GitHub private vulnerability reporting form:
   https://github.com/iqbqioza/nostrfy/security/advisories/new
2. **Alternatively:** email the maintainer at **takuya@iqbqioza.com** with the subject
   prefixed with **`[SECURITY-REPORT:nostrfy]`** (e.g.
   `[SECURITY-REPORT:nostrfy] Path traversal in the Blossom GET handler`).

**Please include:**

- The affected version (from `nostrfy --version`)
- A description of the vulnerability and its impact
- Steps to reproduce (config snippets, request examples)
- Whether it affects a public deployment

## Response

This is a personal project maintained in spare time, so responses are best-effort:

- **Acknowledgement:** as soon as possible — ideally within **3 business days**.
- **Status updates:** you will be kept informed of the fix progress whenever possible.
- **Fix timeline:** depends on severity and availability — critical issues are prioritized; a fix and a security advisory are published as soon as practical.

## Scope

- The relay server itself (`nostrfy`): WebSocket handling, NIP implementations, the REST API, the management API (NIP-86), LMDB persistence and the Blossom file server.
- The official installation and deployment artifacts (`install.sh`, Dockerfile, systemd units, configuration templates).

Out of scope: third-party services you connect to (LiveKit, S3/R2 buckets, reverse proxies) and client-side applications.

## Security Notes for Operators

- nostrfy runs with **no root privileges required** — run it as a dedicated user and do not expose the management port publicly.
- Use TLS in front of the relay (reverse proxy or Cloudflare) — the relay itself serves plain HTTP/WS.
- Review the access control (`[access]` section, `nostrfy relay allow/deny`, NIP-86) to keep the relay open while preventing abuse.
- Report vulnerabilities even for minor issues — fixes are appreciated.