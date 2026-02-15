# OpenClaw Security Guide

## Gateway Security (Issue #1971)

### The Problem

~900+ OpenClaw instances were found exposed on Shodan (port 18789) without authentication, allowing anyone to:

- Execute shell commands on the host
- Access API keys and credentials
- Read emails and calendar data
- Send messages on behalf of the user
- Control the browser

### Immediate Protection

OpenClaw now enforces **mandatory authentication** when binding to external interfaces (0.0.0.0, LAN IP).

#### Auto-Generated Secure Tokens

When you start the gateway on an external interface without auth configured, OpenClaw will:

1. **Auto-generate** a 256-bit cryptographically secure token
2. **Save it to your config** for persistence
3. **Log instructions** for connecting clients

The token is a 64-character hex string (e.g., `a3f7b2d8...`) providing strong protection against brute force attacks.

### Best Practices

#### 1. Use Loopback Binding (Safest)

```json
{
  "gateway": {
    "bind": "loopback"
  }
}
```

This binds to `127.0.0.1` only — no external access.

#### 2. Use Cloudflare Tunnel (Recommended for Remote)

Instead of exposing port 18789 directly:

```bash
# Install cloudflared
brew install cloudflared  # macOS
# or download from https://github.com/cloudflare/cloudflared

# Create tunnel
cloudflared tunnel create openclaw

# Route tunnel
cloudflared tunnel route dns openclaw openclaw.yourdomain.com

# Run tunnel (keeps 18789 private)
cloudflared tunnel run openclaw
```

#### 3. Use Tailscale (Zero-Config VPN)

```json
{
  "gateway": {
    "bind": "loopback",
    "tailscale": {
      "mode": "serve"
    }
  }
}
```

Only Tailscale network members can access your gateway.

#### 4. Firewall Protection

If you must expose directly, firewall the port:

```bash
# Linux (ufw)
sudo ufw deny 18789  # Block all
sudo ufw allow from 192.168.1.0/24 to any port 18789  # Allow LAN only

# macOS (pfctl)
echo "block drop quick on en0 proto tcp from any to any port 18789" | sudo pfctl -ef -
```

### Token Security Requirements

When binding externally, OpenClaw enforces:

- **Tokens**: Minimum 32 characters (256+ bits entropy)
- **Passwords**: Minimum 12 characters
- **Auto-generation**: 64-character hex (256 bits) if none provided

Weak tokens will be rejected with:

```
SECURITY: Gateway binding requires strong auth.
Token must be >=32 chars, password >=12 chars.
```

### Verifying Your Setup

Check if your gateway is exposed:

```bash
# Check public IP
shodan host $(curl -s ifconfig.me)

# Check local binding
sudo lsof -i :18789

# Should show 127.0.0.1:1879 (safe) or *:18789 (exposed)
```

### Incident Response

If you discover your gateway was exposed:

1. **Stop the gateway**: `openclaw gateway stop`
2. **Rotate tokens**: Generate new token in config
3. **Check logs**: Review `/tmp/openclaw/*.log` for unauthorized access
4. **Audit actions**: Check shell history, browser history, sent messages
5. **Revoke credentials**: Rotate any exposed API keys (OpenAI, etc.)

## Security & Trust

**Jamieson O'Reilly** ([@theonejvo](https://twitter.com/theonejvo)) is Security & Trust at OpenClaw. Jamieson is the founder of [Dvuln](https://dvuln.com) and brings extensive experience in offensive security, penetration testing, and security program development.

## Bug Bounties

OpenClaw is a labor of love. There is no bug bounty program and no budget for paid reports. Please still disclose responsibly so we can fix issues quickly.
The best way to help the project right now is by sending PRs.

## Maintainers: GHSA Updates via CLI

When patching a GHSA via `gh api`, include `X-GitHub-Api-Version: 2022-11-28` (or newer). Without it, some fields (notably CVSS) may not persist even if the request returns 200.

## Out of Scope

- Public Internet Exposure
- Using OpenClaw in ways that the docs recommend not to
- Prompt injection attacks

## Operational Guidance

For threat model + hardening guidance (including `openclaw security audit --deep` and `--fix`), see:

- `https://docs.openclaw.ai/gateway/security`

### Tool filesystem hardening

- `tools.exec.applyPatch.workspaceOnly: true` (recommended): keeps `apply_patch` writes/deletes within the configured workspace directory.
- `tools.fs.workspaceOnly: true` (optional): restricts `read`/`write`/`edit`/`apply_patch` paths to the workspace directory.
- Avoid setting `tools.exec.applyPatch.workspaceOnly: false` unless you fully trust who can trigger tool execution.

### Web Interface Safety

OpenClaw's web interface (Gateway Control UI + HTTP endpoints) is intended for **local use only**.

- Recommended: keep the Gateway **loopback-only** (`127.0.0.1` / `::1`).
  - Config: `gateway.bind="loopback"` (default).
  - CLI: `openclaw gateway run --bind loopback`.
- Do **not** expose it to the public internet (no direct bind to `0.0.0.0`, no public reverse proxy). It is not hardened for public exposure.
- If you need remote access, prefer an SSH tunnel or Tailscale serve/funnel (so the Gateway still binds to loopback), plus strong Gateway auth.
- The Gateway HTTP surface includes the canvas host (`/__openclaw__/canvas/`, `/__openclaw__/a2ui/`). Treat canvas content as sensitive/untrusted and avoid exposing it beyond loopback unless you understand the risk.

## Runtime Requirements

### Node.js Version

OpenClaw requires **Node.js 22.12.0 or later** (LTS). This version includes important security patches:

- CVE-2025-59466: async_hooks DoS vulnerability
- CVE-2026-21636: Permission model bypass vulnerability

Verify your Node.js version:
