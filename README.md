# API Heist Academy — Hardened Edition

Defensive verification application for the **OWASP API Security Top 10 (2023)**. The original classroom release intentionally exposed ten vulnerable API paths; this edition removes the exploit flags and enforces authentication, authorization, validation, resource limits, and safe integration boundaries.

## Attribution

- Original intentionally vulnerable classroom lab: [thano-ai/api_heist](https://github.com/thano-ai/api_heist)
- Security hardening, defensive verification suite, and Arabic remediation report: **Ammar Aikan**
- Purpose: a defensive coursework contribution that preserves the original repository history and documents the remediation of each OWASP API risk.

> The default server binds to `127.0.0.1`. Use a TLS reverse proxy and explicitly configured secrets before any non-loopback deployment.

## Security model

| Area | Hardened behavior |
|---|---|
| Team identity | Registration returns a signed, expiring Bearer token bound to one team and profile |
| Admin actions | Separate `X-Admin-Token`; admin routes are disabled when it is not configured |
| Object access | The requested profile ID must match the authenticated token subject |
| Editable fields | Only `name` and `email` are accepted; role and balance remain server-owned |
| Resource use | Body-size, registration, request, transfer-count, and transfer-value limits |
| Outbound fetch | Default-deny, HTTPS-only, exact allowlist, public-IP validation, no redirects, bounded response |
| Webhooks | HMAC-SHA256 signature, timestamp freshness, event allowlist, bounded JSON, replay prevention |
| Browser boundary | Same-origin only, CSP and security headers, safe dynamic rendering |
| Retired surfaces | `/api/v1/users`, `/api/game/submit-flag`, and `/api/ultimate-challenge` return `410` |

The detailed Arabic remediation report is in [`docs/SECURITY_REMEDIATION_REPORT_AR.md`](docs/SECURITY_REMEDIATION_REPORT_AR.md).

## Using the post-remediation guide

Open `http://127.0.0.1:5000` and choose **افتح الثغرات العشر المؤمّنة**. All ten
controls can be opened without team registration, timer state, shared progress,
or flags. Each page shows the former risk, root cause, enforced controls, code
changes, safe negative requests, and expected HTTP results.

Registration is optional and is used only when a protected verification request
needs a team Bearer token. In hardened mode, **إعادة عرض الدليل** clears only the
browser's local guide state and never asks for the administrator token. The
server-wide database reset remains a separate protected API operation.

## Requirements

- Python 3.10+
- Git
- A modern browser
- Optional: Docker Desktop
- Optional: Postman with `postman/API-Heist-Academy.postman_collection.json`

## Local setup (PowerShell)

From the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\backend\requirements.txt
```

Generate independent high-entropy values for the signing, administrator, and webhook secrets:

```powershell
function New-HeistSecret {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [Convert]::ToBase64String($bytes)
}

$env:DVAPI_SECRET = New-HeistSecret
$env:DVAPI_ADMIN_TOKEN = New-HeistSecret
$env:DVAPI_WEBHOOK_SECRET = New-HeistSecret
```

Start the application:

```powershell
.\.venv\Scripts\python.exe .\backend\app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

If `DVAPI_SECRET` is omitted on loopback, the app generates an ephemeral signing key and existing tokens expire when the process restarts. Admin and webhook operations remain disabled until their dedicated secrets are configured.

## Authentication flow

Register a new team:

```http
POST /api/game/register
Content-Type: application/json

{
  "teamName": "Alpha",
  "members": ["Security Student"]
}
```

The response includes `accessToken`, `expiresIn`, and `profileId`. Send the token on protected routes:

```http
Authorization: Bearer <accessToken>
```

Possession of a different team name is not authentication. The legacy `X-Team-Name` header is ignored.

## Webhook signing

For an exact raw JSON body, compute:

```text
HMAC-SHA256(DVAPI_WEBHOOK_SECRET, "<unix_timestamp>.<raw_body>")
```

Then send:

```http
X-Webhook-Timestamp: <unix_timestamp>
X-Webhook-Signature: sha256=<lowercase hex digest>
```

The timestamp must be fresh and an accepted signature can be used only once.

## Outbound fetch allowlist

`POST /api/fetch-url` is disabled for all hosts by default. Configure only exact trusted public hosts when the feature is needed:

```powershell
$env:DVAPI_FETCH_ALLOWLIST = "api.example.com,status.example.com"
```

HTTP, credentials in URLs, non-standard ports, fragments, redirects, non-public IPs, unlisted hosts, oversized responses, and unexpected content types are rejected.

## Docker

Docker Compose requires `DVAPI_SECRET` to be set. It binds the published port to localhost, runs as a non-root user, drops Linux capabilities, enables `no-new-privileges`, and uses a read-only root filesystem.

```powershell
$env:DVAPI_SECRET = New-HeistSecret
$env:DVAPI_ADMIN_TOKEN = New-HeistSecret
$env:DVAPI_WEBHOOK_SECRET = New-HeistSecret
docker compose up --build
```

## Verification

Install test dependencies and run the regression suite:

```powershell
.\.venv\Scripts\python.exe -m pip install -r .\backend\requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pip check
```

The suite uses a temporary SQLite database and does not modify `backend/heist.db`.

## Project layout

| Piece | Path |
|---|---|
| Flask API and security controls | `backend/app.py` |
| Runtime dependencies | `backend/requirements.txt` |
| Security regression tests | `tests/` |
| Hardened browser UI | `frontend/` |
| Hardened Postman collection | `postman/` |
| Arabic remediation report | `docs/SECURITY_REMEDIATION_REPORT_AR.md` |

## Production notes

- Terminate TLS at a trusted reverse proxy and keep the application on a private network.
- Store secrets in a secrets manager, not source control or image layers.
- Rotate all secrets if an earlier vulnerable deployment was exposed.
- Keep `DVAPI_FETCH_ALLOWLIST` empty unless outbound fetching is required.
- For horizontal multi-host deployment, move rate limiting and replay state from SQLite to a shared transactional store.
