# VulnAssess

VulnAssess is a local-first authenticated assessment and security reporting tool. It runs conservative TCP service discovery with Nmap and one-response HTTP security-header checks, saves observations to SQLite, and produces PDF reports. It does not exploit services, brute-force credentials, crawl sites, or submit forms.

## Features

- Responsive dark dashboard with database-backed metrics, history, filtering, and pagination.
- First-run account setup, scrypt password hashes, CSRF protection, rate limits, owner checks, and secure session cookie defaults.
- Explicit authorization confirmation per assessment; loopback-only default allowlist.
- Bounded Nmap TCP connect scan with light version detection, argument-list subprocess, configured ports, and timeouts.
- HTTP checks for HSTS, CSP, nosniff, frame options, Referrer-Policy, Permissions-Policy, and TLS certificate validation. Redirects are checked against scope.
- Transparent service exposure heuristics; an open port alone is not proof of vulnerability.
- Persistent findings and services, review/accepted-risk/resolved workflow, history, and PDF reports.

## Screenshots

Capture the dashboard, new assessment confirmation, and PDF preview locally after setup; no screenshots are bundled so none can be mistaken for real assessment results.

## Windows prerequisites and installation

Python 3.11+ is intended. This workspace was inspected with Python 3.14.3 and Nmap 7.80 at `C:\Program Files (x86)\Nmap\nmap.exe`. Nmap reported Npcap functions could not be loaded, so local connect-mode scans may be limited.

In PowerShell from this directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env`, replace `SECRET_KEY` with a locally generated secret (`python -c "import secrets; print(secrets.token_hex(32))"`), and keep `.env` private. Install Nmap from [nmap.org/download](https://nmap.org/download.html), including Npcap when offered. In a new PowerShell, confirm `nmap --version`; if it is not on PATH, configure `NMAP_PATH` with the full executable path.

## Initialize and run

Flask-Migrate manages schema changes. The repository contains the initial migration; apply it:

```powershell
$env:FLASK_APP = "run.py"
flask db upgrade
python run.py
```

Open `http://127.0.0.1:5000`. Choose first-time account setup and create a password of at least 12 characters. The server binds to loopback and runs without debug mode. SQLite is stored under `instance/`. After model changes, run `flask db migrate -m "describe change"` then `flask db upgrade`.

## Scope and configuration

`ALLOWED_TARGETS` is a comma-separated exact IP, CIDR, and hostname allowlist. Keep defaults unless explicitly authorized. Example lab scope: `127.0.0.1,::1,localhost,192.168.56.0/24`. Hostnames are resolved and every resulting address must be covered by the allowlist. Redirects undergo the same check. Do not expose the development server to a network. `PORTS`, `MAX_SCAN_SECONDS` (capped at 120), and `NMAP_PATH` configure discovery.

## Safe localhost check and reports

Keep loopback scope, open **New assessment**, enter `127.0.0.1`, choose Network discovery or HTTP checks, confirm authorization, and start. A clean network scan may return zero open services. If Nmap is unavailable, the assessment is explicitly marked failed. HTTP checks default to HTTPS; run a local HTTP server if you want a response to inspect, with certificate validation enabled.

There is no fake scan mode. Normal reports use saved assessment data only. Open an assessment and click **Download PDF**; even an empty result report faithfully shows zero findings and the actual status. A separately generated fixture-only sample is available with `python scripts/generate_sample_report.py`; its cover explicitly marks all entries as illustrative fixture data.

## Tests

```powershell
python -m pytest -q
python -m compileall -q app run.py
```

Tests use temporary SQLite and do not scan external systems. These checks do not imply browser-based or penetration testing.

## Architecture and limitations

The `app/` package contains the factory, models, routes, scope checks, scanner adapters, rule engine, and PDF service. Assessments are synchronous and bounded; a request occupies its local worker until it completes or times out. The tool does not validate CVEs or exploitability. Missing headers and exposed services are configuration observations for human review. DNS is validated before requests, but connection-level DNS pinning is not implemented; use trusted DNS and explicit scope. HTTP does not crawl and consumes at most one response chunk.

## Responsible use

Use only systems you own or have explicit written authorization to assess. Keep scope narrow, protect credentials and the database, and validate observations with a qualified reviewer. See [SECURITY.md](SECURITY.md).
