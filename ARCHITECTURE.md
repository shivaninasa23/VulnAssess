# Architecture and methodology

The Flask application factory wires SQLAlchemy, Flask-Migrate, CSRF protection, rate limits, routes, and safe error pages. SQLAlchemy persists accounts, assessments, TCP services, and findings. Routes require a logged-in owner for saved assessments and reports.

Target validation checks IPs, CIDRs, hostnames, and HTTP URLs against the configured allowlist. Nmap executes with arguments and `shell=False`, TCP connect and light service identification, bounded ports, and strict timeouts. HTTP checks disable automatic redirects, validate each redirect scope, verify TLS, enforce timeouts, and do not crawl.

The risk engine records selected exposed services using documented severity heuristics. Open ports are not called vulnerable by themselves. Missing-header rules describe defense-in-depth weaknesses. Each finding stores rationale, confidence, evidence, expected configuration, impact, and remediation. ReportLab generates a PDF from persisted records, escapes untrusted text, and adds page numbers.

Assessments run synchronously, with rate limits and a maximum subprocess timeout. Failures are persisted as `failed`. This suits local small-scope usage, not concurrent enterprise scanning.
