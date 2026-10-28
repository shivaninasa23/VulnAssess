"""Generate a conspicuously labeled illustrative PDF without scanning anything."""
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.services.reports import build_report

fixture=SimpleNamespace(
    report_id="FIXTURE-0001",target="127.0.0.1",assessment_type="http",status="completed",
    started_at=datetime(2026,1,1,tzinfo=timezone.utc),services=[],
    findings=[SimpleNamespace(
        finding_uid="FIXTURE-FINDING-01",check_name="HTTP header: Content-Security-Policy",
        severity="Medium",status="open",confidence="high",
        evidence="Fixture only: header absent in an illustrative response.",
        rationale="Illustrative configuration observation; not proof of exploitability.",
        expected="Define an application-appropriate content security policy.",
        impact="A browser defense-in-depth control may be absent.",
        remediation="Review application behavior and deploy a tested Content-Security-Policy.",
    )],
)
out=Path(__file__).resolve().parents[1]/"sample-report.pdf"
out.write_bytes(build_report(fixture,sample=True))
print(f"Generated clearly labeled fixture report: {out}")
