"""Transparent exposure rules; open ports alone are not vulnerabilities."""
import uuid
RULES={21:("FTP service exposed","Medium","FTP may transmit credentials or data without encryption; exposure does not prove misuse."),23:("Telnet service exposed","High","Telnet is unencrypted and can expose credentials and session data."),139:("SMB service exposed","Medium","SMB availability may increase attack surface; no vulnerability is inferred."),445:("SMB service exposed","Medium","SMB availability may increase attack surface; no vulnerability is inferred."),3389:("Remote desktop service exposed","Medium","Remote desktop access should be restricted to approved management networks."),3306:("Database service exposed","Medium","A database listener may permit unintended network access."),5432:("Database service exposed","Medium","A database listener may permit unintended network access."),27017:("Database service exposed","High","A database listener should not be publicly reachable without a reviewed access design.")}
def service_finding(port,service):
    if port==22:return dict(check_name="SSH service detected",severity="Informational",confidence="high",rationale="SSH is a common encrypted administration service; its presence alone is not a vulnerability.",impact="No impact is inferred from the open port alone.",remediation="Limit access to authorized management networks and maintain secure configuration.")
    rule=RULES.get(port)
    if not rule:return None
    name,severity,rationale=rule
    return dict(check_name=name,severity=severity,confidence="moderate",rationale=rationale,impact="An exposed service can increase reachable attack surface; exploitability was not tested.",remediation="Confirm the service is required, restrict network access, and use encrypted protocols where available.")
def header_findings(headers,https):
    rules={"Strict-Transport-Security":("Enable HSTS for HTTPS sites after confirming HTTPS works.","Low"),"Content-Security-Policy":("Define a policy appropriate to the application to reduce the impact of content injection.","Medium"),"X-Content-Type-Options":("Set nosniff to reduce MIME sniffing behavior.","Low"),"X-Frame-Options":("Set an appropriate frame policy or use frame-ancestors in Content-Security-Policy.","Low"),"Referrer-Policy":("Set a policy that limits unnecessary referrer disclosure.","Low"),"Permissions-Policy":("Restrict browser features not required by the application.","Informational")}; result=[]
    headers={str(key).lower():value for key,value in headers.items()}
    for name,(expected,severity) in rules.items():
        if name=="Strict-Transport-Security" and not https:continue
        observed=headers.get(name.lower())
        concern=None
        if not observed: concern=f"{name} was not present in the response."
        elif name=="Strict-Transport-Security":
            import re
            match=re.search(r"max-age\s*=\s*(\d+)",observed,re.I)
            if not match or int(match.group(1))<31536000: concern=f"Observed value: {observed[:300]} (max-age is missing or under one year)."
        elif name=="X-Content-Type-Options" and observed.strip().lower()!="nosniff": concern=f"Observed value: {observed[:300]} (expected nosniff)."
        elif name=="X-Frame-Options" and observed.strip().upper() not in ("DENY","SAMEORIGIN") and "frame-ancestors" not in headers.get("content-security-policy","").lower(): concern=f"Observed value: {observed[:300]} (no recognized frame restriction)."
        elif name=="Referrer-Policy" and observed.split(",")[-1].strip().lower() not in ("no-referrer","no-referrer-when-downgrade","same-origin","origin","strict-origin","origin-when-cross-origin","strict-origin-when-cross-origin","unsafe-url"): concern=f"Observed value: {observed[:300]} (unrecognized policy token)."
        elif name=="Content-Security-Policy" and any(token in observed.lower() for token in ("'unsafe-inline'","'unsafe-eval'")): concern=f"Observed policy includes unsafe script/style allowances: {observed[:300]}"
        elif name=="Permissions-Policy" and "*" in observed: concern=f"Observed policy includes a wildcard feature allowance: {observed[:300]}"
        if concern:result.append(dict(check_name="HTTP header: "+name,severity=severity,confidence="high",rationale="A missing or weak security header is a configuration weakness, not proof of exploitability.",evidence=concern,expected=expected,impact="The browser may lack this defense-in-depth control.",remediation=expected))
    return result
def normalize_finding(data):
    data.setdefault("evidence","Observed during authorized automated assessment."); data.setdefault("expected",data.get("remediation","Review the configuration.")); data.setdefault("finding_uid",str(uuid.uuid4())); return data
