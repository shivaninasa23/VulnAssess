import ipaddress
from app.services.targets import validate_target,TargetError,validate_redirect
from app.services.risk import service_finding,header_findings
from app.services.scanner import run_nmap,ScanError
from app.models import User,Assessment,Finding
from app.extensions import db
def test_password_hash_and_login(client,app):
    with app.app_context():
        user=User.query.first(); assert user.password_hash!="correct-horse-battery-staple" and user.check_password("correct-horse-battery-staple")
    assert client.get("/dashboard").status_code==302
    assert client.post("/login",data={"username":"tester","password":"wrong-password"}).status_code==200
    assert client.post("/login",data={"username":"tester","password":"correct-horse-battery-staple"}).status_code==302
def test_target_allowlist_and_injection(app):
    with app.app_context():
        assert validate_target("127.0.0.1",app.config)[0]=="127.0.0.1"
        for bad in ["example.com","127.0.0.1;whoami","http://127.0.0.1/path"]:
            try:validate_target(bad,app.config)
            except TargetError:pass
            else:assert False,bad
def test_redirect_scope(app):
    with app.app_context():
        try:validate_redirect("http://192.168.1.5/next",app.config)
        except TargetError:pass
        else:assert False,"disallowed redirect accepted"
def test_private_public_allowlist():
    assert ipaddress.ip_address("127.0.0.1").is_loopback and not ipaddress.ip_address("8.8.8.8").is_loopback
def test_nmap_missing_tool(app):
    with app.app_context():
        try:run_nmap("127.0.0.1",{**app.config,"NMAP_PATH":"no-such-nmap-executable"})
        except ScanError as exc:assert "not installed" in str(exc)
        else:assert False
def test_nmap_timeout(app,monkeypatch):
    import app.services.scanner as scanner
    monkeypatch.setattr(scanner.shutil,"which",lambda _:"nmap.exe")
    def timeout(*args,**kwargs):raise scanner.subprocess.TimeoutExpired("nmap",1)
    monkeypatch.setattr(scanner.subprocess,"run",timeout)
    with app.app_context():
        try:scanner.run_nmap("127.0.0.1",app.config)
        except ScanError as exc:assert "timed out" in str(exc)
        else:assert False
def test_header_and_severity_rules():
    findings=header_findings({},True); assert len(findings)==6 and all("not proof" in f["rationale"] for f in findings)
    assert len(header_findings({},False))==5
    assert service_finding(23,"telnet")["severity"]=="High" and service_finding(22,"ssh")["severity"]=="Informational" and service_finding(80,"http") is None
    complete={"Strict-Transport-Security":"max-age=31536000","Content-Security-Policy":"default-src 'self'","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"strict-origin","Permissions-Policy":"geolocation=()"}
    assert header_findings(complete,True)==[]
def test_http_response_and_redirect_scope(app,monkeypatch):
    import app.services.scanner as scanner
    class Response:
        is_redirect=False; is_permanent_redirect=False
        headers={"x-content-type-options":"nosniff"}
        def iter_content(self,size):return iter([b"ok"])
        def close(self):pass
    monkeypatch.setattr(scanner.requests,"get",lambda *args,**kwargs:Response())
    with app.app_context():
        findings,_=scanner.run_http("http://127.0.0.1",app.config)
        assert len(findings)==4 and all("Strict-Transport-Security"!=f["check_name"].split(": ")[-1] for f in findings)
        class Redirect(Response):
            is_redirect=True
            headers={"Location":"http://192.168.1.10/private"}
        monkeypatch.setattr(scanner.requests,"get",lambda *args,**kwargs:Redirect())
        try:scanner.run_http("http://127.0.0.1",app.config)
        except TargetError:pass
        else:assert False,"out-of-scope redirect accepted"
def test_assessment_workflow_and_dashboard(client,app,monkeypatch):
    import app.routes as routes
    monkeypatch.setattr(routes,"run_nmap",lambda target,config:[])
    client.post("/login",data={"username":"tester","password":"correct-horse-battery-staple"})
    response=client.post("/assessments/new",data={"target":"127.0.0.1","assessment_type":"network","authorized":"yes"})
    assert response.status_code==302
    detail=client.get(response.headers["Location"]); assert b"completed" in detail.data
    assert client.get("/dashboard").status_code==200 and b"Finding severity" in client.get("/dashboard").data
    assert client.get("/history?sort=target&direction=asc").status_code==200
    with app.app_context():a=Assessment.query.first(); aid=a.id
    assert b"Report preview" in client.get(f"/assessments/{aid}/report/preview").data
def test_persistence_finding_update_and_report(client,app):
    client.post("/login",data={"username":"tester","password":"correct-horse-battery-staple"})
    with app.app_context():
        a=Assessment(report_id="report-1",target="127.0.0.1",assessment_type="http",status="completed",owner_id=User.query.first().id); db.session.add(a); db.session.flush(); f=Finding(finding_uid="finding-1",assessment_id=a.id,check_name="Header check",severity="Low",confidence="high",rationale="Observed",evidence="Missing",expected="Set it",impact="Weakness",remediation="Fix it"); db.session.add(f); db.session.commit(); aid=a.id; fid=f.id
    assert client.post(f"/findings/{fid}/status",data={"status":"resolved"},follow_redirects=True).status_code==200
    assert client.get(f"/assessments/{aid}/report").headers["Content-Type"]=="application/pdf"
    assert client.get(f"/assessments/{aid+999}/report").status_code==404
    with app.app_context():
        other=User(username="other"); other.set_password("another-secure-test-password"); db.session.add(other); db.session.commit()
    client.post("/logout")
    client.post("/login",data={"username":"other","password":"another-secure-test-password"})
    assert client.get(f"/assessments/{aid}/report").status_code==404

def test_csrf_rejects_missing_token():
    from app import create_app
    app=create_app({"TESTING":True,"SECRET_KEY":"csrf-test","SQLALCHEMY_DATABASE_URI":"sqlite:///:memory:","WTF_CSRF_ENABLED":True,"RATELIMIT_ENABLED":False})
    assert app.test_client().post("/login",data={"username":"x","password":"y"}).status_code==400

def test_http_request_errors_are_reported_safely(app,monkeypatch):
    import requests
    import app.services.scanner as scanner
    def timeout(*args,**kwargs):raise requests.Timeout("private response detail")
    monkeypatch.setattr(scanner.requests,"get",timeout)
    with app.app_context():
        try:scanner.run_http("http://127.0.0.1",app.config)
        except ScanError as exc:
            assert "timed out" in str(exc)
            assert "private response detail" not in str(exc)
        else:assert False,"HTTP timeout was not reported"

def test_assessment_rejects_out_of_scope_and_missing_authorization(client,monkeypatch):
    import app.routes as routes
    def unexpected(*args,**kwargs):raise AssertionError("scanner called for rejected input")
    monkeypatch.setattr(routes,"run_nmap",unexpected)
    client.post("/login",data={"username":"tester","password":"correct-horse-battery-staple"})
    denied=client.post("/assessments/new",data={"target":"127.0.0.1","assessment_type":"network"},follow_redirects=True)
    assert b"Confirm that you are authorized" in denied.data
    outside=client.post("/assessments/new",data={"target":"192.0.2.10","assessment_type":"network","authorized":"yes"},follow_redirects=True)
    assert b"outside the configured authorized target allowlist" in outside.data

def test_first_run_setup_and_secure_session_defaults():
    from app import create_app
    app=create_app({"TESTING":True,"SECRET_KEY":"setup-test","SQLALCHEMY_DATABASE_URI":"sqlite:///:memory:","WTF_CSRF_ENABLED":False,"RATELIMIT_ENABLED":False})
    with app.app_context():db.create_all()
    client=app.test_client()
    assert client.get("/setup").status_code==200
    weak=client.post("/setup",data={"username":"qa","password":"short"},follow_redirects=True)
    assert b"password of at least 12 characters" in weak.data
    response=client.post("/setup",data={"username":"qa-user","password":"qa-only-strong-password"})
    assert response.status_code==302 and response.headers["Location"].endswith("/dashboard")
    cookie=response.headers.get("Set-Cookie","")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    assert client.get("/setup").status_code==302
    with app.app_context():db.drop_all()
