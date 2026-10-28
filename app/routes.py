"""Authenticated routes and bounded synchronous assessments."""
import uuid
from datetime import datetime,timezone
from functools import wraps
from flask import Blueprint,render_template,request,redirect,url_for,flash,session,abort,make_response,current_app
from .extensions import db,limiter
from .models import User,Assessment,Service,Finding
from .services.targets import validate_target,TargetError
from .services.scanner import run_nmap,run_http,ScanError,SCAN_LOCK
from .services.risk import service_finding,normalize_finding
from .services.reports import build_report
bp=Blueprint("main",__name__)
def login_required(fn):
    @wraps(fn)
    def wrapped(*args,**kwargs):
        if not session.get("user_id"):return redirect(url_for("main.login",next=request.path))
        return fn(*args,**kwargs)
    return wrapped
def owner_assessment(aid):return Assessment.query.filter_by(id=aid,owner_id=session.get("user_id")).first_or_404()
@bp.app_context_processor
def template_globals():return {"nav_user":db.session.get(User,session.get("user_id")) if session.get("user_id") else None}
@bp.route("/")
def index():return redirect(url_for("main.dashboard" if session.get("user_id") else "main.login"))
@bp.route("/setup",methods=["GET","POST"])
@limiter.limit("5 per hour",methods=["POST"])
def setup():
    if User.query.first():return redirect(url_for("main.login"))
    if request.method=="POST":
        username=request.form.get("username","").strip(); password=request.form.get("password","")
        if len(username)<3 or len(username)>80 or len(password)<12:flash("Use a username of 3–80 characters and password of at least 12 characters.","error")
        else:
            user=User(username=username); user.set_password(password); db.session.add(user); db.session.commit(); session.clear(); session["user_id"]=user.id; flash("Account created.","success"); return redirect(url_for("main.dashboard"))
    return render_template("auth.html",setup=True)
@bp.route("/login",methods=["GET","POST"])
@limiter.limit("5 per minute",methods=["POST"])
def login():
    if request.method=="POST":
        user=User.query.filter_by(username=request.form.get("username","").strip()).first()
        if user and user.check_password(request.form.get("password","")):session.clear(); session["user_id"]=user.id; return redirect(url_for("main.dashboard"))
        flash("Invalid username or password.","error")
    return render_template("auth.html",setup=False)
@bp.post("/logout")
@login_required
def logout():session.clear(); return redirect(url_for("main.login"))
@bp.route("/dashboard")
@login_required
def dashboard():
    uid=session["user_id"]; q=Assessment.query.filter_by(owner_id=uid); owned=Finding.query.join(Assessment).filter(Assessment.owner_id==uid)
    severity_counts={name:owned.filter(Finding.severity==name).count() for name in ("Critical","High","Medium","Low","Informational")}
    return render_template("dashboard.html",total=q.count(),findings=owned.count(),high=owned.filter(Finding.severity.in_(["Critical","High"])).count(),severity_counts=severity_counts,max_severity_count=max(severity_counts.values(),default=0),recent=q.order_by(Assessment.started_at.desc()).limit(6).all())
@bp.route("/assessments/new",methods=["GET","POST"])
@login_required
@limiter.limit("4 per minute",methods=["POST"])
def new_assessment():
    if request.method=="POST":
        target=request.form.get("target",""); kind=request.form.get("assessment_type","")
        if request.form.get("authorized")!="yes":flash("Confirm that you are authorized to assess this target.","error")
        elif kind not in ("network","http","both"):flash("Select a valid assessment type.","error")
        else:
            try:host,_=validate_target(target,current_app.config,allow_url=kind in ("http","both"))
            except TargetError as exc:flash(str(exc),"error")
            else:
                a=Assessment(report_id=str(uuid.uuid4()),target=host,assessment_type=kind,status="running",owner_id=session["user_id"]); db.session.add(a); db.session.commit()
                locked=SCAN_LOCK.acquire(timeout=1)
                try:
                    if not locked:raise ScanError("Another assessment is running. Wait for it to finish before starting another.")
                    if kind in ("network","both"):
                        for row in run_nmap(host,current_app.config):
                            svc=Service(assessment_id=a.id,**row); db.session.add(svc); finding=service_finding(svc.port,svc.service_name)
                            if finding:db.session.add(Finding(assessment_id=a.id,**normalize_finding(finding)))
                    if kind in ("http","both"):
                        rows,cert=run_http(target if "://" in target else host,current_app.config)
                        for item in rows+([cert] if cert else []):db.session.add(Finding(assessment_id=a.id,**normalize_finding(item)))
                    a.status="completed"
                except (ScanError,TargetError) as exc:a.status="failed"; a.error=str(exc)[:300]
                except Exception:current_app.logger.exception("Assessment execution failed"); a.status="failed"; a.error="Assessment failed due to an internal error."
                finally:
                    if locked:SCAN_LOCK.release()
                    a.ended_at=datetime.now(timezone.utc); db.session.commit()
                flash("Assessment completed." if a.status=="completed" else "Assessment failed: "+(a.error or "Unknown error"),"success" if a.status=="completed" else "error"); return redirect(url_for("main.assessment_detail",aid=a.id))
    return render_template("new_assessment.html")
@bp.route("/history")
@login_required
def history():
    q=Assessment.query.filter_by(owner_id=session["user_id"]); status=request.args.get("status","")
    if status in ("completed","failed","running"):q=q.filter_by(status=status)
    sort=request.args.get("sort","date"); direction=request.args.get("direction","desc")
    column={"date":Assessment.started_at,"target":Assessment.target,"status":Assessment.status}.get(sort,Assessment.started_at)
    pagination=q.order_by(column.desc() if direction=="desc" else column.asc()).paginate(page=max(1,request.args.get("page",1,type=int)),per_page=15,error_out=False)
    return render_template("history.html",pagination=pagination,status=status,sort=sort,direction=direction)
@bp.route("/assessments/<int:aid>")
@login_required
def assessment_detail(aid):return render_template("assessment.html",a=owner_assessment(aid))
@bp.post("/assessments/<int:aid>/delete")
@login_required
def assessment_delete(aid):
    db.session.delete(owner_assessment(aid)); db.session.commit(); flash("Assessment deleted.","success"); return redirect(url_for("main.history"))
@bp.route("/findings/<int:fid>")
@login_required
def finding_detail(fid):
    f=Finding.query.join(Assessment).filter(Finding.id==fid,Assessment.owner_id==session["user_id"]).first_or_404(); return render_template("finding.html",f=f)
@bp.post("/findings/<int:fid>/status")
@login_required
def finding_status(fid):
    f=Finding.query.join(Assessment).filter(Finding.id==fid,Assessment.owner_id==session["user_id"]).first_or_404(); status=request.form.get("status")
    if status not in ("open","reviewed","accepted_risk","resolved"):abort(400)
    f.status=status; db.session.commit(); flash("Finding status updated.","success"); return redirect(url_for("main.finding_detail",fid=f.id))
@bp.route("/assessments/<int:aid>/report")
@login_required
def report(aid):
    a=owner_assessment(aid); response=make_response(build_report(a)); response.headers["Content-Type"]="application/pdf"; mode="inline" if request.args.get("inline")=="1" else "attachment"; response.headers["Content-Disposition"]=f'{mode}; filename="VulnAssess-{a.report_id[:8]}.pdf"'; return response
@bp.route("/assessments/<int:aid>/report/preview")
@login_required
def report_preview(aid):return render_template("report_preview.html",a=owner_assessment(aid))
@bp.route("/settings")
@login_required
def settings():return render_template("settings.html",allowlist=current_app.config["ALLOWED_TARGETS"])
@bp.route("/about")
@login_required
def about():return render_template("about.html")
