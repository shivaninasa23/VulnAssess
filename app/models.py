from datetime import datetime,timezone
from werkzeug.security import generate_password_hash,check_password_hash
from .extensions import db
class User(db.Model):
    id=db.Column(db.Integer,primary_key=True); username=db.Column(db.String(80),unique=True,nullable=False,index=True); password_hash=db.Column(db.String(255),nullable=False); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc),nullable=False)
    def set_password(self,password): self.password_hash=generate_password_hash(password,method="scrypt")
    def check_password(self,password): return check_password_hash(self.password_hash,password)
class Assessment(db.Model):
    id=db.Column(db.Integer,primary_key=True); report_id=db.Column(db.String(36),unique=True,nullable=False,index=True); target=db.Column(db.String(253),nullable=False); assessment_type=db.Column(db.String(30),nullable=False); status=db.Column(db.String(20),nullable=False,default="queued",index=True); started_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc),nullable=False); ended_at=db.Column(db.DateTime); error=db.Column(db.String(300)); owner_id=db.Column(db.Integer,db.ForeignKey("user.id"),nullable=False,index=True)
    services=db.relationship("Service",cascade="all, delete-orphan",backref="assessment"); findings=db.relationship("Finding",cascade="all, delete-orphan",backref="assessment")
class Service(db.Model):
    id=db.Column(db.Integer,primary_key=True); assessment_id=db.Column(db.Integer,db.ForeignKey("assessment.id"),nullable=False,index=True); host=db.Column(db.String(253),nullable=False); port=db.Column(db.Integer,nullable=False); protocol=db.Column(db.String(8),nullable=False,default="tcp"); service_name=db.Column(db.String(80)); product=db.Column(db.String(120)); version=db.Column(db.String(80))
class Finding(db.Model):
    id=db.Column(db.Integer,primary_key=True); finding_uid=db.Column(db.String(36),unique=True,nullable=False,index=True); assessment_id=db.Column(db.Integer,db.ForeignKey("assessment.id"),nullable=False,index=True); check_name=db.Column(db.String(120),nullable=False); severity=db.Column(db.String(20),nullable=False,index=True); confidence=db.Column(db.String(30),nullable=False,default="moderate"); rationale=db.Column(db.Text,nullable=False); evidence=db.Column(db.Text,nullable=False); expected=db.Column(db.Text,nullable=False); impact=db.Column(db.Text,nullable=False); remediation=db.Column(db.Text,nullable=False); status=db.Column(db.String(30),nullable=False,default="open",index=True); created_at=db.Column(db.DateTime,default=lambda:datetime.now(timezone.utc),nullable=False)
