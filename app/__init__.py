"""VulnAssess Flask application factory."""
import os
from pathlib import Path
from flask import Flask
from .extensions import db, migrate, csrf, limiter
def create_app(test_config=None):
    app=Flask(__name__,instance_relative_config=True)
    app.config.from_mapping(SECRET_KEY=os.getenv("SECRET_KEY") or os.urandom(32),SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL","sqlite:///vulnassess.db"),SQLALCHEMY_TRACK_MODIFICATIONS=False,ALLOWED_TARGETS=os.getenv("ALLOWED_TARGETS","127.0.0.1,::1,localhost"),NMAP_PATH=os.getenv("NMAP_PATH","nmap"),PORTS=os.getenv("PORTS","21,22,23,80,139,443,445,3306,3389,5432,8080,8443,27017"),MAX_SCAN_SECONDS=int(os.getenv("MAX_SCAN_SECONDS","90")),SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE","0")=="1",WTF_CSRF_TIME_LIMIT=3600)
    if test_config: app.config.update(test_config)
    Path(app.instance_path).mkdir(parents=True,exist_ok=True)
    db.init_app(app); migrate.init_app(app,db); csrf.init_app(app); limiter.init_app(app)
    from . import models
    from .routes import bp
    app.register_blueprint(bp)
    from .errors import register_errors
    register_errors(app)
    return app
