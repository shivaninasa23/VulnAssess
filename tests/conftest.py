import pytest
from app import create_app
from app.extensions import db
from app.models import User
@pytest.fixture
def app():
    app=create_app({"TESTING":True,"SECRET_KEY":"test-secret","SQLALCHEMY_DATABASE_URI":"sqlite:///:memory:","WTF_CSRF_ENABLED":False,"RATELIMIT_ENABLED":False,"ALLOWED_TARGETS":"127.0.0.1,::1,localhost"})
    with app.app_context():
        db.create_all(); user=User(username="tester"); user.set_password("correct-horse-battery-staple"); db.session.add(user); db.session.commit()
    yield app
    with app.app_context():db.drop_all()
@pytest.fixture
def client(app):return app.test_client()
