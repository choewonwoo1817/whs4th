"""pytest 공통 픽스처.

주의: Flask-SocketIO 의 전역 서버는 프로세스에서 하나만 존재하므로,
앱을 테스트마다 새로 만들면 소켓 핸들러가 엉뚱한(이미 삭제된) 앱/DB 컨텍스트를
바라보게 된다. 따라서 앱은 세션 스코프로 1개만 만들고, 각 테스트 전에 DB를 비운다.
(실제 서비스도 단일 앱이므로 이 구조가 운영과 동일하다.)
"""
import os
import tempfile
import uuid

import pytest

from app import create_app
from app.db import init_db, get_db
from app.blueprints import chat as chat_mod
from app.blueprints import auth as auth_mod

_TABLES = ["report", "transfers", "message", "product", "user"]  # FK 자식 → 부모 순


@pytest.fixture(scope="session")
def _app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    sess_dir = tempfile.mkdtemp()
    upload_dir = tempfile.mkdtemp()
    application = create_app(overrides={
        "TESTING": True,
        "DEBUG": True,
        "SECRET_KEY": "test-secret-key",
        "DATABASE": db_path,
        "SESSION_FILE_DIR": sess_dir,
        "UPLOAD_DIR": upload_dir,     # 테스트 업로드는 임시 디렉터리로 격리
        "WTF_CSRF_ENABLED": False,
        "RATELIMIT_ENABLED": False,
        "REPORT_THRESHOLD": 3,
        "REGISTER_BONUS": 0,   # 테스트는 잔액 0에서 시작 (mass-assignment 테스트 안정)
    })
    init_db(application)
    yield application
    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def app(_app):
    # 각 테스트 시작 전 상태 초기화 (DB + 인메모리 throttle)
    with _app.app_context():
        db = get_db()
        for t in _TABLES:
            db.execute(f"DELETE FROM {t}")
    chat_mod._recent.clear()
    auth_mod._failed.clear()
    return _app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_user(app):
    from app.db import execute_db, now_iso
    from app.security import hash_password

    def _make(username="alice", password="password123", display="앨리스",
              is_admin=0, balance=0):
        uid = str(uuid.uuid4())
        with app.app_context():
            execute_db(
                "INSERT INTO user (id, username, display_name, password_hash, is_admin, balance, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (uid, username, display, hash_password(password), is_admin, balance, now_iso()),
            )
        return uid

    return _make


@pytest.fixture
def login(client):
    def _login(uid, sv=0):
        with client.session_transaction() as sess:
            sess["user_id"] = uid
            sess["sv"] = sv          # 세션 무효화 게이트(epoch)와 일치시킴
    return _login
