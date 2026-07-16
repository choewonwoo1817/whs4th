"""횡단 보안 통제 — 보안 헤더(SR-09), 세션 쿠키 플래그(SR-06), CSRF(SR-04)."""
import os
import re
import tempfile

from app import create_app
from app.db import init_db


# --- 보안 헤더 / 세션 쿠키 (기본 client 픽스처는 CSRF 비활성) ---
def test_security_headers_present(client):
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer"
    assert "Content-Security-Policy" in r.headers


def test_session_cookie_httponly_samesite(client, make_user):
    make_user("alice", "password123")
    r = client.post("/login", data={"username": "alice", "password": "password123"})
    cookies = r.headers.getlist("Set-Cookie")
    assert any("HttpOnly" in c for c in cookies)
    assert any("SameSite=Lax" in c for c in cookies)


# --- CSRF 강제 (전용 앱: WTF_CSRF_ENABLED=True) ---
def _csrf_app():
    fd, db_path = tempfile.mkstemp(suffix=".db")
    sess_dir = tempfile.mkdtemp()
    app = create_app(overrides={
        "TESTING": True, "DEBUG": True, "SECRET_KEY": "csrf-test",
        "DATABASE": db_path, "SESSION_FILE_DIR": sess_dir,
        "WTF_CSRF_ENABLED": True, "RATELIMIT_ENABLED": False, "REGISTER_BONUS": 0,
    })
    init_db(app)
    return app, fd, db_path


def test_post_without_csrf_token_rejected():
    app, fd, db_path = _csrf_app()
    try:
        c = app.test_client()
        r = c.post("/register", data={"username": "eve", "display_name": "이브",
                                      "password": "password123", "password_confirm": "password123"})
        assert r.status_code == 400          # CSRF 토큰 없음 → 차단
    finally:
        os.close(fd); os.unlink(db_path)


def test_post_with_csrf_token_accepted():
    app, fd, db_path = _csrf_app()
    try:
        c = app.test_client()
        html = c.get("/register").get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        r = c.post("/register", data={"csrf_token": token, "username": "newbie",
                                      "display_name": "뉴비", "password": "password123",
                                      "password_confirm": "password123"})
        assert r.status_code == 302          # 정상 토큰 → 가입 성공
    finally:
        os.close(fd); os.unlink(db_path)
