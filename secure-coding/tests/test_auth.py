"""Step 2 인증 — 정상 + 공격 케이스."""
from app.db import query_db

REG = "/register"
LOGIN = "/login"


def _reg_data(**over):
    d = {"username": "carol", "display_name": "캐롤",
         "password": "password123", "password_confirm": "password123"}
    d.update(over)
    return d


# --- 정상 ---
def test_register_success_and_password_hashed(client, app):
    r = client.post(REG, data=_reg_data(), follow_redirects=False)
    assert r.status_code == 302
    with app.app_context():
        u = query_db("SELECT * FROM user WHERE username = ?", ("carol",), one=True)
    assert u is not None
    # SR-01: 평문 저장 금지, argon2 해시
    assert u["password_hash"].startswith("$argon2")
    assert "password123" not in u["password_hash"]


def test_login_success_sets_session(client, make_user):
    make_user("alice", "password123")
    r = client.post(LOGIN, data={"username": "alice", "password": "password123"})
    assert r.status_code == 302
    with client.session_transaction() as s:
        assert "user_id" in s


def test_login_rotates_session_cookie(client, make_user):
    # 세션 고정 방지: 로그인 후 세션 쿠키(sid)가 로그인 전과 달라야 함
    make_user("v", "password123")
    client.get("/login")
    before = client.get_cookie("session")
    before_val = before.value if before else None
    client.post(LOGIN, data={"username": "v", "password": "password123"})
    after = client.get_cookie("session")
    after_val = after.value if after else None
    assert after_val is not None
    assert after_val != before_val


def test_logout_clears_session(client, make_user):
    # 로그아웃 시 세션 무효화 → 이후 보호 페이지 접근 불가
    uid = make_user("v", "password123")
    client.post(LOGIN, data={"username": "v", "password": "password123"})
    client.post("/logout")
    r = client.get("/mypage")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_logout_clears_session_legacy(client, make_user, login):
    uid = make_user("alice")
    login(uid)
    r = client.post("/logout")
    assert r.status_code == 302
    with client.session_transaction() as s:
        assert "user_id" not in s


# --- 공격/오용 ---
def test_register_ignores_privilege_fields(client, app):
    # mass-assignment: is_admin/balance 를 폼으로 주입해도 무시되어야 함
    client.post(REG, data=_reg_data(username="eve", is_admin="1", balance="999999"),
                follow_redirects=True)
    with app.app_context():
        u = query_db("SELECT is_admin, balance FROM user WHERE username = ?", ("eve",), one=True)
    assert u["is_admin"] == 0
    assert u["balance"] == 0


def test_register_duplicate_username_rejected(client, make_user, app):
    make_user("dup")
    r = client.post(REG, data=_reg_data(username="dup"))
    assert r.status_code == 400
    with app.app_context():
        n = query_db("SELECT COUNT(*) c FROM user WHERE username = ?", ("dup",), one=True)["c"]
    assert n == 1


def test_register_weak_password_rejected(client, app):
    r = client.post(REG, data=_reg_data(username="weaky", password="123", password_confirm="123"))
    assert r.status_code == 400
    with app.app_context():
        assert query_db("SELECT id FROM user WHERE username = ?", ("weaky",), one=True) is None


def test_login_wrong_password_rejected(client, make_user):
    make_user("alice", "password123")
    r = client.post(LOGIN, data={"username": "alice", "password": "WRONG"})
    assert r.status_code == 401
    with client.session_transaction() as s:
        assert "user_id" not in s


def test_login_sql_injection_blocked(client, make_user):
    # SR-02: 파라미터 바인딩으로 인증 우회 불가
    make_user("bob", "secret123")
    r = client.post(LOGIN, data={"username": "' OR '1'='1'--", "password": "x"})
    assert r.status_code == 401
    with client.session_transaction() as s:
        assert "user_id" not in s


def test_password_change_invalidates_old_sessions(client, make_user, login, app):
    # 비번 변경(epoch 증가) 시 다른 기기에 남은 옛 세션은 무효화되어야 함
    uid = make_user("v", "password123")
    login(uid, sv=0)                       # 옛 세션(epoch 0)
    with app.app_context():
        from app.db import execute_db
        execute_db("UPDATE user SET session_epoch = 1 WHERE id = ?", (uid,))
    r = client.get("/mypage")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_login_timing_enumeration_mitigated(client, make_user):
    # 존재하지 않는 아이디도 argon2 검증을 거쳐 응답 시간 차가 크지 않아야 함
    import time
    make_user("realuser", "password123")
    t0 = time.perf_counter()
    client.post(LOGIN, data={"username": "realuser", "password": "wrongpw"})
    exists = time.perf_counter() - t0
    t1 = time.perf_counter()
    client.post(LOGIN, data={"username": "no_such_user_xyz", "password": "wrongpw"})
    missing = time.perf_counter() - t1
    # 두 경로 모두 argon2를 수행 → 비율이 극단적이지 않음(열거 어려움)
    ratio = max(exists, missing) / max(min(exists, missing), 1e-6)
    assert ratio < 5, f"타이밍 차 과다 (exists={exists:.4f}, missing={missing:.4f})"


def test_dormant_user_cannot_login(client, make_user, app):
    uid = make_user("zzz", "password123")
    with app.app_context():
        from app.db import execute_db
        execute_db("UPDATE user SET is_dormant = 1 WHERE id = ?", (uid,))
    r = client.post(LOGIN, data={"username": "zzz", "password": "password123"})
    assert r.status_code == 403
    with client.session_transaction() as s:
        assert "user_id" not in s
