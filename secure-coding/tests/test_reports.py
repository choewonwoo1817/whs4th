"""Step 6 신고·임계치 — 정상 + 자기/중복 신고 차단, 임계치 자동 처리."""
import uuid

from app.db import query_db, execute_db, now_iso


def _make_product(app, seller_id, title="가방", blocked=0):
    pid = str(uuid.uuid4())
    with app.app_context():
        execute_db(
            "INSERT INTO product (id, title, description, price, seller_id, is_blocked, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (pid, title, "설명", 1000, seller_id, blocked, now_iso()),
        )
    return pid


def _report(client, target_type, target_id, reason="불량합니다"):
    return client.post("/report", data={"target_type": target_type,
                                         "target_id": target_id, "reason": reason})


# --- 정상 ---
def test_report_product_increments_count(client, make_user, login, app):
    seller = make_user("seller")
    reporter = make_user("reporter")
    pid = _make_product(app, seller)
    login(reporter)
    assert _report(client, "product", pid).status_code == 302
    with app.app_context():
        p = query_db("SELECT report_count FROM product WHERE id = ?", (pid,), one=True)
    assert p["report_count"] == 1


def test_product_blocked_after_threshold(client, make_user, login, app):
    # 테스트 설정 REPORT_THRESHOLD = 3
    seller = make_user("seller")
    pid = _make_product(app, seller)
    for i in range(3):
        login(make_user(f"rep{i}"))
        _report(client, "product", pid)
    with app.app_context():
        p = query_db("SELECT report_count, is_blocked FROM product WHERE id = ?", (pid,), one=True)
    assert p["report_count"] == 3 and p["is_blocked"] == 1


def test_user_dormant_after_threshold(client, make_user, login, app):
    victim = make_user("victim")
    for i in range(3):
        login(make_user(f"rep{i}"))
        _report(client, "user", victim)
    with app.app_context():
        u = query_db("SELECT report_count, is_dormant FROM user WHERE id = ?", (victim,), one=True)
    assert u["report_count"] == 3 and u["is_dormant"] == 1


# --- 공격/오용 ---
def test_self_report_user_rejected(client, make_user, login, app):
    uid = make_user("alice")
    login(uid)
    r = _report(client, "user", uid)
    assert r.status_code == 400
    with app.app_context():
        u = query_db("SELECT report_count FROM user WHERE id = ?", (uid,), one=True)
    assert u["report_count"] == 0


def test_report_own_product_rejected(client, make_user, login, app):
    uid = make_user("alice")
    pid = _make_product(app, uid)
    login(uid)
    assert _report(client, "product", pid).status_code == 400


def test_duplicate_report_rejected(client, make_user, login, app):
    seller = make_user("seller")
    reporter = make_user("reporter")
    pid = _make_product(app, seller)
    login(reporter)
    _report(client, "product", pid)
    _report(client, "product", pid)   # 같은 신고자 재신고
    with app.app_context():
        p = query_db("SELECT report_count FROM product WHERE id = ?", (pid,), one=True)
    assert p["report_count"] == 1     # 중복은 카운트되지 않음


def test_report_requires_login(client, make_user, app):
    seller = make_user("seller")
    pid = _make_product(app, seller)
    r = _report(client, "product", pid)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_report_empty_reason_rejected(client, make_user, login, app):
    seller = make_user("seller")
    reporter = make_user("reporter")
    pid = _make_product(app, seller)
    login(reporter)
    r = client.post("/report", data={"target_type": "product", "target_id": pid, "reason": ""})
    assert r.status_code == 400


def test_admin_not_auto_dormant_by_reports(client, make_user, login, app):
    # 담합 신고로 관리자 계정을 휴면 잠그는 DoS 방어
    admin = make_user("admin_target", is_admin=1)
    for i in range(3):   # 테스트 임계치 3
        login(make_user(f"rep{i}"))
        _report(client, "user", admin)
    with app.app_context():
        u = query_db("SELECT is_dormant, report_count FROM user WHERE id = ?", (admin,), one=True)
    assert u["is_dormant"] == 0        # 관리자는 자동 휴면되지 않음
    assert u["report_count"] == 3      # 신고 기록은 남음


def test_dormant_user_cannot_login_after_reports(client, make_user, login, app):
    victim = make_user("victim", "password123")
    for i in range(3):
        login(make_user(f"rep{i}"))
        _report(client, "user", victim)
    # 새 클라이언트 세션으로 로그인 시도
    with client.session_transaction() as s:
        s.clear()
    r = client.post("/login", data={"username": "victim", "password": "password123"})
    assert r.status_code == 403
