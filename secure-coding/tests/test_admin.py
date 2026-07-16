"""Step 8 관리자 — 권한 통제 (SR-11) + 관리 동작."""
import uuid

from app.db import query_db, execute_db, now_iso


def _make_product(app, seller_id, blocked=0):
    pid = str(uuid.uuid4())
    with app.app_context():
        execute_db(
            "INSERT INTO product (id, title, description, price, seller_id, is_blocked, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (pid, "상품", "설명", 1000, seller_id, blocked, now_iso()),
        )
    return pid


# --- 권한 ---
def test_admin_dashboard_ok(client, make_user, login):
    admin = make_user("admin", is_admin=1)
    login(admin)
    assert client.get("/admin/").status_code == 200


def test_non_admin_forbidden(client, make_user, login):
    user = make_user("normal", is_admin=0)
    login(user)
    assert client.get("/admin/").status_code == 403          # SR-11


def test_admin_requires_login(client):
    r = client.get("/admin/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_non_admin_cannot_delete_product(client, make_user, login, app):
    admin_free_seller = make_user("seller")
    attacker = make_user("attacker", is_admin=0)
    pid = _make_product(app, admin_free_seller)
    login(attacker)
    assert client.post(f"/admin/product/{pid}/delete").status_code == 403
    with app.app_context():
        assert query_db("SELECT id FROM product WHERE id = ?", (pid,), one=True) is not None


# --- 관리 동작 ---
def test_admin_delete_product(client, make_user, login, app):
    seller = make_user("seller")
    admin = make_user("admin", is_admin=1)
    pid = _make_product(app, seller)
    login(admin)
    assert client.post(f"/admin/product/{pid}/delete").status_code == 302
    with app.app_context():
        assert query_db("SELECT id FROM product WHERE id = ?", (pid,), one=True) is None


def test_admin_toggle_dormant(client, make_user, login, app):
    target = make_user("target")
    admin = make_user("admin", is_admin=1)
    login(admin)
    client.post(f"/admin/user/{target}/toggle_dormant")
    with app.app_context():
        assert query_db("SELECT is_dormant FROM user WHERE id = ?", (target,), one=True)["is_dormant"] == 1
    client.post(f"/admin/user/{target}/toggle_dormant")   # 복구
    with app.app_context():
        u = query_db("SELECT is_dormant, report_count FROM user WHERE id = ?", (target,), one=True)
    assert u["is_dormant"] == 0 and u["report_count"] == 0


def test_admin_unblock_product(client, make_user, login, app):
    seller = make_user("seller")
    admin = make_user("admin", is_admin=1)
    pid = _make_product(app, seller, blocked=1)
    login(admin)
    client.post(f"/admin/product/{pid}/unblock")
    with app.app_context():
        p = query_db("SELECT is_blocked, report_count FROM product WHERE id = ?", (pid,), one=True)
    assert p["is_blocked"] == 0 and p["report_count"] == 0


def test_admin_cannot_dormant_self(client, make_user, login, app):
    admin = make_user("admin", is_admin=1)
    login(admin)
    client.post(f"/admin/user/{admin}/toggle_dormant")
    with app.app_context():
        assert query_db("SELECT is_dormant FROM user WHERE id = ?", (admin,), one=True)["is_dormant"] == 0
