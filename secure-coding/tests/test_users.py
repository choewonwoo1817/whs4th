"""Step 4 마이페이지·프로필 — 정상 + 공격."""
from app.db import query_db
from app.security import verify_password


# --- 정상 ---
def test_profile_view(client, make_user):
    uid = make_user("alice")
    assert client.get(f"/users/{uid}").status_code == 200


def test_profile_unknown_404(client):
    assert client.get("/users/nope").status_code == 404


def test_update_bio(client, make_user, login, app):
    uid = make_user("alice")
    login(uid)
    client.post("/mypage", data={"action": "bio", "bio": "안녕하세요"})
    with app.app_context():
        u = query_db("SELECT bio FROM user WHERE id = ?", (uid,), one=True)
    assert u["bio"] == "안녕하세요"


def test_change_password_success(client, make_user, login, app):
    uid = make_user("alice", "password123")
    login(uid)
    client.post("/mypage", data={
        "action": "password", "current_password": "password123",
        "new_password": "newpassword456", "new_password_confirm": "newpassword456",
    })
    with app.app_context():
        u = query_db("SELECT password_hash FROM user WHERE id = ?", (uid,), one=True)
    assert verify_password(u["password_hash"], "newpassword456")
    assert not verify_password(u["password_hash"], "password123")


# --- 공격 ---
def test_change_password_wrong_current_rejected(client, make_user, login, app):
    uid = make_user("alice", "password123")
    login(uid)
    client.post("/mypage", data={
        "action": "password", "current_password": "WRONG",
        "new_password": "newpassword456", "new_password_confirm": "newpassword456",
    })
    with app.app_context():
        u = query_db("SELECT password_hash FROM user WHERE id = ?", (uid,), one=True)
    # 현재 비번 검증 실패 → 변경되지 않아야 함
    assert verify_password(u["password_hash"], "password123")


def test_mypage_requires_login(client):
    r = client.get("/mypage")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_bio_xss_escaped(client, make_user, login):
    uid = make_user("alice")
    login(uid)
    client.post("/mypage", data={"action": "bio", "bio": "<script>alert(1)</script>"})
    html = client.get(f"/users/{uid}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_cannot_edit_other_users_bio(client, make_user, login, app):
    # 마이페이지는 세션 본인에게만 작용 → B로 로그인해도 A의 소개글은 불변
    a = make_user("alice")
    b = make_user("bob")
    login(b)
    client.post("/mypage", data={"action": "bio", "bio": "bob-bio"})
    with app.app_context():
        a_bio = query_db("SELECT bio FROM user WHERE id = ?", (a,), one=True)["bio"]
        b_bio = query_db("SELECT bio FROM user WHERE id = ?", (b,), one=True)["bio"]
    assert a_bio == ""          # A 는 영향 없음
    assert b_bio == "bob-bio"
