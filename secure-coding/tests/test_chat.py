"""Step 5 채팅 — SocketIO 정상 + 인증/길이/rate limit/IDOR/XSS."""
import uuid

from app import socketio
from app.db import execute_db, now_iso


def _mkmsg(app, sender, receiver, content):
    with app.app_context():
        execute_db(
            "INSERT INTO message (id, sender_id, receiver_id, content, created_at) VALUES (?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), sender, receiver, content, now_iso()),
        )


def _sio(app, client, uid=None):
    if uid:
        with client.session_transaction() as s:
            s["user_id"] = uid
    return socketio.test_client(app, flask_test_client=client)


# --- 인증 ---
def test_unauth_socket_connect_rejected(app, client):
    sio = socketio.test_client(app, flask_test_client=client)
    assert not sio.is_connected()


def test_auth_socket_connect_ok(app, client, make_user):
    sio = _sio(app, client, make_user("alice"))
    assert sio.is_connected()


def test_dormant_user_socket_rejected(app, client, make_user):
    # 휴면 처리된 사용자는 소켓 연결도 거부되어야 함 (제재 우회 방지)
    uid = make_user("d")
    with app.app_context():
        execute_db("UPDATE user SET is_dormant = 1 WHERE id = ?", (uid,))
    sio = _sio(app, client, uid)
    assert not sio.is_connected()


# --- 전체 채팅 ---
def test_global_message_broadcast(app, client, make_user):
    sio = _sio(app, client, make_user("alice"))
    sio.emit("global_message", {"content": "hello"})
    got = sio.get_received()
    assert any(r["name"] == "global_message" and r["args"][0]["content"] == "hello" for r in got)


def test_message_length_limit(app, client, make_user):
    sio = _sio(app, client, make_user("alice"))
    sio.emit("global_message", {"content": "x" * 600})
    assert not any(r["name"] == "global_message" for r in sio.get_received())


def test_chat_rate_limit(app, client, make_user):
    sio = _sio(app, client, make_user("alice"))
    for i in range(7):
        sio.emit("global_message", {"content": f"m{i}"})
    got = sio.get_received()
    assert any(r["name"] == "error_message" for r in got)   # 초과분 차단 (SR-10)


def test_chat_history_escaped(app, client, make_user, login):
    uid = make_user("alice")
    _mkmsg(app, uid, None, "<script>alert(1)</script>")
    login(uid)
    html = client.get("/chat").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# --- 1:1 채팅 ---
def test_global_chat_requires_login(client):
    assert client.get("/chat").status_code == 302


def test_private_chat_requires_login(client, make_user):
    assert client.get(f"/chat/{make_user('bob')}").status_code == 302


def test_private_chat_self_404(client, make_user, login):
    a = make_user("alice")
    login(a)
    assert client.get(f"/chat/{a}").status_code == 404


def test_inbox_lists_conversations(app, client, make_user, login):
    # 구매자↔판매자가 서로 대화를 찾을 수 있어야 함
    seller = make_user("seller")
    buyer = make_user("buyer")
    _mkmsg(app, buyer, seller, "이 상품 살게요")   # buyer → seller
    # 판매자 관점: 받은 대화 목록에 buyer가 보여야 함
    login(seller)
    html = client.get("/chats").get_data(as_text=True)
    assert f"/chat/{buyer}" in html
    # 구매자 관점: 보낸 대화 목록에 seller가 보여야 함
    with client.session_transaction() as s:
        s["user_id"] = buyer
    html2 = client.get("/chats").get_data(as_text=True)
    assert f"/chat/{seller}" in html2


def test_inbox_requires_login(client):
    r = client.get("/chats")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_private_chat_idor_blocked(app, client, make_user, login):
    a = make_user("alice")
    b = make_user("bob")
    c = make_user("carol")
    _mkmsg(app, b, c, "secret-bc")   # B<->C 대화
    _mkmsg(app, a, b, "hi-ab")       # A<->B 대화
    login(a)
    html = client.get(f"/chat/{b}").get_data(as_text=True)
    assert "hi-ab" in html
    assert "secret-bc" not in html   # 타인 대화 열람 불가 (SR-05)
