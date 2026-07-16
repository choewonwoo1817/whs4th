"""채팅 블루프린트: 전체 채팅 + 1:1 채팅 (HTTP 페이지 + SocketIO 이벤트)."""
import time
import uuid

from flask import Blueprint, render_template, session, abort

from .. import socketio
from ..db import query_db, execute_db, now_iso
from ..security import login_required, current_user
from flask_socketio import join_room, emit

bp = Blueprint("chat", __name__)

MAX_LEN = 500
# 앱 수준 rate limit (Flask-Limiter는 소켓 이벤트에 미적용, SR-10)
RATE_MAX = 5
RATE_WINDOW = 5.0
_recent = {}   # user_id -> [timestamps]


def _rate_ok(uid):
    now = time.time()
    times = [t for t in _recent.get(uid, []) if now - t < RATE_WINDOW]
    if len(times) >= RATE_MAX:
        _recent[uid] = times
        return False
    times.append(now)
    _recent[uid] = times
    return True


# ---------- HTTP 페이지 ----------
@bp.route("/chat")
@login_required
def global_chat():
    messages = query_db(
        "SELECT m.content, m.created_at, u.display_name "
        "FROM message m JOIN user u ON m.sender_id = u.id "
        "WHERE m.receiver_id IS NULL ORDER BY m.created_at DESC LIMIT 50"
    )
    return render_template("chat/global.html", messages=list(reversed(messages)))


@bp.route("/chats")
@login_required
def inbox():
    """내 1:1 대화 목록 (구매자·판매자가 서로 대화를 찾아 이어가는 곳)."""
    me = current_user()
    conversations = query_db(
        "SELECT u.id AS partner_id, u.display_name, MAX(t.created_at) AS last_at "
        "FROM ("
        "  SELECT receiver_id AS pid, created_at FROM message "
        "  WHERE sender_id = ? AND receiver_id IS NOT NULL "
        "  UNION ALL "
        "  SELECT sender_id AS pid, created_at FROM message WHERE receiver_id = ? "
        ") t JOIN user u ON u.id = t.pid "
        "GROUP BY u.id, u.display_name ORDER BY last_at DESC",
        (me["id"], me["id"]),
    )
    return render_template("chat/inbox.html", conversations=conversations)


@bp.route("/chat/<user_id>")
@login_required
def private_chat(user_id):
    me = current_user()
    other = query_db("SELECT id, display_name FROM user WHERE id = ?", (user_id,), one=True)
    if other is None or other["id"] == me["id"]:
        abort(404)
    # SR-05: 본인이 참여한 대화만 조회 (URL로 타인 대화 열람 차단)
    messages = query_db(
        "SELECT content, created_at, sender_id FROM message "
        "WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?) "
        "ORDER BY created_at ASC LIMIT 100",
        (me["id"], user_id, user_id, me["id"]),
    )
    return render_template("chat/private.html", other=other, messages=messages, me=me)


# ---------- SocketIO 이벤트 ----------
def _active_user(uid):
    """존재하며 휴면이 아닌 사용자만 반환 (소켓 계층 인가, SR-11/제재 우회 방지)."""
    u = query_db("SELECT display_name, is_dormant FROM user WHERE id = ?", (uid,), one=True)
    if u is None or u["is_dormant"]:
        return None
    return u


@socketio.on("connect")
def on_connect():
    uid = session.get("user_id")
    if not uid or _active_user(uid) is None:
        return False              # 미인증·휴면 연결 거부
    join_room(uid)                # 1:1 라우팅용 개인 방


@socketio.on("global_message")
def on_global_message(data):
    uid = session.get("user_id")
    if not uid:
        return
    content = (data or {}).get("content", "").strip()
    if not content or len(content) > MAX_LEN:
        return
    user = _active_user(uid)
    if not user:
        return
    if not _rate_ok(uid):
        emit("error_message", {"error": "메시지를 너무 빠르게 보냅니다."})
        return
    execute_db(
        "INSERT INTO message (id, sender_id, receiver_id, content, created_at) VALUES (?, ?, NULL, ?, ?)",
        (str(uuid.uuid4()), uid, content, now_iso()),
    )
    # content 는 클라이언트에서 textContent 로 삽입되어 XSS 방지 (SR-03)
    emit("global_message", {"sender": user["display_name"], "content": content}, broadcast=True)


@socketio.on("private_message")
def on_private_message(data):
    uid = session.get("user_id")
    if not uid:
        return
    data = data or {}
    to = data.get("to", "")
    content = data.get("content", "").strip()
    if not content or len(content) > MAX_LEN:
        return
    user = _active_user(uid)
    if not user:
        return
    target = query_db("SELECT id FROM user WHERE id = ?", (to,), one=True)
    if not target or target["id"] == uid:
        return
    if not _rate_ok(uid):
        emit("error_message", {"error": "메시지를 너무 빠르게 보냅니다."})
        return
    execute_db(
        "INSERT INTO message (id, sender_id, receiver_id, content, created_at) VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), uid, to, content, now_iso()),
    )
    payload = {"sender": user["display_name"], "sender_id": uid, "content": content}
    emit("private_message", payload, room=to)     # 수신자에게만
    emit("private_message", payload, room=uid)     # 발신자 본인에게만
