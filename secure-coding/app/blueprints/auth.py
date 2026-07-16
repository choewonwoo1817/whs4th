"""인증 블루프린트: 회원가입 / 로그인 / 로그아웃."""
import sqlite3
import time
import uuid

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, session, current_app,
)

from .. import limiter
from ..db import query_db, execute_db, now_iso
from ..security import (
    hash_password, verify_password, needs_rehash, equalize_timing, regenerate_session,
    validate_username, validate_password, validate_text, current_user,
)

bp = Blueprint("auth", __name__)

# --- SR-15: 로그인 실패 점진 잠금 (in-memory, IP+아이디 기준) ---
_failed = {}
MAX_FAILED = 5
LOCK_WINDOW = 300  # 초


def _fail_key():
    return (request.remote_addr, request.form.get("username", ""))


def _lock_remaining():
    rec = _failed.get(_fail_key())
    if not rec:
        return 0
    count, first = rec
    if time.time() - first > LOCK_WINDOW:
        _failed.pop(_fail_key(), None)
        return 0
    if count >= MAX_FAILED:
        return int(LOCK_WINDOW - (time.time() - first))
    return 0


def _register_fail():
    now = time.time()
    if len(_failed) > 1000:      # 메모리 남용 방지: 만료 항목 정리
        for k, (_, ts) in list(_failed.items()):
            if now - ts > LOCK_WINDOW:
                _failed.pop(k, None)
    key = _fail_key()
    rec = _failed.get(key)
    if rec and now - rec[1] <= LOCK_WINDOW:
        _failed[key] = (rec[0] + 1, rec[1])
    else:
        _failed[key] = (1, now)


def _clear_fail():
    _failed.pop(_fail_key(), None)


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("main.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password_confirm", "")
        errors = []

        err = validate_username(username)
        if err:
            errors.append(err)
        derr, display_name = validate_text(request.form.get("display_name", ""), "계정명", 30)
        if derr:
            errors.append(derr)
        err = validate_password(password)
        if err:
            errors.append(err)
        if password != password2:
            errors.append("비밀번호 확인이 일치하지 않습니다.")
        if not errors and query_db("SELECT id FROM user WHERE username = ?", (username,), one=True):
            errors.append("이미 사용 중인 아이디입니다.")

        if errors:
            for m in errors:
                flash(m, "danger")
            return render_template("auth/register.html", username=username,
                                   display_name=request.form.get("display_name", "")), 400

        # 보안: is_admin·is_dormant 등 권한/상태 컬럼은 입력에서 받지 않는다 (mass-assignment 차단).
        # balance 도 사용자 입력이 아니라 서버 설정값(가입 보너스)으로만 지정한다.
        try:
            execute_db(
                "INSERT INTO user (id, username, display_name, password_hash, balance, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), username, display_name, hash_password(password),
                 current_app.config["REGISTER_BONUS"], now_iso()),
            )
        except sqlite3.IntegrityError:
            # 동시 가입 등으로 UNIQUE 충돌 시 500 대신 친절히 처리
            flash("이미 사용 중인 아이디입니다.", "danger")
            return render_template("auth/register.html", username=username,
                                   display_name=request.form.get("display_name", "")), 400
        flash("회원가입이 완료되었습니다. 로그인해 주세요.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if current_user():
        return redirect(url_for("main.index"))

    if request.method == "POST":
        wait = _lock_remaining()
        if wait > 0:
            flash(f"로그인 시도가 많습니다. 약 {wait}초 후 다시 시도하세요.", "danger")
            return render_template("auth/login.html"), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = query_db("SELECT * FROM user WHERE username = ?", (username,), one=True)

        # 사용자 존재 여부를 메시지·응답시간 양쪽으로 노출하지 않는다.
        if user is None:
            equalize_timing(password)   # 타이밍 기반 사용자 열거 방지
            _register_fail()
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "danger")
            return render_template("auth/login.html", username=username), 401
        if not verify_password(user["password_hash"], password):
            _register_fail()
            flash("아이디 또는 비밀번호가 올바르지 않습니다.", "danger")
            return render_template("auth/login.html", username=username), 401

        if user["is_dormant"]:
            flash("휴면 처리된 계정입니다. 관리자에게 문의하세요.", "danger")
            return render_template("auth/login.html", username=username), 403

        _clear_fail()
        # 세션 고정 방지: 로그인 성공 시 서버측 세션 id 회전 (SR-06)
        regenerate_session()
        session["user_id"] = user["id"]
        session["sv"] = user["session_epoch"]
        session.permanent = True

        # 해시 파라미터가 낡았으면 조용히 재해시
        if needs_rehash(user["password_hash"]):
            execute_db("UPDATE user SET password_hash = ? WHERE id = ?",
                       (hash_password(password), user["id"]))

        flash("로그인되었습니다.", "success")
        return redirect(url_for("main.index"))

    return render_template("auth/login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("로그아웃되었습니다.", "info")
    return redirect(url_for("main.index"))
