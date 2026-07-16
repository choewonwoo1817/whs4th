"""인증/인가/검증 공통 헬퍼."""
import re
import secrets
from functools import wraps

from flask import session, g, redirect, url_for, flash, abort
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# argon2: salt 자동 적용 강력 해시 (SR-01)
_ph = PasswordHasher()


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# 타이밍 기반 사용자 열거 방지용 더미 해시
_DUMMY_HASH = _ph.hash("timing-equalizer")


def equalize_timing(password: str) -> None:
    """사용자가 존재하지 않을 때도 argon2 검증을 수행해 응답 시간 차이를 없앤다."""
    try:
        _ph.verify(_DUMMY_HASH, password or "")
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        pass   # 더미 검증은 항상 불일치 → 시간만 소비하고 무시


def needs_rehash(password_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(password_hash)
    except Exception:
        return False


# --- 세션 재발급 (세션 고정 방지) ---
def regenerate_session():
    """서버측 세션 id를 새로 발급하고 이전 세션 데이터를 버린다 (session fixation 방지)."""
    session.clear()
    if hasattr(session, "sid"):        # Flask-Session(서버측 세션)일 때 sid 회전
        session.sid = secrets.token_urlsafe(32)
    session.modified = True


# --- 현재 사용자 ---
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    if g.get("_cached_uid") != uid:
        from .db import query_db
        g._cached_user = query_db("SELECT * FROM user WHERE id = ?", (uid,), one=True)
        g._cached_uid = uid
    u = g._cached_user
    if u is None:
        return None
    # 휴면 계정·무효화된(epoch 불일치) 세션은 로그아웃 상태로 취급
    if u["is_dormant"] or session.get("sv") != u["session_epoch"]:
        return None
    return u


# --- 데코레이터 ---
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        # current_user 가 휴면·무효화 세션을 None 으로 처리하는 단일 게이트
        if current_user() is None:
            session.clear()
            flash("로그인이 필요합니다.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:      # 미로그인·휴면·무효화 세션 모두 차단
            session.clear()
            flash("로그인이 필요합니다.", "warning")
            return redirect(url_for("auth.login"))
        if not user["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


# --- 서버 측 입력 검증 (SR-07). 클라이언트 검증에 의존하지 않는다. ---
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")


def validate_username(value: str):
    if not value or not USERNAME_RE.match(value):
        return "아이디는 영문/숫자/밑줄 3~20자여야 합니다."
    return None


def validate_password(value: str):
    if not value or len(value) < 8 or len(value) > 128:
        return "비밀번호는 8~128자여야 합니다."
    return None


def validate_text(value: str, field: str, max_len: int, min_len: int = 1):
    if value is None:
        value = ""
    value = value.strip()
    if len(value) < min_len:
        return f"{field}을(를) 입력하세요.", None
    if len(value) > max_len:
        return f"{field}은(는) 최대 {max_len}자입니다.", None
    return None, value


def validate_int(value, field: str, min_v=None, max_v=None):
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return f"{field}은(는) 정수여야 합니다.", None
    if min_v is not None and n < min_v:
        return f"{field}은(는) {min_v} 이상이어야 합니다.", None
    if max_v is not None and n > max_v:
        return f"{field}은(는) {max_v} 이하여야 합니다.", None
    return None, n
