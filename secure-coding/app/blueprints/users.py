"""사용자 블루프린트: 프로필 조회 / 마이페이지(소개글·비밀번호 변경)."""
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session

from ..db import query_db, execute_db
from ..security import (
    login_required, current_user, verify_password, hash_password,
    validate_password, validate_text, regenerate_session,
)

bp = Blueprint("users", __name__)


@bp.route("/users/<id>")
def profile(id):
    u = query_db(
        "SELECT id, username, display_name, bio, created_at FROM user WHERE id = ?",
        (id,), one=True,
    )
    if u is None:
        abort(404)
    products = query_db(
        "SELECT id, title, price FROM product WHERE seller_id = ? AND is_blocked = 0 "
        "ORDER BY created_at DESC LIMIT 50",
        (id,),
    )
    return render_template("users/profile.html", u=u, products=products)


@bp.route("/mypage", methods=["GET", "POST"])
@login_required
def mypage():
    # 세션의 본인 레코드에만 작용 → 타인 자원 변경 불가 (SR-05)
    user = current_user()
    if request.method == "POST":
        action = request.form.get("action")

        if action == "bio":
            err, bio = validate_text(request.form.get("bio", ""), "소개글", 500, min_len=0)
            if err:
                flash(err, "danger")
            else:
                execute_db("UPDATE user SET bio = ? WHERE id = ?", (bio, user["id"]))
                flash("소개글이 수정되었습니다.", "success")
            return redirect(url_for("users.mypage"))

        if action == "password":
            current_pw = request.form.get("current_password", "")
            new_pw = request.form.get("new_password", "")
            new_pw2 = request.form.get("new_password_confirm", "")
            pw_err = validate_password(new_pw)
            if not verify_password(user["password_hash"], current_pw):
                flash("현재 비밀번호가 올바르지 않습니다.", "danger")   # 재인증 요구
            elif pw_err:
                flash(pw_err, "danger")
            elif new_pw != new_pw2:
                flash("새 비밀번호 확인이 일치하지 않습니다.", "danger")
            else:
                # epoch 증가 → 다른 기기에 남은 기존 세션 전부 무효화
                new_epoch = user["session_epoch"] + 1
                execute_db("UPDATE user SET password_hash = ?, session_epoch = ? WHERE id = ?",
                           (hash_password(new_pw), new_epoch, user["id"]))
                # 현재 세션은 sid 재발급 후 새 epoch 로 재설정 (로그인 유지)
                uid = user["id"]
                regenerate_session()
                session["user_id"] = uid
                session["sv"] = new_epoch
                session.permanent = True
                flash("비밀번호가 변경되었습니다.", "success")
            return redirect(url_for("users.mypage"))

    my_products = query_db(
        "SELECT id, title, price, is_blocked FROM product WHERE seller_id = ? "
        "ORDER BY created_at DESC",
        (user["id"],),
    )
    return render_template("users/mypage.html", user=user, products=my_products)
