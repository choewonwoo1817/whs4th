"""송금 블루프린트: 사용자 간 포인트 이체 (원자적 처리, SR-08)."""
import uuid

from flask import Blueprint, render_template, request, redirect, url_for, flash

from ..db import query_db, now_iso, transaction
from ..security import login_required, current_user, validate_int

bp = Blueprint("transfer", __name__)
MAX_AMOUNT = 1_000_000_000


class _Insufficient(Exception):
    pass


@bp.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    me = current_user()

    if request.method == "POST":
        to_username = request.form.get("to_username", "").strip()
        aerr, amount = validate_int(request.form.get("amount", ""), "송금 금액",
                                    min_v=1, max_v=MAX_AMOUNT)   # 음수/0 차단
        errors = []
        if aerr:
            errors.append(aerr)

        receiver = None
        if to_username:
            receiver = query_db("SELECT id, is_dormant FROM user WHERE username = ?",
                                (to_username,), one=True)
        if receiver is None:
            errors.append("받는 사람을 찾을 수 없습니다.")
        elif receiver["id"] == me["id"]:
            errors.append("자기 자신에게는 송금할 수 없습니다.")
        elif receiver["is_dormant"]:
            errors.append("휴면 계정에는 송금할 수 없습니다.")

        if errors:
            for m in errors:
                flash(m, "danger")
            return render_template("transfer/new.html", balance=me["balance"],
                                   to_username=to_username), 400

        try:
            with transaction() as db:
                # 조건부 UPDATE: 잔액이 충분할 때만 차감 (read-then-write 경쟁 조건 방지, SR-08)
                cur = db.execute(
                    "UPDATE user SET balance = balance - ? WHERE id = ? AND balance >= ?",
                    (amount, me["id"], amount),
                )
                if cur.rowcount != 1:
                    raise _Insufficient()
                db.execute("UPDATE user SET balance = balance + ? WHERE id = ?",
                           (amount, receiver["id"]))
                db.execute(
                    "INSERT INTO transfers (id, sender_id, receiver_id, amount, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), me["id"], receiver["id"], amount, now_iso()),
                )
        except _Insufficient:
            flash("잔액이 부족합니다.", "danger")
            return render_template("transfer/new.html", balance=me["balance"],
                                   to_username=to_username), 400

        flash(f"{amount}P를 송금했습니다.", "success")
        return redirect(url_for("users.mypage"))

    return render_template("transfer/new.html", balance=me["balance"], to_username="")
