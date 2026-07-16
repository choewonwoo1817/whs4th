"""신고 블루프린트: 유저/상품 신고 + 임계치 자동 처리."""
import sqlite3
import uuid

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, current_app,
)

from ..db import query_db, now_iso, transaction
from ..security import login_required, current_user, validate_text

bp = Blueprint("reports", __name__)


def _apply_threshold(db, target_type, target_id, threshold):
    """피신고 카운트를 원자적으로 올리고, 임계치 도달 시 차단/휴면 처리."""
    if target_type == "product":
        db.execute("UPDATE product SET report_count = report_count + 1 WHERE id = ?", (target_id,))
        cnt = db.execute("SELECT report_count FROM product WHERE id = ?", (target_id,)).fetchone()[0]
        if cnt >= threshold:
            db.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (target_id,))
    else:
        db.execute("UPDATE user SET report_count = report_count + 1 WHERE id = ?", (target_id,))
        row = db.execute("SELECT report_count, is_admin FROM user WHERE id = ?", (target_id,)).fetchone()
        # 관리자 계정은 담합 신고로 인한 자동 휴면(DoS)에서 제외한다.
        if row["report_count"] >= threshold and not row["is_admin"]:
            db.execute("UPDATE user SET is_dormant = 1 WHERE id = ?", (target_id,))


@bp.route("/report", methods=["GET", "POST"])
@login_required
def new():
    me = current_user()

    if request.method == "POST":
        target_type = request.form.get("target_type", "")
        target_id = request.form.get("target_id", "")
        rerr, reason = validate_text(request.form.get("reason", ""), "신고 사유", 500)

        errors = []
        if target_type not in ("user", "product"):
            errors.append("잘못된 신고 대상입니다.")
        if rerr:
            errors.append(rerr)

        # 대상 존재 + 자기 신고 차단 (SR-12)
        if not errors:
            if target_type == "user":
                target = query_db("SELECT id FROM user WHERE id = ?", (target_id,), one=True)
                if target is None:
                    errors.append("대상을 찾을 수 없습니다.")
                elif target_id == me["id"]:
                    errors.append("자기 자신은 신고할 수 없습니다.")
            else:
                target = query_db("SELECT id, seller_id FROM product WHERE id = ?", (target_id,), one=True)
                if target is None:
                    errors.append("대상을 찾을 수 없습니다.")
                elif target["seller_id"] == me["id"]:
                    errors.append("본인 상품은 신고할 수 없습니다.")

        if errors:
            for m in errors:
                flash(m, "danger")
            return render_template("report/new.html",
                                   target_type=target_type, target_id=target_id), 400

        threshold = current_app.config["REPORT_THRESHOLD"]
        try:
            # 신고 INSERT + 카운트 증가 + 임계치 처리를 하나의 트랜잭션으로 (원자성)
            with transaction() as db:
                db.execute(
                    "INSERT INTO report (id, reporter_id, target_type, target_id, reason, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), me["id"], target_type, target_id, reason, now_iso()),
                )
                _apply_threshold(db, target_type, target_id, threshold)
        except sqlite3.IntegrityError:
            # UNIQUE(reporter_id, target_type, target_id) 위반 = 중복 신고 (SR-12)
            flash("이미 신고한 대상입니다.", "warning")
            return redirect(url_for("main.index"))

        flash("신고가 접수되었습니다.", "success")
        return redirect(url_for("main.index"))

    # GET: 신고 폼 (대상은 쿼리스트링으로 전달)
    return render_template("report/new.html",
                           target_type=request.args.get("target_type", ""),
                           target_id=request.args.get("target_id", ""))
