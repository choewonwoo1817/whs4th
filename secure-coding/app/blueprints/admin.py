"""관리자 블루프린트: 유저/상품/신고 관리. 전 라우트 admin_required (SR-11)."""
from flask import Blueprint, render_template, redirect, url_for, flash, abort

from ..db import query_db, execute_db
from ..security import admin_required, current_user
from ..uploads import delete_image

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@admin_required
def dashboard():
    users = query_db(
        "SELECT id, username, display_name, is_admin, is_dormant, report_count, balance "
        "FROM user ORDER BY created_at DESC"
    )
    products = query_db(
        "SELECT p.id, p.title, p.is_blocked, p.report_count, u.username AS seller "
        "FROM product p JOIN user u ON p.seller_id = u.id ORDER BY p.created_at DESC"
    )
    reports = query_db(
        "SELECT r.id, r.target_type, r.target_id, r.reason, u.username AS reporter, r.created_at "
        "FROM report r JOIN user u ON r.reporter_id = u.id ORDER BY r.created_at DESC LIMIT 100"
    )
    return render_template("admin/dashboard.html", users=users, products=products, reports=reports)


@bp.route("/product/<id>/delete", methods=["POST"])
@admin_required
def delete_product(id):
    p = query_db("SELECT id, image_path FROM product WHERE id = ?", (id,), one=True)
    if p is None:
        abort(404)
    execute_db("DELETE FROM product WHERE id = ?", (id,))
    delete_image(p["image_path"])
    flash("상품을 삭제했습니다.", "info")
    return redirect(url_for("admin.dashboard"))


@bp.route("/product/<id>/unblock", methods=["POST"])
@admin_required
def unblock_product(id):
    if query_db("SELECT id FROM product WHERE id = ?", (id,), one=True) is None:
        abort(404)
    execute_db("UPDATE product SET is_blocked = 0, report_count = 0 WHERE id = ?", (id,))
    flash("상품 차단을 해제했습니다.", "success")
    return redirect(url_for("admin.dashboard"))


@bp.route("/user/<id>/toggle_dormant", methods=["POST"])
@admin_required
def toggle_dormant(id):
    target = query_db("SELECT id, is_dormant FROM user WHERE id = ?", (id,), one=True)
    if target is None:
        abort(404)
    if target["id"] == current_user()["id"]:
        flash("본인 계정은 휴면 처리할 수 없습니다.", "danger")
        return redirect(url_for("admin.dashboard"))
    if target["is_dormant"]:
        execute_db("UPDATE user SET is_dormant = 0, report_count = 0 WHERE id = ?", (id,))
        flash("사용자를 복구했습니다.", "success")
    else:
        execute_db("UPDATE user SET is_dormant = 1 WHERE id = ?", (id,))
        flash("사용자를 휴면 처리했습니다.", "info")
    return redirect(url_for("admin.dashboard"))
