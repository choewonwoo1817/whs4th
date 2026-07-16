"""상품 블루프린트: 등록/상세/수정/삭제/검색 + 업로드 이미지 서빙."""
import uuid

from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, abort,
    current_app, send_from_directory,
)

from ..db import query_db, execute_db, now_iso
from ..security import login_required, current_user, validate_text, validate_int
from ..uploads import save_image, delete_image, UploadError

bp = Blueprint("products", __name__)

MAX_PRICE = 1_000_000_000


def _validate_product_form():
    errors = []
    terr, title = validate_text(request.form.get("title", ""), "상품명", 100)
    if terr:
        errors.append(terr)
    derr, desc = validate_text(request.form.get("description", ""), "설명", 2000, min_len=0)
    if derr:
        errors.append(derr)
    perr, price = validate_int(request.form.get("price", ""), "가격", min_v=0, max_v=MAX_PRICE)
    if perr:
        errors.append(perr)
    return errors, title, desc, price


@bp.route("/products/new", methods=["GET", "POST"])
@login_required
def new():
    if request.method == "POST":
        errors, title, desc, price = _validate_product_form()
        if errors:      # 폼이 유효할 때만 이미지 저장 → 검증 실패 시 고아 파일 방지
            for m in errors:
                flash(m, "danger")
            return render_template("products/new.html", form=request.form), 400
        image_name = None
        file = request.files.get("image")
        if file and file.filename:
            try:
                image_name = save_image(file)
            except UploadError as e:
                flash(str(e), "danger")
                return render_template("products/new.html", form=request.form), 400
        pid = str(uuid.uuid4())
        execute_db(
            "INSERT INTO product (id, title, description, price, image_path, seller_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (pid, title, desc, price, image_name, current_user()["id"], now_iso()),
        )
        flash("상품이 등록되었습니다.", "success")
        return redirect(url_for("products.detail", id=pid))
    return render_template("products/new.html", form={})


@bp.route("/products/<id>")
def detail(id):
    p = query_db(
        "SELECT p.*, u.display_name AS seller_name, u.username AS seller_username "
        "FROM product p JOIN user u ON p.seller_id = u.id WHERE p.id = ?",
        (id,), one=True,
    )
    if p is None or p["is_blocked"]:
        abort(404)
    is_owner = current_user() is not None and current_user()["id"] == p["seller_id"]
    return render_template("products/detail.html", p=p, is_owner=is_owner)


@bp.route("/products/<id>/edit", methods=["GET", "POST"])
@login_required
def edit(id):
    p = query_db("SELECT * FROM product WHERE id = ?", (id,), one=True)
    if p is None:
        abort(404)
    if p["seller_id"] != current_user()["id"]:   # SR-05 소유자 검증 (IDOR 방지)
        abort(403)
    if request.method == "POST":
        errors, title, desc, price = _validate_product_form()
        if errors:
            for m in errors:
                flash(m, "danger")
            return render_template("products/edit.html", p=p), 400
        new_image = None
        file = request.files.get("image")
        if file and file.filename:
            try:
                new_image = save_image(file)
            except UploadError as e:
                flash(str(e), "danger")
                return render_template("products/edit.html", p=p), 400
        if new_image:
            execute_db(
                "UPDATE product SET title = ?, description = ?, price = ?, image_path = ? WHERE id = ?",
                (title, desc, price, new_image, id),
            )
            delete_image(p["image_path"])     # 교체된 옛 이미지 정리
        else:
            execute_db(
                "UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?",
                (title, desc, price, id),
            )
        flash("상품이 수정되었습니다.", "success")
        return redirect(url_for("products.detail", id=id))
    return render_template("products/edit.html", p=p)


@bp.route("/products/<id>/delete", methods=["POST"])   # GET 삭제 금지
@login_required
def delete(id):
    p = query_db("SELECT * FROM product WHERE id = ?", (id,), one=True)
    if p is None:
        abort(404)
    if p["seller_id"] != current_user()["id"]:   # SR-05
        abort(403)
    execute_db("DELETE FROM product WHERE id = ?", (id,))
    delete_image(p["image_path"])                # 고아 파일 정리
    flash("상품이 삭제되었습니다.", "info")
    return redirect(url_for("main.index"))


@bp.route("/search")
def search():
    q = request.args.get("q", "").strip()
    products = []
    if q:
        products = query_db(
            "SELECT id, title FROM product WHERE is_blocked = 0 AND title LIKE ? "
            "ORDER BY created_at DESC LIMIT 50",
            (f"%{q}%",),   # 파라미터 바인딩 (SR-02); 목록엔 이름만
        )
    return render_template("products/search.html", q=q, products=products)


@bp.route("/uploads/<path:name>")
def uploaded_file(name):
    # send_from_directory 가 경로 이탈(../)을 차단 (SR-14)
    return send_from_directory(current_app.config["UPLOAD_DIR"], name)
