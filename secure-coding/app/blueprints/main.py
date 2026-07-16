"""메인(홈) 블루프린트."""
from flask import Blueprint, render_template

from ..db import query_db

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    # 차단되지 않은 상품만, 목록엔 이름만 노출 (FR-12, 상세는 클릭 시)
    products = query_db(
        "SELECT id, title FROM product WHERE is_blocked = 0 "
        "ORDER BY created_at DESC LIMIT 50"
    )
    return render_template("index.html", products=products)
