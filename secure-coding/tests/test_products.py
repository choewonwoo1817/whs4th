"""Step 3 상품 — CRUD 정상 + IDOR/XSS/SQLi/업로드 공격."""
import io

from PIL import Image

from app.db import query_db, execute_db, now_iso


def _png_bytes(color=(255, 0, 0)):
    buf = io.BytesIO()
    Image.new("RGB", (10, 10), color).save(buf, format="PNG")
    buf.seek(0)
    return buf


def _make_product(app, seller_id, title="가방", price=1000, blocked=0):
    import uuid
    pid = str(uuid.uuid4())
    with app.app_context():
        execute_db(
            "INSERT INTO product (id, title, description, price, seller_id, is_blocked, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (pid, title, "설명", price, seller_id, blocked, now_iso()),
        )
    return pid


# --- 정상 ---
def test_create_product(client, make_user, login, app):
    uid = make_user("alice")
    login(uid)
    r = client.post("/products/new", data={"title": "노트북", "description": "좋음", "price": "5000"})
    assert r.status_code == 302
    with app.app_context():
        p = query_db("SELECT * FROM product WHERE title = ?", ("노트북",), one=True)
    assert p is not None and p["seller_id"] == uid


def test_detail_view(client, make_user, app):
    uid = make_user("alice")
    pid = _make_product(app, uid)
    assert client.get(f"/products/{pid}").status_code == 200


def test_blocked_product_hidden(client, make_user, app):
    uid = make_user("alice")
    pid = _make_product(app, uid, blocked=1)
    assert client.get(f"/products/{pid}").status_code == 404


def test_upload_valid_png(client, make_user, login, app):
    uid = make_user("alice")
    login(uid)
    r = client.post("/products/new",
                    data={"title": "사진상품", "description": "d", "price": "10",
                          "image": (_png_bytes(), "photo.png")},
                    content_type="multipart/form-data")
    assert r.status_code == 302
    with app.app_context():
        p = query_db("SELECT image_path FROM product WHERE title = ?", ("사진상품",), one=True)
    assert p["image_path"] and p["image_path"].endswith(".png")


# --- 공격 ---
def test_edit_others_product_forbidden(client, make_user, login, app):
    owner = make_user("owner")
    attacker = make_user("attacker")
    pid = _make_product(app, owner)
    login(attacker)
    r = client.post(f"/products/{pid}/edit", data={"title": "해킹", "description": "x", "price": "1"})
    assert r.status_code == 403            # SR-05 IDOR 차단
    with app.app_context():
        p = query_db("SELECT title FROM product WHERE id = ?", (pid,), one=True)
    assert p["title"] != "해킹"


def test_delete_others_product_forbidden(client, make_user, login, app):
    owner = make_user("owner")
    attacker = make_user("attacker")
    pid = _make_product(app, owner)
    login(attacker)
    assert client.post(f"/products/{pid}/delete").status_code == 403
    with app.app_context():
        assert query_db("SELECT id FROM product WHERE id = ?", (pid,), one=True) is not None


def test_delete_get_not_allowed(client, make_user, login, app):
    uid = make_user("owner")
    pid = _make_product(app, uid)
    login(uid)
    assert client.get(f"/products/{pid}/delete").status_code == 405   # GET 삭제 금지


def test_stored_xss_escaped(client, make_user, app):
    uid = make_user("alice")
    pid = _make_product(app, uid, title="<script>alert(1)</script>")
    html = client.get(f"/products/{pid}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html      # 원본 그대로 렌더되지 않음
    assert "&lt;script&gt;" in html                     # 이스케이프되어 출력 (SR-03)


def test_search_finds_matching_product(client, make_user, app):
    uid = make_user("alice")
    _make_product(app, uid, title="노트북")
    html = client.get("/search", query_string={"q": "노트"}).get_data(as_text=True)
    assert "노트북" in html          # 부분 문자열 검색 매칭


def test_search_sql_injection_blocked(client, make_user, app):
    uid = make_user("alice")
    _make_product(app, uid, title="정상상품")
    _make_product(app, uid, title="숨김상품", blocked=1)
    html = client.get("/search", query_string={"q": "' OR '1'='1"}).get_data(as_text=True)
    # 인젝션이 통했다면 모든 상품(차단 포함)이 노출됨 → 그렇지 않아야 함
    assert "숨김상품" not in html
    assert "정상상품" not in html   # 리터럴 문자열엔 매칭 안 됨


def test_upload_svg_rejected(client, make_user, login):
    uid = make_user("alice")
    login(uid)
    svg = io.BytesIO(b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>")
    r = client.post("/products/new",
                    data={"title": "svg상품", "description": "d", "price": "10",
                          "image": (svg, "x.svg")},
                    content_type="multipart/form-data")
    assert r.status_code == 400        # SVG 확장자 차단 (SR-13)


def test_upload_oversized_image_rejected(client, make_user, login):
    # 압축폭탄 방어: 픽셀 상한(25MP) 초과 이미지 거부
    uid = make_user("alice")
    login(uid)
    buf = io.BytesIO()
    Image.new("RGB", (6000, 6000)).save(buf, format="PNG")   # 36MP > 25MP
    buf.seek(0)
    r = client.post("/products/new",
                    data={"title": "큰이미지", "description": "d", "price": "1",
                          "image": (buf, "big.png")},
                    content_type="multipart/form-data")
    assert r.status_code == 400


def test_upload_fake_image_rejected(client, make_user, login):
    uid = make_user("alice")
    login(uid)
    # 확장자는 png 지만 내용은 텍스트 → Pillow 검증 실패
    fake = io.BytesIO(b"this is not an image")
    r = client.post("/products/new",
                    data={"title": "위장", "description": "d", "price": "10",
                          "image": (fake, "evil.png")},
                    content_type="multipart/form-data")
    assert r.status_code == 400


def test_delete_removes_image_file(client, make_user, login, app):
    import os
    uid = make_user("alice")
    login(uid)
    client.post("/products/new",
                data={"title": "파일테스트", "description": "d", "price": "1",
                      "image": (_png_bytes(), "a.png")},
                content_type="multipart/form-data")
    with app.app_context():
        p = query_db("SELECT id, image_path FROM product WHERE title = ?", ("파일테스트",), one=True)
    updir = app.config["UPLOAD_DIR"]
    assert os.path.isfile(os.path.join(updir, p["image_path"]))
    client.post(f"/products/{p['id']}/delete")
    assert not os.path.isfile(os.path.join(updir, p["image_path"]))   # 고아 파일 정리 확인


def test_edit_replaces_image_and_removes_old(client, make_user, login, app):
    import os
    uid = make_user("alice")
    login(uid)
    client.post("/products/new",
                data={"title": "교체", "description": "d", "price": "1",
                      "image": (_png_bytes((255, 0, 0)), "a.png")},
                content_type="multipart/form-data")
    with app.app_context():
        p = query_db("SELECT id, image_path FROM product WHERE title = ?", ("교체",), one=True)
    old = p["image_path"]
    updir = app.config["UPLOAD_DIR"]
    client.post(f"/products/{p['id']}/edit",
                data={"title": "교체", "description": "d", "price": "1",
                      "image": (_png_bytes((0, 255, 0)), "b.png")},
                content_type="multipart/form-data")
    with app.app_context():
        p2 = query_db("SELECT image_path FROM product WHERE id = ?", (p["id"],), one=True)
    assert p2["image_path"] != old
    assert not os.path.isfile(os.path.join(updir, old))                # 옛 이미지 삭제
    assert os.path.isfile(os.path.join(updir, p2["image_path"]))       # 새 이미지 존재


def test_password_change_keeps_session(client, make_user, login, app):
    uid = make_user("alice", "password123")
    login(uid)
    client.post("/mypage", data={"action": "password", "current_password": "password123",
                                 "new_password": "newpassword456", "new_password_confirm": "newpassword456"})
    # 세션 재발급 후에도 로그인 유지 (재발급이 로그인을 깨지 않음)
    assert client.get("/mypage").status_code == 200


def test_negative_price_rejected(client, make_user, login):
    uid = make_user("alice")
    login(uid)
    r = client.post("/products/new", data={"title": "음수", "description": "d", "price": "-500"})
    assert r.status_code == 400
