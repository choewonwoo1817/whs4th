"""슬라이드 최소 요구사항 보완분 검증 — 내 상품 관리 동선, 1:1 채팅 시작 UI."""
import uuid

from app.db import execute_db, now_iso


def _make_product(app, seller_id, title="내상품"):
    pid = str(uuid.uuid4())
    with app.app_context():
        execute_db(
            "INSERT INTO product (id, title, description, price, seller_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (pid, title, "설명", 1000, seller_id, now_iso()),
        )
    return pid


def test_mypage_lists_own_products_with_manage_links(client, make_user, login, app):
    uid = make_user("alice")
    pid = _make_product(app, uid, title="내가올린가방")
    login(uid)
    html = client.get("/mypage").get_data(as_text=True)
    assert "내가올린가방" in html                      # 내 상품 확인
    assert f"/products/{pid}/edit" in html             # 수정 동선
    assert f"/products/{pid}/delete" in html           # 삭제 동선


def test_profile_has_1to1_chat_link(client, make_user, login):
    a = make_user("alice")
    b = make_user("bob")
    login(a)
    html = client.get(f"/users/{b}").get_data(as_text=True)
    assert f"/chat/{b}" in html                         # 1:1 채팅 시작 링크


def test_product_detail_has_seller_chat_link(client, make_user, login, app):
    seller = make_user("seller")
    buyer = make_user("buyer")
    pid = _make_product(app, seller)
    login(buyer)
    html = client.get(f"/products/{pid}").get_data(as_text=True)
    assert f"/chat/{seller}" in html                    # 판매자와 1:1 채팅 링크
