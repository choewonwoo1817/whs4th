"""Step 7 송금 — 정상 + 음수/자기/부족/휴면 차단 + 동시성 더블스펜딩 방지."""
import threading

from app.db import query_db


def _bal(app, uid):
    with app.app_context():
        return query_db("SELECT balance FROM user WHERE id = ?", (uid,), one=True)["balance"]


# --- 정상 ---
def test_transfer_success(client, make_user, login, app):
    sender = make_user("sender", balance=1000)
    make_user("receiver", balance=0)
    login(sender)
    r = client.post("/transfer", data={"to_username": "receiver", "amount": "300"})
    assert r.status_code == 302
    assert _bal(app, sender) == 700
    with app.app_context():
        recv = query_db("SELECT balance FROM user WHERE username = ?", ("receiver",), one=True)
    assert recv["balance"] == 300


# --- 공격/오용 ---
def test_transfer_negative_amount_rejected(client, make_user, login, app):
    sender = make_user("sender", balance=1000)
    make_user("receiver")
    login(sender)
    r = client.post("/transfer", data={"to_username": "receiver", "amount": "-500"})
    assert r.status_code == 400
    assert _bal(app, sender) == 1000     # 변화 없음


def test_transfer_zero_amount_rejected(client, make_user, login):
    sender = make_user("sender", balance=1000)
    make_user("receiver")
    login(sender)
    assert client.post("/transfer", data={"to_username": "receiver", "amount": "0"}).status_code == 400


def test_transfer_over_balance_rejected(client, make_user, login, app):
    sender = make_user("sender", balance=100)
    make_user("receiver", balance=0)
    login(sender)
    r = client.post("/transfer", data={"to_username": "receiver", "amount": "500"})
    assert r.status_code == 400
    assert _bal(app, sender) == 100      # 잔액 그대로


def test_transfer_to_self_rejected(client, make_user, login, app):
    sender = make_user("sender", balance=1000)
    login(sender)
    r = client.post("/transfer", data={"to_username": "sender", "amount": "100"})
    assert r.status_code == 400
    assert _bal(app, sender) == 1000


def test_transfer_to_unknown_rejected(client, make_user, login):
    sender = make_user("sender", balance=1000)
    login(sender)
    assert client.post("/transfer", data={"to_username": "ghost", "amount": "100"}).status_code == 400


def test_transfer_to_dormant_rejected(client, make_user, login, app):
    sender = make_user("sender", balance=1000)
    victim = make_user("victim", balance=0)
    with app.app_context():
        from app.db import execute_db
        execute_db("UPDATE user SET is_dormant = 1 WHERE id = ?", (victim,))
    login(sender)
    assert client.post("/transfer", data={"to_username": "victim", "amount": "100"}).status_code == 400


def test_transfer_requires_login(client):
    r = client.post("/transfer", data={"to_username": "x", "amount": "100"})
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_no_double_spend_under_concurrency(app, make_user):
    """잔액 100인 sender가 동시에 100씩 두 번 송금 시도 → 한 번만 성공."""
    sender = make_user("sender", balance=100)
    r1 = make_user("r1", balance=0)
    r2 = make_user("r2", balance=0)
    results = []

    def do(recv):
        try:
            with app.app_context():
                from app.db import transaction
                with transaction() as db:
                    cur = db.execute(
                        "UPDATE user SET balance = balance - ? WHERE id = ? AND balance >= ?",
                        (100, sender, 100),
                    )
                    if cur.rowcount != 1:
                        results.append("fail")
                        return
                    db.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (100, recv))
                    results.append("ok")
        except Exception:
            results.append("err")

    t1 = threading.Thread(target=do, args=(r1,))
    t2 = threading.Thread(target=do, args=(r2,))
    t1.start(); t2.start(); t1.join(); t2.join()

    assert results.count("ok") == 1        # 정확히 한 번만 성공
    assert _bal(app, sender) == 0          # 잔액이 음수로 가지 않음
