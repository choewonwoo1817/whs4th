"""보안 실증 — 실제 /transfer 엔드포인트를 스레드 2개로 동시에 호출해,
잔액 1회분만 있는 계정이 두 번 송금되지 않음(더블스펜딩 방지)을 라이브 HTTP로 검증한다.

기존 단위 테스트는 DB 계층 조건부 UPDATE만 검증했으나, 이 스크립트는 라우트+세션+DB 전체 경로를 동시성으로 친다.

실행: python 보안실증/demo_concurrency.py <base_url> <db_path>
"""
import http.cookiejar
import re
import sqlite3
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5013"
DB = sys.argv[2] if len(sys.argv) > 2 else "instance/market.db"


def make_session():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def get(op, path):
    return op.open(BASE + path).read().decode()


def csrf(op, path):
    return re.search(r'name="csrf_token" value="([^"]+)"', get(op, path)).group(1)


def post(op, path, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    try:
        op.open(req)
        return 200
    except urllib.error.HTTPError as e:
        return e.code


def register(username, pw="password123"):
    op = make_session()
    post(op, "/register", {"csrf_token": csrf(op, "/register"), "username": username,
                           "display_name": username, "password": pw, "password_confirm": pw})
    return op


def login_as(username, pw="password123"):
    op = make_session()
    post(op, "/login", {"csrf_token": csrf(op, "/login"), "username": username, "password": pw})
    return op


# 수신자 2명, 송신자 1명(가입 보너스 1000P) 준비 (아이디 3자 이상 규칙 준수)
register("rcv1"); register("rcv2"); register("sender")

# 송신자의 서로 다른 세션 2개 (동시 요청 주체)
sessA, sessB = login_as("sender"), login_as("sender")
tokA, tokB = csrf(sessA, "/transfer"), csrf(sessB, "/transfer")

results = {}
def do(sess, tok, to, key):
    results[key] = post(sess, "/transfer", {"csrf_token": tok, "to_username": to, "amount": "1000"})

tA = threading.Thread(target=do, args=(sessA, tokA, "rcv1", "A"))
tB = threading.Thread(target=do, args=(sessB, tokB, "rcv2", "B"))
tA.start(); tB.start(); tA.join(); tB.join()

con = sqlite3.connect(DB)
bal = con.execute("SELECT balance FROM user WHERE username='sender'").fetchone()[0]
r1 = con.execute("SELECT balance FROM user WHERE username='rcv1'").fetchone()[0]
r2 = con.execute("SELECT balance FROM user WHERE username='rcv2'").fetchone()[0]
xfers = con.execute("SELECT COUNT(*) FROM transfers t JOIN user u ON t.sender_id=u.id WHERE u.username='sender'").fetchone()[0]
con.close()

print(f"동시 요청 결과(HTTP): A(302=성공/400=실패)={results.get('A')}, B={results.get('B')}")
print(f"송신자 잔액: {bal} (0 이어야)")
print(f"수신자 r1={r1}, r2={r2} (한쪽만 1000)")
print(f"송신자 거래 기록 수: {xfers} (1 이어야)")
ok = (bal == 0) and (xfers == 1) and ((r1 == 1000) ^ (r2 == 1000))
print("→", "✅ 더블스펜딩 방지 확인 (한 번만 송금)" if ok else "❌ 이상: 더블스펜딩 발생")
sys.exit(0 if ok else 1)
