"""보안 실증 — SQL Injection이 '취약 코드(Before)'에서는 실제로 인증을 우회하고,
'수정 코드(After)'에서는 막힘을 보여준다. 보고서 6.1의 Before/After가 가설이 아님을 증명.

실행: python 보안실증/demo_sqli.py
"""
import sqlite3

db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE user (username TEXT, password TEXT)")
db.execute("INSERT INTO user VALUES ('alice', 'secret')")

payload = "' OR '1'='1'--"   # 존재하지 않는 아이디지만 항상 참으로 만드는 인젝션

print("입력(공격 페이로드):", payload)
print("-" * 60)

# ── Before (취약): 문자열 포매팅으로 쿼리 조립 ──
vulnerable_query = f"SELECT * FROM user WHERE username = '{payload}'"  # nosec B608 - 의도적 취약(실증용)
naive = db.execute(vulnerable_query).fetchall()
print("[Before/취약] 쿼리:", vulnerable_query)
print("[Before/취약] 결과:", naive)
print("  →", "❌ 인증 우회 성공 (취약!)" if naive else "안전")
print("-" * 60)

# ── After (수정): 파라미터 바인딩 ──
safe = db.execute("SELECT * FROM user WHERE username = ?", (payload,)).fetchall()
print("[After/수정] 쿼리: SELECT * FROM user WHERE username = ?  args=(payload,)")
print("[After/수정] 결과:", safe)
print("  →", "✅ 우회 차단 (안전)" if not safe else "여전히 취약")
