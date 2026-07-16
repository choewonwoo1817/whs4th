# 6. 발견한 보안 약점과 수정 (Before / After)

> 과제 핵심 요구사항인 "확인한 보안 약점이 무엇이고 어떻게 변경했는지"를 정리한다.
> 각 항목은 **취약 코드(Before) → 공격 시나리오 → 수정(After) → 검증**으로 구성한다.
> "취약한 순진한 구현"은 개발 중 실제로 경계한 안티패턴이며, 최종 코드는 모두 After 상태다.
> 검증은 `tests/`의 실제 테스트로 자동화되어 있다(총 85개 통과).
>
> - **6.1~6.12**: 설계 단계에서 선제 제거한 표준 취약점. Before(취약 코드)가 가설이 아님은 실증 스크립트로 확인 — 예: `보안실증/demo_sqli.py` 실행 시 취약 코드는 `' OR '1'='1'--`로 **인증 우회 성공**, 수정 코드(파라미터 바인딩)는 **차단**.
> - **6.13~6.17**: 개발·리뷰 중 **실제로 발견해 수정한 사례**(의존성 CVE 9건, 다중 에이전트 패널이 잡은 세션 고정 등).

---

## 6.1 SQL Injection — 인증 우회 (SR-02)

**Before (취약)**
```python
# 문자열 포매팅으로 쿼리를 조립하면 인젝션에 노출
user = db.execute(
    f"SELECT * FROM user WHERE username = '{username}'"
).fetchone()
```
**공격:** 아이디에 `' OR '1'='1'--` 입력 → 쿼리가 항상 참이 되어 인증 우회.

**After (수정)** — `app/blueprints/auth.py`
```python
user = query_db("SELECT * FROM user WHERE username = ?", (username,), one=True)
```
파라미터 바인딩으로 입력이 데이터로만 취급된다. 프로젝트 전체가 이 규칙을 따른다.

**검증:** `test_auth.py::test_login_sql_injection_blocked` — `' OR '1'='1'--` 로그인 시 401, 세션 미생성.

---

## 6.2 비밀번호 평문 저장 (SR-01)

**Before**
```python
execute_db("INSERT INTO user (username, password) VALUES (?, ?)", (username, password))
```
**공격:** DB 유출 시 전 계정 비밀번호가 즉시 노출.

**After** — `app/security.py`, `auth.py`
```python
from argon2 import PasswordHasher
_ph = PasswordHasher()
# 저장
execute_db("INSERT INTO user (..., password_hash, ...) VALUES (..., ?, ...)", (hash_password(pw),))
# 검증
_ph.verify(stored_hash, pw)
```
argon2id + salt 자동 적용. 평문·단순 해시(MD5/SHA)를 쓰지 않는다.

**검증:** `test_auth.py::test_register_success_and_password_hashed` — 저장값이 `$argon2`로 시작, 평문 미포함.

---

## 6.3 권한 상승 — Mass Assignment (SR-11)

**Before**
```python
# 폼 전체를 그대로 저장 → is_admin 을 폼에 넣으면 관리자가 됨
cols = ",".join(request.form.keys())
```
**공격:** 회원가입 요청에 `is_admin=1`(또는 `balance=999999`) 필드를 추가 → 누구나 관리자/부자.

**After** — `app/blueprints/auth.py`
```python
execute_db(
    "INSERT INTO user (id, username, display_name, password_hash, balance, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    (uuid, username, display_name, hash_password(pw), REGISTER_BONUS, now_iso()),
)  # is_admin/is_dormant 는 삽입 대상에서 제외(기본값), balance 는 서버 상수만 사용
```
**검증:** `test_auth.py::test_register_ignores_privilege_fields` — `is_admin=1&balance=999999` 주입해도 무시됨(핵심: **사용자 입력이 특권/상태 컬럼에 반영되지 않음**). 테스트는 설정 `REGISTER_BONUS=0` 기준이라 balance=0; 운영 기본 가입 보너스는 1000이며 이 역시 서버 상수만 사용.

---

## 6.4 저장형 XSS — 상품/소개글/채팅 (SR-03)

**Before**
```html
<div>{{ product.description | safe }}</div>   <!-- 이스케이프 해제 -->
```
```javascript
li.innerHTML = sender + ": " + msg;   // 채팅을 innerHTML 로 삽입
```
**공격:** 상품 설명/소개글/채팅에 `<script>alert(1)</script>` 저장 → 열람자 브라우저에서 실행.

**After**
- 서버 렌더링: Jinja2 자동 이스케이프 유지, `|safe` 미사용.
- 채팅(클라이언트 렌더): `app/static/js/chat.js`
```javascript
li.appendChild(document.createTextNode(content));  // textContent → HTML 미해석
```
**검증:** `test_products.py::test_stored_xss_escaped`, `test_users.py::test_bio_xss_escaped`,
`test_chat.py::test_chat_history_escaped` — 원본 태그 미출력, `&lt;script&gt;`로 이스케이프.

---

## 6.5 IDOR — 타인 상품 수정/삭제 (SR-05)

**Before**
```python
@bp.route("/products/<id>/delete", methods=["POST"])
@login_required
def delete(id):
    execute_db("DELETE FROM product WHERE id = ?", (id,))  # 소유자 확인 없음
```
**공격:** 남의 `product_id`로 삭제/수정 요청 → 그대로 실행. (UUID여도 방어 아님)

**After** — `app/blueprints/products.py`
```python
p = query_db("SELECT * FROM product WHERE id = ?", (id,), one=True)
if p is None: abort(404)
if p["seller_id"] != current_user()["id"]: abort(403)   # 소유자 검증
```
**검증:** `test_products.py::test_edit_others_product_forbidden`, `test_delete_others_product_forbidden` — 타인 자원 조작 시 403, 데이터 불변. 채팅 1:1도 동일 원리(`test_chat.py::test_private_chat_idor_blocked`).

---

## 6.6 송금 경쟁 조건 — 더블스펜딩 (SR-08)

**Before**
```python
bal = query_db("SELECT balance FROM user WHERE id=?", (me,), one=True)["balance"]
if bal >= amount:                              # 확인
    execute_db("UPDATE user SET balance=? WHERE id=?", (bal - amount, me))  # 갱신
```
**공격:** 잔액 100인 계정이 동시에 100씩 두 번 송금 → 두 요청 모두 확인 통과 후 갱신 → 잔액 음수(더블스펜딩).

**After** — `app/blueprints/transfer.py` + `app/db.py::transaction`
```python
with transaction() as db:   # BEGIN IMMEDIATE
    cur = db.execute(
        "UPDATE user SET balance = balance - ? WHERE id = ? AND balance >= ?",
        (amount, me, amount))
    if cur.rowcount != 1:    # 잔액 부족이면 0행 → 실패
        raise _Insufficient()
    db.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver))
```
조건부 UPDATE + 트랜잭션 잠금으로 원자성 확보. DB에도 `CHECK(balance>=0)`.

**검증(2단):**
- DB 계층: `test_transfer.py::test_no_double_spend_under_concurrency` — 조건부 UPDATE를 별도 연결 스레드 2개로 실행해 1건만 성공·잔액 0.
- **엔드포인트 계층: `보안실증/demo_concurrency.py`** — 스레드 2개가 **실제 `/transfer` 라우트를 동시 호출**(라우트+세션+DB 전 경로). 잔액 1회분에서 1건만 302 성공·1건 400 거부, 송신자 잔액 0, 거래기록 정확히 1건 확인.
- 정상/초과: `test_transfer_success`, `test_transfer_over_balance_rejected`.

---

## 6.7 잘못된 송금 입력 — 음수/자기송금 (SR-08)

**Before:** 금액 부호·수신자 검증 없음 → `amount=-500` 송금 시 오히려 잔액 증가, 자기 자신 송금 허용.

**After** — 서버측 검증 + DB 제약
```python
aerr, amount = validate_int(form["amount"], "송금 금액", min_v=1, max_v=1_000_000_000)
if receiver["id"] == me["id"]: errors.append("자기 자신에게는 송금할 수 없습니다.")
```
DB: `transfers.amount CHECK(amount > 0)`, `CHECK(sender_id <> receiver_id)`.

**검증:** `test_transfer.py::test_transfer_negative_amount_rejected`, `test_transfer_zero_amount_rejected`, `test_transfer_to_self_rejected`.

---

## 6.8 악성 파일 업로드 — SVG/위장 이미지 (SR-13)

**Before**
```python
file.save(os.path.join(UPLOAD_DIR, file.filename))  # 확장자·내용 검증 없이 원본 저장
```
**공격:** `evil.svg`(내부 `<script>`) 업로드 → 저장형 XSS. 또는 `evil.png`로 위장한 실행 파일 업로드.

**After** — `app/uploads.py`
```python
if ext not in {"jpg","jpeg","png","gif","webp"}: raise UploadError(...)  # SVG 제외
probe = Image.open(BytesIO(data)); probe.verify()                        # 실제 이미지 검증
img = Image.open(BytesIO(data)); img.save(path, format=img.format)       # 재인코딩(스크립트 제거)
```
저장 파일명은 서버가 UUID로 부여, 서빙은 `send_from_directory`(경로 이탈 차단).

**검증:** `test_products.py::test_upload_svg_rejected`, `test_upload_fake_image_rejected` — 각각 400.

---

## 6.9 신고 남용 — 자기/중복 신고 (SR-12)

**Before:** 신고에 아무 제한이 없어 한 사람이 반복 신고로 임계치를 채워 타인을 휴면/차단시킬 수 있음.

**After** — `app/blueprints/reports.py` + `schema.sql`
```python
if target_id == me["id"]: errors.append("자기 자신은 신고할 수 없습니다.")
# INSERT 시 UNIQUE(reporter_id, target_type, target_id) 위반 → 중복 신고 차단
```
신고 카운트 증가·임계치 처리는 `BEGIN IMMEDIATE` 트랜잭션으로 원자 처리.

**검증:** `test_reports.py::test_self_report_user_rejected`, `test_duplicate_report_rejected`(중복은 카운트 미증가), `test_report_own_product_rejected`.

---

## 6.10 CSRF — 상태변경 위조 (SR-04)

**Before:** 토큰 없이 POST 처리 → 공격자 사이트가 피해자 브라우저로 비밀번호 변경·송금·상품삭제 요청을 위조.

**After** — `app/__init__.py`
```python
csrf = CSRFProtect(); csrf.init_app(app)   # 전역
```
모든 폼에 `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`.

**검증:** `test_security.py::test_post_without_csrf_token_rejected`(토큰 없음 400) / `test_post_with_csrf_token_accepted`(정상 302).

---

## 6.11 세션·전송 보안 (SR-06, SR-16)

**Before:** 클라이언트 쿠키 세션(휴면 처리해도 즉시 무효화 불가), 쿠키 플래그 미설정, 평문 전송.

**After**
- 서버 측 세션(Flask-Session) → 휴면/로그아웃 시 서버가 즉시 무효화.
- `SESSION_COOKIE_HTTPONLY=True`, `SAMESITE=Lax`, `SECURE`(HTTPS 토글), 유휴 타임아웃.
- 운영은 ngrok HTTPS로 HTTP·WebSocket(WSS) 모두 TLS.

**검증:** `test_security.py::test_session_cookie_httponly_samesite`, `test_reports.py::test_dormant_user_cannot_login_after_reports`.

---

## 6.12 정보 노출 & 무차별 대입 (SR-09, SR-10, SR-15)

- **에러 메시지:** 전역 에러 핸들러가 스택트레이스/쿼리 대신 일반 메시지만 노출(`app/__init__.py`). 운영 `DEBUG=False`.
- **로그인 보호:** Flask-Limiter(분당 제한) + 연속 실패 시 점진 잠금(`auth.py`).

**검증:** `test_security.py::test_security_headers_present`, 보안 헤더 4종 적용.

---

## 6.13 의존성 취약점 (유지보수, SR 상시)

`pip-audit`로 초기 의존성에서 **9건의 알려진 취약점**(flask·python-dotenv·pillow) 발견 →
안전 버전으로 업그레이드(Flask 3.1.3, python-dotenv 1.2.2, Pillow 12.3.0, Flask-SocketIO 5.6.1) →
**재점검 0건**. 상세는 05_유지보수.md.

---

## 6.14 신고 기반 관리자 계정 잠금 — DoS (독립 감사에서 발견)

**Before:** 신고 임계치 자동 휴면 로직에 관리자 예외가 없어, 일반 유저 여러 명이 담합하여
관리자 계정을 신고하면 관리자가 휴면 처리되어 로그인이 차단됨(서비스 마비).

**공격:** 서로 다른 계정 N개(임계치)로 관리자 `user_id`를 신고 → `is_dormant=1` → 관리자 로그인 불가.

**After** — `app/blueprints/reports.py::_apply_threshold`
```python
row = db.execute("SELECT report_count, is_admin FROM user WHERE id = ?", (target_id,)).fetchone()
if row["report_count"] >= threshold and not row["is_admin"]:   # 관리자는 자동 휴면 제외
    db.execute("UPDATE user SET is_dormant = 1 WHERE id = ?", (target_id,))
```
신고 기록·카운트는 남기되(감사 추적), 관리자 계정은 자동 휴면 대상에서 제외한다.

**검증:** `test_reports.py::test_admin_not_auto_dormant_by_reports` — 임계치까지 신고해도 관리자 `is_dormant=0`.

---

## 6.15 워커 풀 다중 리뷰 반영 (2차 하드닝)

17개 리뷰 워커(기능·개발자 2렌즈 × 8모듈 + 종합)로 재감사해 발견·수정한 항목:

- **CSP vs 인라인 핸들러 충돌**: `script-src`에 `unsafe-inline`이 없어 삭제확인 `onsubmit="confirm()"`이 CSP에 차단 → 확인창 없이 삭제되던 문제. 인라인 제거 후 외부 `static/js/confirm.js`(`data-confirm` 속성)로 대체, CSP 무결성 유지. (`test_products.py`, 소유자 페이지 렌더 검증)
- **소켓 계층 인가 우회**: SocketIO 핸들러가 휴면 사용자를 검증하지 않아 제재된 사용자가 채팅 지속 가능 → connect/메시지 핸들러에 `is_dormant` 검증 추가. (`test_chat.py::test_dormant_user_socket_rejected`)
- **업로드 파일 라이프사이클**: 상품 삭제 시 이미지 파일 미삭제(고아), 수정 시 이미지 교체 불가, 폼 검증 실패 시 이미지 고아 → 삭제 시 파일 제거, 수정 시 교체+옛 파일 정리, 검증 순서 교정. (`test_delete_removes_image_file`, `test_edit_replaces_image_and_removes_old`)
- **비밀번호 변경 후 세션 재발급**: 변경 후 세션을 재발급해 기존(탈취) 세션 무효화. (`test_password_change_keeps_session`)
- (부가) SQLite `PRAGMA busy_timeout=5000` 명시로 동시 쓰기 시 즉시 실패 대신 대기.

> 참고: 워커가 제기한 "동시 송금 시 `database is locked` 500"은 실측 결과 재현되지 않음(sqlite3 기본 timeout이 대기 처리) — 과대보고로 판단하고 별도 수정 없이 `busy_timeout`만 명시.

---

## 6.16 방어적 하드닝 (테스터 관점 선제 조치)

침투 테스트에서 노릴 수 있는 잔여 표면을 선제적으로 제거:

- **로그인 타이밍 기반 사용자 열거**: 존재하지 않는 아이디는 argon2 검증을 건너뛰어 응답이 빨라짐 → 유효 아이디 추측 가능. 아이디가 없을 때도 더미 해시로 argon2 검증을 수행해 응답 시간 차 제거. (`test_auth.py::test_login_timing_enumeration_mitigated`)
- **이미지 압축폭탄(DoS)**: 작은 파일이지만 초대형 해상도인 이미지로 메모리 고갈 유발 → 25MP 픽셀 상한 + `DecompressionBombError` 처리로 차단. (`test_products.py::test_upload_oversized_image_rejected`)
- **회원가입 동시성 UNIQUE 충돌**: 동시 가입 시 `IntegrityError`로 500 노출 → 친절한 400 처리.
- **로그인 잠금 메모리 남용**: 공격자가 다양한 아이디/IP로 인메모리 잠금 dict를 무한 증식 → 만료 항목 자동 정리.

---

## 6.17 세션 고정(Session Fixation) — PM 리뷰 패널이 발견

**Before:** 로그인 시 `session.clear()` 후 재대입만 하여, Flask-Session의 서버측 세션 id(sid)가 **회전되지 않음**. 설계 주석은 "세션 재발급(SR-06)"이라 했으나 실제로는 미작동 → 공격자가 피해자 브라우저에 심은 sid가 로그인 후에도 유지되어 세션 고정→계정 탈취 가능.

**공격(라이브 재현):** curl로 로그인 전/후 `session` 쿠키 값이 **동일함**을 확인 → 취약 확정.

**After** — `app/security.py::regenerate_session`, `auth.py`, `users.py`, `schema.sql`
```python
def regenerate_session():
    session.clear()
    if hasattr(session, "sid"):
        session.sid = secrets.token_urlsafe(32)   # 서버측 sid 실제 회전
    session.modified = True
```
- 로그인·비밀번호 변경 시 sid를 실제로 회전(재현 결과 로그인 전/후 sid 상이).
- `user.session_epoch` 도입 → 비밀번호 변경 시 증가시켜 **다른 기기의 기존 세션 전부 무효화**(`current_user`가 epoch 불일치 세션을 로그아웃 처리).

**검증:** `test_auth.py::test_login_rotates_session_cookie`(전후 sid 상이), `test_password_change_invalidates_old_sessions`(옛 세션 무효), 라이브 재현.

> 이 항목은 다중에이전트 PM 리뷰 패널이 "보고서가 방어된다고 단언했으나 실제 미작동"으로 지적 → 재현으로 확인 후 수정한 사례다. (허위 방어 주장을 실증으로 교정)

---

## 요약 표

| # | 약점 | 유형(KISA) | 수정 | 검증 테스트 |
|---|---|---|---|---|
| 6.1 | SQL Injection | 입력검증 | 파라미터 바인딩 | test_auth |
| 6.2 | 평문 비밀번호 | 보안기능 | argon2 해시 | test_auth |
| 6.3 | Mass Assignment | 캡슐화 | 컬럼 화이트리스트 | test_auth |
| 6.4 | 저장형 XSS | 입력검증 | 이스케이프/textContent | test_products/users/chat |
| 6.5 | IDOR | 캡슐화 | 소유자 검증 | test_products/chat |
| 6.6 | 송금 경쟁조건 | 시간·상태 | 조건부 UPDATE+트랜잭션 | test_transfer |
| 6.7 | 음수/자기송금 | 입력검증 | 검증+DB CHECK | test_transfer |
| 6.8 | 악성 업로드 | 입력검증 | 화이트리스트+재인코딩 | test_products |
| 6.9 | 신고 남용 | 시간·상태 | 자기/중복 차단 | test_reports |
| 6.10 | CSRF | 보안기능 | CSRFProtect | test_security |
| 6.11 | 세션/전송 | 보안기능 | 서버세션·쿠키·TLS | test_security/reports |
| 6.12 | 정보노출/무차별 | 에러·시간상태 | 에러핸들러·rate limit | test_security |
| 6.13 | 의존성 취약점 | API오용 | 버전 업그레이드 | pip-audit 0건 |
| 6.14 | 관리자 신고-DoS | 시간·상태 | 관리자 자동휴면 예외 | test_reports |
| 6.15a | CSP-인라인 충돌 | 보안기능 | 외부 JS(data-confirm) | test_products |
| 6.15b | 소켓 인가 우회 | 캡슐화 | 소켓 휴면 검증 | test_chat |
| 6.15c | 업로드 파일 고아 | 코드오류 | 삭제/교체 시 파일 정리 | test_products |
| 6.15d | 비번변경 세션 | 보안기능 | 세션 재발급 | test_products |
| 6.16a | 로그인 타이밍 열거 | 보안기능 | 더미 argon2 검증 | test_auth |
| 6.16b | 이미지 압축폭탄 | 입력검증 | 픽셀 상한(25MP) | test_products |
| 6.16c | 가입 UNIQUE 충돌 500 | 에러처리 | IntegrityError 400 처리 | — |
| 6.16d | 잠금 메모리 남용 | 시간·상태 | 만료 항목 정리 | — |
| 6.17 | 세션 고정 | 보안기능 | sid 회전 + epoch 무효화 | test_auth |
