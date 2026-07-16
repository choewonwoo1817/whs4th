# Tiny Second-hand Shopping Platform

WhiteHat School **시큐어 코딩** 과제 — 보안 약점을 최소화한 중고거래 플랫폼.

Flask + Flask-SocketIO + SQLite 기반. 회원가입/로그인, 상품 등록·검색, 실시간(전체/1:1) 채팅,
신고·임계치 자동 차단, 포인트 송금, 관리자 기능을 제공하며, 각 기능은 시큐어 코딩 원칙에 따라 구현되었습니다.

> 개발 전 과정 보고서: [`보고서/`](보고서/) (요구사항 분석 → 시스템 설계 → 구현 → 테스트 → 유지보수 → 보안약점 Before/After)

---

## 요구 환경

- Python 3.12
- Linux(Ubuntu) 권장 — WSL/VMware/VirtualBox 등 (macOS/Windows도 동작)
- (선택) ngrok — 외부 HTTPS 노출

## 1. 설치

### miniconda 사용 시
```bash
conda create -n secure-coding python=3.12 -y
conda activate secure-coding
pip install -r requirements.txt
```

### venv 사용 시
```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 2. 환경변수(.env) 설정

`.env.example`을 복사해 `.env`를 만들고 값을 채웁니다. (`.env`는 커밋 금지)
```bash
cp .env.example .env
# SECRET_KEY 무작위 생성:
python -c "import secrets; print(secrets.token_hex(32))"
# 출력값을 .env 의 SECRET_KEY 에 붙여넣고, ADMIN_INITIAL_PASSWORD 도 지정
```

주요 항목:
| 변수 | 설명 |
|---|---|
| `SECRET_KEY` | 세션 서명 키(무작위 필수) |
| `FLASK_ENV` | `development` 또는 `production`(운영은 DEBUG off) |
| `SESSION_COOKIE_SECURE` | HTTPS(ngrok)면 `1`, 로컬 http면 `0` |
| `REPORT_THRESHOLD` | 신고 임계치(기본 5) |
| `ADMIN_USERNAME` / `ADMIN_INITIAL_PASSWORD` | 최초 관리자 계정 |

## 3. DB 초기화 & 관리자 생성
```bash
flask --app run init-db      # 테이블 생성
flask --app run seed-admin   # .env 의 관리자 계정 생성
```

## 4. 실행
```bash
python run.py                # http://localhost:5000
```
> macOS에서 `Address already in use`(5000 포트를 AirPlay Receiver가 점유)가 나오면 다른 포트로 실행:
> ```bash
> PORT=5001 python run.py    # http://localhost:5001
> ```
> (또는 시스템 설정에서 'AirPlay 수신 모드'를 끄면 됩니다.)

### (선택) 외부 노출 — ngrok
```bash
ngrok config add-authtoken <YOUR_TOKEN>   # 최초 1회
ngrok http 5000
```
ngrok HTTPS 주소로 접속 시 `.env`에서 `SESSION_COOKIE_SECURE=1` 권장.

## 5. 테스트
```bash
pip install pytest
pytest -q                    # 85개 통과
```

## 6. 보안 점검 (SAST + 의존성)
```bash
pip install bandit pip-audit
bandit -r app/                  # 소스 정적분석 → High/Medium/Low 0
pip-audit -r requirements.txt   # 의존성 취약점 → No known vulnerabilities found
```

---

## 프로젝트 구조
```
app/
  __init__.py        앱 팩토리(CSRF·세션·Rate limit·보안헤더·에러처리)
  config.py          환경변수 설정
  db.py              SQLite 접근계층(파라미터 바인딩·트랜잭션)
  security.py        argon2 해시·인증 데코레이터·입력검증
  uploads.py         이미지 업로드 검증·재인코딩
  schema.sql         DB 스키마(무결성 제약)
  blueprints/        auth/products/users/chat/reports/transfer/admin
  templates/ static/ 화면·JS·CSS
tests/               pytest (85개)
보고서/               개발 전 과정 보고서(01~06)
run.py               진입점
requirements.txt     의존성(안전 버전 고정)
```

## 보안 요약

입력 검증(파라미터 바인딩·서버측 검증), argon2 비밀번호 해시, CSRF, XSS 방어(자동 이스케이프·textContent),
접근제어(소유자/관리자 검증), 원자적 송금(더블스펜딩 방지), 파일 업로드 검증(재인코딩·SVG 차단),
신고 남용 방지, 서버 측 세션·보안 헤더, 의존성 취약점 관리. 상세는 [`보고서/06_보안약점_before_after.md`](보고서/06_보안약점_before_after.md).
