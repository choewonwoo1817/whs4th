"""애플리케이션 설정 — 값은 환경변수(.env)에서 로드한다. 시크릿은 코드에 하드코딩하지 않는다."""
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


def _bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


class Config:
    # --- 핵심 ---
    SECRET_KEY = os.environ.get("SECRET_KEY")
    ENV = os.environ.get("FLASK_ENV", "production")
    DEBUG = ENV == "development"

    # --- 데이터베이스 ---
    DATABASE = os.environ.get("DATABASE", "instance/market.db")

    # --- 세션 (서버 측 저장, SR-06) ---
    SESSION_TYPE = "filesystem"
    SESSION_FILE_DIR = os.environ.get("SESSION_DIR", "flask_session")
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=int(os.environ.get("SESSION_LIFETIME", "3600")))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # HTTPS(ngrok)에서만 Secure 활성. 로컬 http 테스트 시 0. (SR-06)
    SESSION_COOKIE_SECURE = _bool(os.environ.get("SESSION_COOKIE_SECURE"), False)

    # --- 업로드 (SR-13) ---
    UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "uploads")
    MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(2 * 1024 * 1024)))
    # 멀티파트 폼 오버헤드 여유를 둬, 정상 크기 파일은 앱 계층(uploads.py)에서 정확히 검증
    MAX_CONTENT_LENGTH = MAX_UPLOAD_BYTES + 256 * 1024

    # --- 도메인 정책 ---
    REPORT_THRESHOLD = int(os.environ.get("REPORT_THRESHOLD", "5"))
    REGISTER_BONUS = int(os.environ.get("REGISTER_BONUS", "1000"))  # 가입 축하 포인트(송금 데모용)

    # Rate limit 저장소: 기본 인메모리(단일 프로세스). 다중 워커 배포 시 redis:// 등 공유 저장소로 설정
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_INITIAL_PASSWORD = os.environ.get("ADMIN_INITIAL_PASSWORD")
