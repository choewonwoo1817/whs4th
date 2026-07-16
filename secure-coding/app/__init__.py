"""애플리케이션 팩토리. 보안 기능(CSRF·세션·Rate limit·보안헤더·에러처리)을 전역 적용한다."""
import os
import secrets

from flask import Flask, render_template
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_session import Session
from flask_socketio import SocketIO

from .config import Config
from . import db
from .security import current_user

# 확장 인스턴스 (팩토리에서 init_app)
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)   # 저장소는 config RATELIMIT_STORAGE_URI 에서 로드
server_session = Session()
socketio = SocketIO()


def create_app(config_object=Config, overrides=None):
    app = Flask(__name__)
    app.config.from_object(config_object)
    if overrides:
        app.config.update(overrides)

    # SECRET_KEY: 운영에서는 필수, 개발에서 미설정 시 임시 키(경고)
    if not app.config.get("SECRET_KEY"):
        if app.config["DEBUG"]:
            app.config["SECRET_KEY"] = secrets.token_hex(32)
            app.logger.warning("SECRET_KEY 미설정 — 임시 개발 키 사용. .env 를 생성하세요.")
        else:
            raise RuntimeError("SECRET_KEY 가 설정되지 않았습니다 (운영 환경 필수).")

    # 필요한 디렉터리 준비
    os.makedirs(app.config["SESSION_FILE_DIR"], exist_ok=True)
    os.makedirs(app.config["UPLOAD_DIR"], exist_ok=True)

    # 확장 초기화
    csrf.init_app(app)          # 모든 POST 폼 CSRF 검증 (SR-04)
    server_session.init_app(app)  # 서버 측 세션 (SR-06)
    limiter.init_app(app)       # Rate limiting (SR-10)
    socketio.init_app(app, async_mode="threading")

    app.teardown_appcontext(db.close_db)

    _register_security_headers(app)
    _register_error_handlers(app)

    # 템플릿에서 current_user 사용
    @app.context_processor
    def inject_user():
        return {"current_user": current_user()}

    # 블루프린트
    from .blueprints.main import bp as main_bp
    app.register_blueprint(main_bp)
    from .blueprints.auth import bp as auth_bp
    app.register_blueprint(auth_bp)
    from .blueprints.products import bp as products_bp
    app.register_blueprint(products_bp)
    from .blueprints.users import bp as users_bp
    app.register_blueprint(users_bp)
    from .blueprints.chat import bp as chat_bp   # import 시 SocketIO 핸들러 등록됨
    app.register_blueprint(chat_bp)
    from .blueprints.reports import bp as reports_bp
    app.register_blueprint(reports_bp)
    from .blueprints.transfer import bp as transfer_bp
    app.register_blueprint(transfer_bp)
    from .blueprints.admin import bp as admin_bp
    app.register_blueprint(admin_bp)

    # CLI (init-db, seed-admin)
    from .cli import register_cli
    register_cli(app)

    return app


def _register_security_headers(app):
    @app.after_request
    def set_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # 실시간 채팅 클라이언트(socket.io) 로드를 위해 script-src 에 CDN 허용
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "style-src 'self'; "
            "script-src 'self'; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        return resp


def _register_error_handlers(app):
    # 사용자에겐 일반 메시지, 상세는 서버 로그로만 (SR-09)
    def _render(code, message):
        return render_template("errors/generic.html", code=code, message=message), code

    @app.errorhandler(400)
    def bad_request(e):
        return _render(400, "잘못된 요청입니다.")

    @app.errorhandler(403)
    def forbidden(e):
        return _render(403, "권한이 없습니다.")

    @app.errorhandler(404)
    def not_found(e):
        return _render(404, "페이지를 찾을 수 없습니다.")

    @app.errorhandler(413)
    def too_large(e):
        return _render(413, "업로드 용량이 너무 큽니다.")

    @app.errorhandler(429)
    def too_many(e):
        return _render(429, "요청이 너무 많습니다. 잠시 후 다시 시도하세요.")

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Internal server error")
        return _render(500, "서버 오류가 발생했습니다.")
