"""Flask CLI 명령: init-db, seed-admin."""
import uuid

import click

from .db import init_db as _init_db, query_db, execute_db, now_iso
from .security import hash_password


def register_cli(app):
    @app.cli.command("init-db")
    def init_db_command():
        """DB 스키마 생성."""
        _init_db(app)
        click.echo("DB 초기화 완료.")

    @app.cli.command("seed-admin")
    def seed_admin_command():
        """최초 관리자 계정 생성 (.env 의 ADMIN_* 사용)."""
        with app.app_context():
            username = app.config["ADMIN_USERNAME"]
            password = app.config.get("ADMIN_INITIAL_PASSWORD")
            if not password:
                click.echo("ADMIN_INITIAL_PASSWORD 미설정 (.env 확인).")
                return
            if query_db("SELECT id FROM user WHERE username = ?", (username,), one=True):
                click.echo(f"이미 관리자 '{username}' 존재. 건너뜀.")
                return
            execute_db(
                "INSERT INTO user (id, username, display_name, password_hash, is_admin, created_at) "
                "VALUES (?, ?, ?, ?, 1, ?)",
                (str(uuid.uuid4()), username, "관리자", hash_password(password), now_iso()),
            )
            click.echo(f"관리자 계정 생성 완료: {username}")
