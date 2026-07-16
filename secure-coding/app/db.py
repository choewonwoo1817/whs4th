"""SQLite 접근 계층. 모든 쿼리는 파라미터 바인딩(?)만 사용한다 (SR-02)."""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from flask import g, current_app


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def get_db():
    if "db" not in g:
        db_path = current_app.config["DATABASE"]
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        # isolation_level=None → autocommit. 송금 등은 명시적 BEGIN IMMEDIATE 로 원자성 확보 (SR-08).
        conn = sqlite3.connect(db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")   # 동시 쓰기 시 즉시 실패 대신 대기
        g.db = conn
    return g.db


def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query_db(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    if one:
        return rows[0] if rows else None
    return rows


def execute_db(sql, args=()):
    cur = get_db().execute(sql, args)
    lastrow = cur.lastrowid
    cur.close()
    return lastrow


@contextmanager
def transaction():
    """BEGIN IMMEDIATE 트랜잭션. 신고 집계·송금 등 원자적 처리에 사용 (SR-08)."""
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        yield db
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise


def init_db(app):
    """schema.sql 을 실행해 테이블을 생성한다."""
    with app.app_context():
        db = get_db()
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, encoding="utf-8") as f:
            db.executescript(f.read())
