-- Tiny Second-hand Shopping Platform — DB 스키마
-- 무결성 제약을 DB 최후 방어선으로 사용 (SR-08, 데이터 무결성)

PRAGMA foreign_keys = ON;

-- 사용자
CREATE TABLE IF NOT EXISTS user (
    id            TEXT PRIMARY KEY,                         -- UUID (열거 완화; 접근제어는 앱에서 별도 강제)
    username      TEXT NOT NULL UNIQUE,                     -- 로그인 아이디 (중복 불가)
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,                            -- argon2 해시 (평문 저장 금지, SR-01)
    bio           TEXT NOT NULL DEFAULT '',
    balance       INTEGER NOT NULL DEFAULT 0 CHECK (balance >= 0),   -- 잔액 음수 불가 (SR-08)
    is_admin      INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0,1)),
    is_dormant    INTEGER NOT NULL DEFAULT 0 CHECK (is_dormant IN (0,1)),
    report_count  INTEGER NOT NULL DEFAULT 0 CHECK (report_count >= 0),
    session_epoch INTEGER NOT NULL DEFAULT 0,               -- 증가 시 기존 세션 전부 무효화(비번 변경 등)
    created_at    TEXT NOT NULL
);

-- 상품
CREATE TABLE IF NOT EXISTS product (
    id           TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    price        INTEGER NOT NULL CHECK (price >= 0),
    image_path   TEXT,
    seller_id    TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,  -- 소유자 (SR-05)
    is_blocked   INTEGER NOT NULL DEFAULT 0 CHECK (is_blocked IN (0,1)),
    report_count INTEGER NOT NULL DEFAULT 0 CHECK (report_count >= 0),
    created_at   TEXT NOT NULL
);

-- 신고 (본인 신고/중복 신고 차단은 앱 + UNIQUE 제약)
CREATE TABLE IF NOT EXISTS report (
    id          TEXT PRIMARY KEY,
    reporter_id TEXT NOT NULL REFERENCES user(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL CHECK (target_type IN ('user','product')),
    target_id   TEXT NOT NULL,
    reason      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    UNIQUE (reporter_id, target_type, target_id)          -- 중복 신고 방지 (SR-12)
);

-- 송금/거래 내역  (테이블명 transaction 은 SQL 예약어라 transfers 사용)
CREATE TABLE IF NOT EXISTS transfers (
    id          TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL REFERENCES user(id),
    receiver_id TEXT NOT NULL REFERENCES user(id),
    amount      INTEGER NOT NULL CHECK (amount > 0),        -- 금액 양수 (SR-08)
    created_at  TEXT NOT NULL,
    CHECK (sender_id <> receiver_id)                        -- 자기 송금 차단 (SR-08)
);

-- 채팅 메시지 (receiver_id NULL = 전체 채팅)
CREATE TABLE IF NOT EXISTS message (
    id          TEXT PRIMARY KEY,
    sender_id   TEXT NOT NULL REFERENCES user(id),
    receiver_id TEXT REFERENCES user(id),
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_product_seller  ON product(seller_id);
CREATE INDEX IF NOT EXISTS idx_product_title   ON product(title);
CREATE INDEX IF NOT EXISTS idx_report_target   ON report(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_transfers_sender ON transfers(sender_id);
CREATE INDEX IF NOT EXISTS idx_message_receiver ON message(receiver_id);
