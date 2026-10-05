"""SQLite 持久化：nonce 防重放登记与事件摘要存储。

nonce 以 (station_id, nonce) 为主键，只有在请求通过全部校验、即将被接纳时
才在同一事务内插入；任何失败路径都不会写入 nonce。数据库文件落在 DATA_DIR
（Compose 中挂载为命名卷），因此并发请求与服务重启后均满足"至多成功一次"。
"""
from __future__ import annotations

import sqlite3
import threading

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    station_id TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    used_at    REAL NOT NULL,
    PRIMARY KEY (station_id, nonce)
);
CREATE TABLE IF NOT EXISTS events (
    digest      TEXT PRIMARY KEY,
    station_id  TEXT NOT NULL,
    payload     TEXT NOT NULL,
    received_at REAL NOT NULL
);
"""


class Store:
    """单连接 + 互斥锁：写操作串行化，配合主键约束保证并发下 nonce 至多成功一次。"""

    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._lock = threading.Lock()

    def record_acceptance(self, station_id: str, nonce: str, key_id: str,
                          digest: str, canonical_payload: str, now: float) -> bool:
        """同一事务内登记 nonce 与事件摘要。

        返回 True 表示接纳成功；nonce 冲突返回 False，且事务回滚不留任何记录。
        """
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO nonces (station_id, nonce, key_id, used_at)"
                    " VALUES (?, ?, ?, ?)",
                    (station_id, nonce, key_id, now),
                )
                self._conn.execute(
                    "INSERT OR IGNORE INTO events (digest, station_id, payload, received_at)"
                    " VALUES (?, ?, ?, ?)",
                    (digest, station_id, canonical_payload, now),
                )
                self._conn.commit()
                return True
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return False

    def nonce_seen(self, station_id: str, nonce: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM nonces WHERE station_id = ? AND nonce = ?",
                (station_id, nonce),
            ).fetchone()
            return row is not None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
