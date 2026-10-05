"""SQLite 持久化：nonce 防重放登记与事件摘要存储。

nonce 以 (station_id, nonce) 为主键，只有在请求通过全部校验、即将被接纳时
才在同一事务内插入；任何失败路径都不会写入 nonce。数据库文件落在 DATA_DIR
（Compose 中挂载为命名卷），因此并发请求与服务重启后均满足"至多成功一次"。

nonces.digest 记录该 nonce 首次接纳时的稳定事件摘要，供恢复接口
（POST /api/telemetry/events/recover）核对。旧版本数据卷的 nonces 表没有
digest 列，启动时自动补列，历史行该列为 NULL —— 表示"仅有防重放记录、
无法恢复回执"。
"""
from __future__ import annotations

import sqlite3
import threading
from typing import NamedTuple

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces (
    station_id TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    used_at    REAL NOT NULL,
    digest     TEXT,
    PRIMARY KEY (station_id, nonce)
);
CREATE TABLE IF NOT EXISTS events (
    digest      TEXT PRIMARY KEY,
    station_id  TEXT NOT NULL,
    payload     TEXT NOT NULL,
    received_at REAL NOT NULL
);
"""


class Receipt(NamedTuple):
    """某 (station_id, nonce) 的首次接纳回执。

    digest 为 None 表示记录来自旧数据卷：只登记了防重放 nonce，
    没有保存事件摘要，无法核对/恢复。
    """

    digest: str | None
    used_at: float


class Store:
    """单连接 + 互斥锁：写操作串行化，配合主键约束保证并发下 nonce 至多成功一次。"""

    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        self._migrate_legacy_schema()
        self._conn.commit()
        self._lock = threading.Lock()

    def _migrate_legacy_schema(self) -> None:
        """旧数据卷的 nonces 表缺少 digest 列时补列（历史行留 NULL）。"""
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(nonces)")}
        if "digest" not in columns:
            self._conn.execute("ALTER TABLE nonces ADD COLUMN digest TEXT")

    def record_acceptance(self, station_id: str, nonce: str, key_id: str,
                          digest: str, canonical_payload: str, now: float) -> bool:
        """同一事务内登记 nonce（含事件摘要）与事件内容。

        返回 True 表示接纳成功；nonce 冲突返回 False，且事务回滚不留任何记录。
        """
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO nonces (station_id, nonce, key_id, used_at, digest)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (station_id, nonce, key_id, now, digest),
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

    def lookup_receipt(self, station_id: str, nonce: str) -> Receipt | None:
        """按 (站点, nonce) 只读查询首次接纳回执，不写入也不改写任何记录。

        返回 None 表示该站点从未成功接纳过此 nonce；
        返回 Receipt(digest=None, ...) 表示旧数据卷只有防重放记录。
        查询严格按站点隔离，不会泄露其他站点的结果。
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT digest, used_at FROM nonces"
                " WHERE station_id = ? AND nonce = ?",
                (station_id, nonce),
            ).fetchone()
        if row is None:
            return None
        return Receipt(digest=row[0], used_at=row[1])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
