import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.store import Receipt, Store


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "telemetry.db")
        self.store = Store(self.db)

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_record_once_then_conflict(self):
        ok = self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.0)
        self.assertTrue(ok)
        again = self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 2.0)
        self.assertFalse(again)

    def test_nonce_scoped_per_station(self):
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.0))
        # 同一 nonce 值用于不同站点：允许
        self.assertTrue(
            self.store.record_acceptance("st-2", "nonce-1", "k2", "e" * 64, "{}", 1.0))

    def test_conflict_rolls_back_event_row(self):
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.0))
        self.assertFalse(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "f" * 64, "{}", 2.0))
        # 冲突事务整体回滚：新摘要不应入库
        row = self.store._conn.execute(
            "SELECT COUNT(*) FROM events WHERE digest = ?", ("f" * 64,)).fetchone()
        self.assertEqual(row[0], 0)

    def test_persistence_across_restart(self):
        """关闭并重开数据库（等价于服务重启）后 nonce 仍被拒绝。"""
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1", "d" * 64, "{}", 1.0))
        self.store.close()
        reopened = Store(self.db)
        try:
            self.assertTrue(reopened.nonce_seen("st-1", "nonce-1"))
            self.assertFalse(reopened.record_acceptance(
                "st-1", "nonce-1", "k1", "d" * 64, "{}", 2.0))
        finally:
            reopened.close()
        # 重新打开 self.store 供 tearDown 关闭
        self.store = Store(self.db)

    def test_concurrent_same_nonce_exactly_one_wins(self):
        results = []
        barrier = threading.Barrier(16)

        def worker():
            barrier.wait(timeout=10)
            results.append(self.store.record_acceptance(
                "st-1", "nonce-race", "k1", "d" * 64, "{}", 1.0))

        threads = [threading.Thread(target=worker) for _ in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        self.assertEqual(len(results), 16)
        self.assertEqual(sum(1 for r in results if r), 1)
        self.assertEqual(sum(1 for r in results if not r), 15)

    # ---------- 回执恢复 ----------
    def test_lookup_receipt_returns_first_acceptance(self):
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1",
                                         "d" * 64, "{}", 1234.5))
        receipt = self.store.lookup_receipt("st-1", "nonce-1")
        self.assertEqual(receipt, Receipt(digest="d" * 64, used_at=1234.5))

    def test_lookup_receipt_unknown_nonce_is_none(self):
        self.assertIsNone(self.store.lookup_receipt("st-1", "never-used"))

    def test_lookup_receipt_is_station_scoped(self):
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1",
                                         "d" * 64, "{}", 1.0))
        # 其他站点持有相同 nonce 值时不得看到 st-1 的回执
        self.assertIsNone(self.store.lookup_receipt("st-2", "nonce-1"))

    def test_lookup_receipt_is_read_only(self):
        self.assertTrue(
            self.store.record_acceptance("st-1", "nonce-1", "k1",
                                         "d" * 64, "{}", 1.0))
        self.store.lookup_receipt("st-1", "nonce-1")
        self.store.lookup_receipt("st-1", "nonce-1")
        # 首次接纳记录保持不变
        self.assertEqual(self.store.lookup_receipt("st-1", "nonce-1"),
                         Receipt(digest="d" * 64, used_at=1.0))

    def test_legacy_volume_nonuce_has_null_digest(self):
        """旧数据卷（nonces 无 digest 列）迁移后历史行 digest 为 None。"""
        self.store.close()
        # 以旧版本表结构写入一行防重放记录
        conn = sqlite3.connect(self.db)
        conn.execute(
            "CREATE TABLE nonces_old (station_id TEXT NOT NULL, nonce TEXT NOT NULL,"
            " key_id TEXT NOT NULL, used_at REAL NOT NULL,"
            " PRIMARY KEY (station_id, nonce))")
        conn.execute("INSERT INTO nonces_old VALUES (?, ?, ?, ?)",
                     ("st-1", "legacy-nonce", "k1", 1.0))
        conn.execute("ALTER TABLE nonces RENAME TO nonces_new")
        conn.execute("ALTER TABLE nonces_old RENAME TO nonces")
        conn.execute("DROP TABLE nonces_new")
        conn.commit()
        conn.close()

        reopened = Store(self.db)
        try:
            receipt = reopened.lookup_receipt("st-1", "legacy-nonce")
            self.assertIsNotNone(receipt)
            self.assertIsNone(receipt.digest)  # 旧记录无法恢复
            # 迁移后新接纳仍正常记录摘要
            self.assertTrue(reopened.record_acceptance(
                "st-1", "fresh-nonce", "k1", "d" * 64, "{}", 2.0))
            self.assertEqual(reopened.lookup_receipt("st-1", "fresh-nonce").digest,
                             "d" * 64)
            # 旧 nonce 仍然具备防重放效力
            self.assertFalse(reopened.record_acceptance(
                "st-1", "legacy-nonce", "k1", "e" * 64, "{}", 3.0))
        finally:
            reopened.close()
        self.store = Store(self.db)


if __name__ == "__main__":
    unittest.main()
