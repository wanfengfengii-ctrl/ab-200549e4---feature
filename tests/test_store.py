import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.store import Store


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


if __name__ == "__main__":
    unittest.main()
