"""端到端测试：真实 HTTP 服务器 + 临时密钥库 + 临时数据目录。"""
import gzip
import json
import os
import secrets
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import auth
from app.config import Config
from app.payload import stable_digest
from app.server import create_server

EVENTS_PATH = "/api/telemetry/events"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


def _write_keys(path: str) -> dict:
    now = time.time()
    keys = {
        "active": {"key_id": "k-active", "station_id": "st-1",
                   "secret": "secret-active",
                   "not_before": _iso(now - 3600), "not_after": _iso(now + 3600)},
        "expired": {"key_id": "k-expired", "station_id": "st-1",
                    "secret": "secret-expired",
                    "not_before": _iso(now - 7200), "not_after": _iso(now - 3600)},
        "future": {"key_id": "k-future", "station_id": "st-1",
                   "secret": "secret-future",
                   "not_before": _iso(now + 3600), "not_after": _iso(now + 7200)},
        "other": {"key_id": "k-other", "station_id": "st-2",
                  "secret": "secret-other",
                  "not_before": _iso(now - 3600), "not_after": _iso(now + 3600)},
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"keys": list(keys.values())}, fh)
    return keys


class ServerFixture:
    def __init__(self, data_dir: str, keys_file: str):
        config = Config(host="127.0.0.1", port=0, keys_file=keys_file,
                        data_dir=data_dir)
        self.httpd = create_server(config)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd.gateway.store.close()
        self.thread.join(timeout=5)


def post(url: str, raw: bytes, headers: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url + EVENTS_PATH, data=raw,
                                 headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def get(url: str, path: str) -> tuple[int, dict]:
    with urllib.request.urlopen(url + path, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def signed_headers(key: dict, timestamp: int, nonce: str, raw: bytes,
                   station: str | None = None, secret: str | None = None) -> dict:
    station = station or key["station_id"]
    signature = auth.sign_request(secret or key["secret"], "POST", EVENTS_PATH,
                                  station, key["key_id"], str(timestamp), nonce, raw)
    return {
        "X-Station-Id": station,
        "X-Key-Id": key["key_id"],
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Signature": signature,
    }


def make_payload(station: str) -> dict:
    return {
        "station_id": station,
        "sent_at": int(time.time()),
        "events": [
            {"event_id": "evt-" + secrets.token_hex(4),
             "measured_at": int(time.time()) - 5,
             "dose_usv_h": 0.117, "instrument": "gm-1"},
        ],
    }


def tamper_signature(sig: str) -> str:
    """保证篡改后的签名与原文不同（首字符换成另一个 Base64 字符）。"""
    return ("A" if sig[0] != "A" else "B") + sig[1:]


class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys_file = os.path.join(self.tmp.name, "keys.json")
        self.keys = _write_keys(self.keys_file)
        self.data_dir = os.path.join(self.tmp.name, "data")
        self.server = ServerFixture(self.data_dir, self.keys_file)
        self.key = self.keys["active"]

    def tearDown(self):
        self.server.stop()
        self.tmp.cleanup()

    def _nonce(self) -> str:
        return secrets.token_hex(12)

    def _send_valid(self, payload: dict | None = None, nonce: str | None = None):
        payload = payload if payload is not None else make_payload("st-1")
        raw = json.dumps(payload).encode()
        nonce = nonce or self._nonce()
        headers = signed_headers(self.key, int(time.time()), nonce, raw)
        return post(self.server.url, raw, headers), raw, headers, payload

    # ---------- 健康检查 ----------
    def test_healthz(self):
        status, body = get(self.server.url, "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")

    # ---------- 成功路径 ----------
    def test_accept_json_202_with_stable_digest(self):
        (status, body), _, _, payload = self._send_valid()
        self.assertEqual(status, 202)
        self.assertEqual(body["status"], "accepted")
        expected, _ = stable_digest(payload)
        self.assertEqual(body["event_digest"], expected)

    def test_accept_gzip_same_digest(self):
        payload = make_payload("st-1")
        plain = json.dumps(payload).encode()
        compressed = gzip.compress(plain)
        headers = signed_headers(self.key, int(time.time()), self._nonce(),
                                 compressed)
        headers["Content-Encoding"] = "gzip"
        status, body = post(self.server.url, compressed, headers)
        self.assertEqual(status, 202)
        expected, _ = stable_digest(payload)
        self.assertEqual(body["event_digest"], expected)

    def test_gzip_without_content_encoding_sniffed(self):
        payload = make_payload("st-1")
        compressed = gzip.compress(json.dumps(payload).encode())
        headers = signed_headers(self.key, int(time.time()), self._nonce(),
                                 compressed)
        status, _ = post(self.server.url, compressed, headers)
        self.assertEqual(status, 202)

    # ---------- 签名 ----------
    def test_bad_signature_401(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw)
        headers["X-Signature"] = tamper_signature(headers["X-Signature"])
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "SIGNATURE_INVALID")

    def test_wrong_secret_401(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw,
                                 secret="not-the-secret")
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "SIGNATURE_INVALID")

    def test_unknown_key_401(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw)
        headers["X-Key-Id"] = "no-such-key"
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "KEY_UNKNOWN")

    # ---------- 密钥有效期 ----------
    def test_expired_key_403(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.keys["expired"], int(time.time()),
                                 self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "KEY_EXPIRED")

    def test_not_yet_valid_key_403(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.keys["future"], int(time.time()),
                                 self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "KEY_EXPIRED")

    def test_key_station_mismatch_403(self):
        raw = json.dumps(make_payload("st-2")).encode()
        # k-other 属于 st-2，却用于 st-1 的报文头
        headers = signed_headers(self.keys["other"], int(time.time()),
                                 self._nonce(), raw, station="st-1")
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"]["code"], "KEY_STATION_MISMATCH")

    # ---------- 时间窗 ----------
    def test_stale_timestamp_401(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()) - 3600,
                                 self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "TIMESTAMP_OUT_OF_RANGE")

    def test_future_timestamp_401(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()) + 3600,
                                 self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "TIMESTAMP_OUT_OF_RANGE")

    # ---------- 畸形载荷 ----------
    def test_malformed_payload_400(self):
        raw = b'{"station_id": "st-1", "events": ['
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "PAYLOAD_MALFORMED")

    def test_payload_station_mismatch_400(self):
        raw = json.dumps(make_payload("st-2")).encode()
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "PAYLOAD_MALFORMED")

    # ---------- 失败不占用 nonce ----------
    def test_failed_request_does_not_consume_nonce(self):
        nonce = self._nonce()
        # 1) 签名错误 -> 401
        raw = json.dumps(make_payload("st-1")).encode()
        bad = signed_headers(self.key, int(time.time()), nonce, raw)
        bad["X-Signature"] = tamper_signature(bad["X-Signature"])
        status, _ = post(self.server.url, raw, bad)
        self.assertEqual(status, 401)
        # 2) 同一 nonce 修正签名后 -> 202
        good = signed_headers(self.key, int(time.time()), nonce, raw)
        status, _ = post(self.server.url, raw, good)
        self.assertEqual(status, 202)

    def test_malformed_payload_does_not_consume_nonce(self):
        nonce = self._nonce()
        bad_raw = b'{"station_id": "st-1", broken'
        headers = signed_headers(self.key, int(time.time()), nonce, bad_raw)
        status, _ = post(self.server.url, bad_raw, headers)
        self.assertEqual(status, 400)
        # 同一 nonce 换上合法载荷 -> 202
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()), nonce, raw)
        status, _ = post(self.server.url, raw, headers)
        self.assertEqual(status, 202)

    # ---------- 防重放 ----------
    def test_replay_409(self):
        (status, _), raw, headers, _ = self._send_valid()
        self.assertEqual(status, 202)
        status, body = post(self.server.url, raw, headers)  # 原样重放
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "NONCE_REPLAY")

    def test_replay_survives_restart(self):
        (status, _), raw, headers, _ = self._send_valid()
        self.assertEqual(status, 202)
        # 重启服务（同一数据目录）
        self.server.stop()
        self.server = ServerFixture(self.data_dir, self.keys_file)
        status, body = post(self.server.url, raw, headers)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"]["code"], "NONCE_REPLAY")

    def test_concurrent_same_nonce_exactly_one_accepted(self):
        raw = json.dumps(make_payload("st-1")).encode()
        headers = signed_headers(self.key, int(time.time()), self._nonce(), raw)
        barrier = threading.Barrier(16)

        def worker():
            barrier.wait(timeout=10)
            return post(self.server.url, raw, headers)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: worker(), range(16)))
        codes = [s for s, _ in results]
        self.assertEqual(codes.count(202), 1, f"codes={codes}")
        self.assertEqual(codes.count(409), 15, f"codes={codes}")

    # ---------- 其他 ----------
    def test_missing_headers_400(self):
        status, body = post(self.server.url, b"{}", {})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "MALFORMED_HEADERS")

    def test_unknown_path_404(self):
        req = urllib.request.Request(self.server.url + "/nope", data=b"{}",
                                     method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            self.fail("expected HTTPError")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 404)


if __name__ == "__main__":
    unittest.main()
