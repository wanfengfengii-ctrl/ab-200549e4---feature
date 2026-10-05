"""对运行中的网关执行端到端冒烟：签名、压缩、时间窗、密钥有效期、防重放（含并发）、
回执恢复（200/404/409、签名路径区分、旧数据卷、并发重试）。"""
from __future__ import annotations

import gzip
import json
import os
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from app import auth
from app.keystore import KeyStore
from app.payload import stable_digest

EVENTS_PATH = "/api/telemetry/events"
RECOVER_PATH = "/api/telemetry/events/recover"


class SmokeFailure(Exception):
    pass


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def _post(base_url: str, raw: bytes, headers: dict,
          path: str = EVENTS_PATH, timeout: float = 10.0) -> tuple[int, dict]:
    req = urllib.request.Request(base_url + path, data=raw,
                                 headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _headers_for(key, timestamp: int, nonce: str, raw: bytes,
                 secret: str | None = None,
                 path: str = EVENTS_PATH) -> dict:
    signature = auth.sign_request(secret or key.secret, "POST", path,
                                  key.station_id, key.key_id, str(timestamp),
                                  nonce, raw)
    return {
        "X-Station-Id": key.station_id,
        "X-Key-Id": key.key_id,
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Signature": signature,
    }


def _payload(station_id: str) -> dict:
    return {
        "station_id": station_id,
        "sent_at": int(time.time()),
        "events": [
            {"event_id": "evt-" + secrets.token_hex(4),
             "measured_at": int(time.time()) - 5,
             "dose_usv_h": 0.117, "instrument": "gm-1"},
        ],
    }


def _nonce() -> str:
    return secrets.token_hex(12)


def _tamper(sig: str) -> str:
    """保证篡改后的签名与原文不同（首字符换成另一个 Base64 字符）。"""
    return ("A" if sig[0] != "A" else "B") + sig[1:]


def run_smoke(base_url: str, keys_file: str) -> bool:
    keystore = KeyStore.load(keys_file)
    active = keystore.get("test-key-1")
    expired = keystore.get("test-key-expired")
    future = keystore.get("test-key-future")
    if not (active and expired and future):
        print("[smoke] keys file must define test-key-1 / test-key-expired / "
              "test-key-future")
        return False

    ctx: dict = {}

    # ---------- 签名与压缩 ----------
    def case_happy_json():
        payload = _payload(active.station_id)
        raw = json.dumps(payload).encode()
        headers = _headers_for(active, int(time.time()), _nonce(), raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 202, f"expected 202, got {status}: {body}")
        expected, _ = stable_digest(payload)
        _expect(body.get("event_digest") == expected,
                f"digest mismatch: {body.get('event_digest')} != {expected}")
        ctx["json"] = (raw, headers, expected)

    def case_happy_gzip_same_digest():
        raw_plain = json.dumps(_payload(active.station_id)).encode()
        compressed = gzip.compress(raw_plain)
        headers = _headers_for(active, int(time.time()), _nonce(), compressed)
        headers["Content-Encoding"] = "gzip"
        status, body = _post(base_url, compressed, headers)
        _expect(status == 202, f"expected 202, got {status}: {body}")
        expected, _ = stable_digest(json.loads(raw_plain.decode()))
        _expect(body.get("event_digest") == expected,
                "gzip payload digest should equal plain-json digest")

    def case_gzip_magic_without_header():
        compressed = gzip.compress(json.dumps(_payload(active.station_id)).encode())
        headers = _headers_for(active, int(time.time()), _nonce(), compressed)
        status, body = _post(base_url, compressed, headers)
        _expect(status == 202, f"expected 202, got {status}: {body}")

    def case_bad_signature():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), _nonce(), raw)
        headers["X-Signature"] = _tamper(headers["X-Signature"])
        status, body = _post(base_url, raw, headers)
        _expect(status == 401 and body["error"]["code"] == "SIGNATURE_INVALID",
                f"expected 401 SIGNATURE_INVALID, got {status}: {body}")

    def case_wrong_secret():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), _nonce(), raw,
                               secret="definitely-wrong-secret")
        status, body = _post(base_url, raw, headers)
        _expect(status == 401 and body["error"]["code"] == "SIGNATURE_INVALID",
                f"expected 401 SIGNATURE_INVALID, got {status}: {body}")

    def case_unknown_key():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), _nonce(), raw)
        headers["X-Key-Id"] = "no-such-key"
        status, body = _post(base_url, raw, headers)
        _expect(status == 401 and body["error"]["code"] == "KEY_UNKNOWN",
                f"expected 401 KEY_UNKNOWN, got {status}: {body}")

    # ---------- 密钥有效期与时间窗 ----------
    def case_expired_key():
        raw = json.dumps(_payload(expired.station_id)).encode()
        headers = _headers_for(expired, int(time.time()), _nonce(), raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 403 and body["error"]["code"] == "KEY_EXPIRED",
                f"expected 403 KEY_EXPIRED, got {status}: {body}")

    def case_not_yet_valid_key():
        raw = json.dumps(_payload(future.station_id)).encode()
        headers = _headers_for(future, int(time.time()), _nonce(), raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 403 and body["error"]["code"] == "KEY_EXPIRED",
                f"expected 403 KEY_EXPIRED, got {status}: {body}")

    def case_stale_timestamp():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()) - 3600, _nonce(), raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 401 and body["error"]["code"] == "TIMESTAMP_OUT_OF_RANGE",
                f"expected 401 TIMESTAMP_OUT_OF_RANGE, got {status}: {body}")

    def case_future_timestamp():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()) + 3600, _nonce(), raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 401 and body["error"]["code"] == "TIMESTAMP_OUT_OF_RANGE",
                f"expected 401 TIMESTAMP_OUT_OF_RANGE, got {status}: {body}")

    # ---------- 畸形载荷 & 失败不占 nonce ----------
    def case_malformed_payload_then_retry_same_nonce():
        nonce = _nonce()
        bad_raw = b'{"station_id": "' + active.station_id.encode() + b'", broken'
        headers = _headers_for(active, int(time.time()), nonce, bad_raw)
        status, body = _post(base_url, bad_raw, headers)
        _expect(status == 400 and body["error"]["code"] == "PAYLOAD_MALFORMED",
                f"expected 400 PAYLOAD_MALFORMED, got {status}: {body}")
        # 失败请求不得占用 nonce：同一 nonce 换上合法载荷必须成功
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), nonce, raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 202,
                f"nonce consumed by failed request! got {status}: {body}")

    def case_bad_signature_does_not_consume_nonce():
        nonce = _nonce()
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), nonce, raw)
        headers["X-Signature"] = _tamper(headers["X-Signature"])
        status, _ = _post(base_url, raw, headers)
        _expect(status == 401, f"expected 401, got {status}")
        headers = _headers_for(active, int(time.time()), nonce, raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 202,
                f"nonce consumed by failed request! got {status}: {body}")

    # ---------- 防重放 ----------
    def case_replay_rejected():
        raw, headers, _ = ctx["json"]
        status, body = _post(base_url, raw, headers)  # 原样重放首个成功请求
        _expect(status == 409 and body["error"]["code"] == "NONCE_REPLAY",
                f"expected 409 NONCE_REPLAY, got {status}: {body}")

    def case_concurrent_replay_exactly_one_wins():
        raw = json.dumps(_payload(active.station_id)).encode()
        headers = _headers_for(active, int(time.time()), _nonce(), raw)
        barrier = threading.Barrier(16)

        def worker():
            barrier.wait(timeout=10)
            return _post(base_url, raw, headers)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: worker(), range(16)))
        codes = [s for s, _ in results]
        _expect(codes.count(202) == 1,
                f"expected exactly one 202, got codes={codes}")
        _expect(codes.count(409) == 15,
                f"expected fifteen 409, got codes={codes}")

    # ---------- 回执恢复 ----------
    def case_recover_after_accept():
        payload = _payload(active.station_id)
        raw = json.dumps(payload).encode()
        nonce = _nonce()
        headers = _headers_for(active, int(time.time()), nonce, raw)
        status, accepted = _post(base_url, raw, headers)
        _expect(status == 202, f"expected 202, got {status}: {accepted}")
        # 模拟 202 丢失：新时间戳重新签名，内容完全一致
        rec_headers = _headers_for(active, int(time.time()), nonce, raw,
                                   path=RECOVER_PATH)
        status, body = _post(base_url, raw, rec_headers, path=RECOVER_PATH)
        _expect(status == 200 and body.get("status") == "recovered",
                f"expected 200 recovered, got {status}: {body}")
        _expect(body.get("event_digest") == accepted["event_digest"],
                "recovered digest must equal first acceptance digest")
        _expect(body.get("received_at") == accepted["received_at"],
                "recovered received_at must equal first acceptance time")
        ctx["recover"] = (payload, raw, nonce, accepted)

    def case_recover_idempotent():
        _, raw, nonce, accepted = ctx["recover"]
        for _ in range(3):
            headers = _headers_for(active, int(time.time()), nonce, raw,
                                   path=RECOVER_PATH)
            status, body = _post(base_url, raw, headers, path=RECOVER_PATH)
            _expect(status == 200 and body.get("status") == "recovered",
                    f"expected 200 recovered, got {status}: {body}")
        # 恢复不改写 nonce：原接纳接口仍判重放
        headers = _headers_for(active, int(time.time()), nonce, raw)
        status, body = _post(base_url, raw, headers)
        _expect(status == 409 and body["error"]["code"] == "NONCE_REPLAY",
                f"expected 409 NONCE_REPLAY, got {status}: {body}")

    def case_recover_gzip_same_content():
        payload = _payload(active.station_id)
        plain = json.dumps(payload).encode()
        nonce = _nonce()
        status, accepted = _post(
            base_url, plain, _headers_for(active, int(time.time()), nonce, plain))
        _expect(status == 202, f"expected 202, got {status}: {accepted}")
        compressed = gzip.compress(plain)
        headers = _headers_for(active, int(time.time()), nonce, compressed,
                               path=RECOVER_PATH)
        headers["Content-Encoding"] = "gzip"
        status, body = _post(base_url, compressed, headers, path=RECOVER_PATH)
        _expect(status == 200 and body.get("event_digest") == accepted["event_digest"],
                f"gzip recovery failed: {status} {body}")

    def case_recover_unknown_nonce_404_and_no_side_effect():
        payload = _payload(active.station_id)
        raw = json.dumps(payload).encode()
        nonce = _nonce()
        headers = _headers_for(active, int(time.time()), nonce, raw,
                               path=RECOVER_PATH)
        status, body = _post(base_url, raw, headers, path=RECOVER_PATH)
        _expect(status == 404 and body["error"]["code"] == "RECEIPT_NOT_FOUND",
                f"expected 404 RECEIPT_NOT_FOUND, got {status}: {body}")
        # 404 不得登记 nonce：随后正常接纳必须成功
        status, body = _post(
            base_url, raw, _headers_for(active, int(time.time()), nonce, raw))
        _expect(status == 202, f"404 recovery consumed the nonce! got {status}: {body}")

    def case_recover_mismatch_409():
        _, _, nonce, _ = ctx["recover"]
        other = _payload(active.station_id)  # 不同事件内容
        raw = json.dumps(other).encode()
        headers = _headers_for(active, int(time.time()), nonce, raw,
                               path=RECOVER_PATH)
        status, body = _post(base_url, raw, headers, path=RECOVER_PATH)
        _expect(status == 409 and body["error"]["code"] == "RECEIPT_MISMATCH",
                f"expected 409 RECEIPT_MISMATCH, got {status}: {body}")

    def case_recover_wrong_signature_path_401():
        _, raw, nonce, _ = ctx["recover"]
        # 用接纳路径签名请求恢复接口，必须失败（两路径签名不可互换）
        headers = _headers_for(active, int(time.time()), nonce, raw,
                               path=EVENTS_PATH)
        status, body = _post(base_url, raw, headers, path=RECOVER_PATH)
        _expect(status == 401 and body["error"]["code"] == "SIGNATURE_INVALID",
                f"expected 401 SIGNATURE_INVALID, got {status}: {body}")

    def case_recover_cross_station_not_leaked():
        # station-alpha 接纳的 nonce，station-beta 用自己的有效密钥恢复 -> 404
        _, _, nonce, _ = ctx["recover"]
        beta = keystore.get("test-key-2")
        _expect(beta is not None, "keys file must define test-key-2")
        payload = {"station_id": beta.station_id, "sent_at": int(time.time()),
                   "events": [{"event_id": "evt-cross",
                               "measured_at": int(time.time()) - 5,
                               "dose_usv_h": 0.2}]}
        raw = json.dumps(payload).encode()
        headers = _headers_for(beta, int(time.time()), nonce, raw,
                               path=RECOVER_PATH)
        status, body = _post(base_url, raw, headers, path=RECOVER_PATH)
        _expect(status == 404 and body["error"]["code"] == "RECEIPT_NOT_FOUND",
                f"cross-station recovery must be 404, got {status}: {body}")

    def case_recover_legacy_volume_unavailable():
        # 接纳后直接把 SQLite 中该行 digest 抹掉，模拟旧版本卷只有防重放记录
        payload = _payload(active.station_id)
        raw = json.dumps(payload).encode()
        nonce = _nonce()
        status, _ = _post(
            base_url, raw, _headers_for(active, int(time.time()), nonce, raw))
        _expect(status == 202, f"expected 202, got {status}")
        db_path = os.path.join(os.environ.get("DATA_DIR", "/data"), "telemetry.db")
        if not os.path.exists(db_path):
            _expect(False, f"database not found at {db_path} (legacy case needs "
                           "shared DATA_DIR)")
        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                "UPDATE nonces SET digest = NULL WHERE station_id = ? AND nonce = ?",
                (active.station_id, nonce))
            conn.commit()
        finally:
            conn.close()
        headers = _headers_for(active, int(time.time()), nonce, raw,
                               path=RECOVER_PATH)
        status, body = _post(base_url, raw, headers, path=RECOVER_PATH)
        _expect(status == 409 and body["error"]["code"] == "RECEIPT_UNAVAILABLE",
                f"expected 409 RECEIPT_UNAVAILABLE, got {status}: {body}")
        # 旧记录仍有防重放效力
        status, body = _post(
            base_url, raw, _headers_for(active, int(time.time()), nonce, raw))
        _expect(status == 409 and body["error"]["code"] == "NONCE_REPLAY",
                f"legacy nonce must still replay-guard, got {status}: {body}")

    def case_concurrent_lost_202_retries_single_acceptance():
        # 202 丢失后 16 路并发重试：8 路原接纳接口（409）+ 8 路恢复接口（200）
        raw = json.dumps(_payload(active.station_id)).encode()
        nonce = _nonce()
        status, accepted = _post(
            base_url, raw, _headers_for(active, int(time.time()), nonce, raw))
        _expect(status == 202, f"expected 202, got {status}")
        barrier = threading.Barrier(16)

        def worker(i):
            barrier.wait(timeout=10)
            if i % 2 == 0:
                return _post(base_url, raw,
                             _headers_for(active, int(time.time()), nonce, raw))
            return _post(base_url, raw,
                         _headers_for(active, int(time.time()), nonce, raw,
                                      path=RECOVER_PATH),
                         path=RECOVER_PATH)

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(worker, range(16)))
        codes = [s for s, _ in results]
        _expect(codes.count(200) == 8, f"expected eight 200, got codes={codes}")
        _expect(codes.count(409) == 8, f"expected eight 409, got codes={codes}")
        # 回执仍是首次接纳的结果
        headers = _headers_for(active, int(time.time()), nonce, raw,
                               path=RECOVER_PATH)
        status, body = _post(base_url, raw, headers, path=RECOVER_PATH)
        _expect(status == 200
                and body.get("event_digest") == accepted["event_digest"]
                and body.get("received_at") == accepted["received_at"],
                f"receipt altered by retries: {status} {body}")

    cases = [
        ("happy_json_202_stable_digest", case_happy_json),
        ("happy_gzip_same_digest", case_happy_gzip_same_digest),
        ("gzip_magic_without_header", case_gzip_magic_without_header),
        ("bad_signature_401", case_bad_signature),
        ("wrong_secret_401", case_wrong_secret),
        ("unknown_key_401", case_unknown_key),
        ("expired_key_403", case_expired_key),
        ("not_yet_valid_key_403", case_not_yet_valid_key),
        ("stale_timestamp_401", case_stale_timestamp),
        ("future_timestamp_401", case_future_timestamp),
        ("malformed_payload_400_then_retry_same_nonce",
         case_malformed_payload_then_retry_same_nonce),
        ("bad_signature_does_not_consume_nonce",
         case_bad_signature_does_not_consume_nonce),
        ("replay_409", case_replay_rejected),
        ("concurrent_replay_exactly_one_wins", case_concurrent_replay_exactly_one_wins),
        ("recover_200_after_accept", case_recover_after_accept),
        ("recover_idempotent_and_nonce_unchanged", case_recover_idempotent),
        ("recover_gzip_same_content_200", case_recover_gzip_same_content),
        ("recover_unknown_nonce_404_no_side_effect",
         case_recover_unknown_nonce_404_and_no_side_effect),
        ("recover_mismatch_409", case_recover_mismatch_409),
        ("recover_wrong_signature_path_401", case_recover_wrong_signature_path_401),
        ("recover_cross_station_not_leaked", case_recover_cross_station_not_leaked),
        ("recover_legacy_volume_unavailable_409", case_recover_legacy_volume_unavailable),
        ("concurrent_lost_202_retries_single_acceptance",
         case_concurrent_lost_202_retries_single_acceptance),
    ]

    all_ok = True
    for name, fn in cases:
        try:
            fn()
            print(f"[smoke]   PASS {name}")
        except Exception as exc:  # noqa: BLE001 - 冒烟需要汇总所有失败
            all_ok = False
            print(f"[smoke]   FAIL {name}: {exc}")
    return all_ok
