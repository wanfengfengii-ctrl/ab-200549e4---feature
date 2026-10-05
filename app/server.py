"""HTTP 网关：POST /api/telemetry/events 的验签、解压、校验与防重放接纳。

处理顺序（严格保证"先验签，再解压/校验"，且失败请求不占用 nonce）：

    1. 必需请求头齐全且格式合法          -> 400 MALFORMED_HEADERS
    2. 读取原始请求体（带大小上限）       -> 411 / 413
    3. 发送时刻与当前时间相差 <= 5 分钟   -> 401 TIMESTAMP_OUT_OF_RANGE
    4. 密钥已登记、在有效期内、归属本站点 -> 401 KEY_UNKNOWN / 403 KEY_EXPIRED / 403 KEY_STATION_MISMATCH
    5. HMAC-SHA256 签名验证              -> 401 SIGNATURE_INVALID
    6. 解压 + JSON 解析 + 事件校验        -> 400 PAYLOAD_MALFORMED / 415 UNSUPPORTED_ENCODING
    7. 事务性登记 nonce（唯一约束）       -> 409 NONCE_REPLAY
    8. 接纳                              -> 202 + 稳定事件摘要
"""
from __future__ import annotations

import json
import logging
import os
import re
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import auth
from . import payload as payload_mod
from .config import Config
from .errors import ApiError
from .keystore import KeyStore
from .store import Store

log = logging.getLogger("gateway")

EVENTS_PATH = "/api/telemetry/events"
_NONCE_RE = re.compile(r"[A-Za-z0-9._~-]{8,128}")


class Gateway:
    """聚合配置、密钥库与持久化存储，挂载到 HTTP server 实例上。"""

    def __init__(self, config: Config, keystore: KeyStore, store: Store):
        self.config = config
        self.keystore = keystore
        self.store = store


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TelemetryGateway/1.0"

    # ---------- 路由 ----------
    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok", "time": int(time.time())})
        else:
            self._send_json(404, _error_dict("NOT_FOUND", "unknown path"))

    def do_POST(self) -> None:
        try:
            if self.path != EVENTS_PATH:
                raise ApiError(404, "NOT_FOUND", "unknown path")
            status, body = self._handle_events()
        except ApiError as exc:
            status, body = exc.status, exc.to_dict()
            log.info("reject %s -> %d %s", self.path, exc.status, exc.code)
        except Exception:
            log.exception("unhandled error while processing %s", self.path)
            status, body = 500, _error_dict("INTERNAL_ERROR", "internal server error")
        self._send_json(status, body)

    def do_PUT(self) -> None:
        self._send_json(405, _error_dict("METHOD_NOT_ALLOWED", "use POST"))

    do_DELETE = do_PUT
    do_PATCH = do_PUT

    # ---------- 主流程 ----------
    def _handle_events(self) -> tuple[int, dict]:
        gateway: Gateway = self.server.gateway  # type: ignore[attr-defined]
        config = gateway.config

        station_id = self._required_header("X-Station-Id")
        key_id = self._required_header("X-Key-Id")
        ts_raw = self._required_header("X-Timestamp")
        nonce = self._required_header("X-Nonce")
        signature = self._required_header("X-Signature")

        try:
            timestamp = int(ts_raw, 10)
        except ValueError:
            raise ApiError(400, "MALFORMED_HEADERS",
                           "X-Timestamp must be unix epoch seconds")
        if not _NONCE_RE.fullmatch(nonce):
            raise ApiError(400, "MALFORMED_HEADERS",
                           "X-Nonce must be 8..128 chars of [A-Za-z0-9._~-]")

        raw_body = self._read_body(config.max_body_bytes)

        now = time.time()
        skew = abs(now - timestamp)
        if skew > config.skew_seconds:
            raise ApiError(401, "TIMESTAMP_OUT_OF_RANGE",
                           f"timestamp skew {skew:.0f}s exceeds "
                           f"{config.skew_seconds}s")

        key = gateway.keystore.get(key_id)
        if key is None:
            raise ApiError(401, "KEY_UNKNOWN", "unregistered key id")
        if not key.is_active(now):
            state = "expired" if now > key.not_after else "not yet valid"
            raise ApiError(403, "KEY_EXPIRED", f"key {key_id} is {state}")
        if key.station_id != station_id:
            raise ApiError(403, "KEY_STATION_MISMATCH",
                           "key is not registered for this station")

        canonical = auth.canonical_string("POST", EVENTS_PATH, station_id, key_id,
                                          ts_raw, nonce, raw_body)
        if not auth.verify_signature(key.secret, canonical, signature):
            raise ApiError(401, "SIGNATURE_INVALID", "signature verification failed")

        # 验签通过后才解压、解析、校验事件
        data = payload_mod.maybe_decompress(
            raw_body, self.headers.get("Content-Encoding"),
            config.max_decompressed_bytes)
        obj = payload_mod.parse_and_validate(data, station_id, now)
        digest, canonical_payload = payload_mod.stable_digest(obj)

        # 全部校验通过，事务性登记 nonce；冲突即重放
        accepted = gateway.store.record_acceptance(
            station_id, nonce, key_id, digest, canonical_payload, now)
        if not accepted:
            raise ApiError(409, "NONCE_REPLAY", "nonce already used for this station")

        log.info("accepted station=%s key=%s nonce=%s digest=%s",
                 station_id, key_id, nonce, digest)
        return 202, {
            "status": "accepted",
            "station_id": station_id,
            "nonce": nonce,
            "event_digest": digest,
            "received_at": int(now),
        }

    # ---------- 工具 ----------
    def _required_header(self, name: str) -> str:
        value = self.headers.get(name)
        if value is None or value.strip() == "":
            raise ApiError(400, "MALFORMED_HEADERS",
                           f"missing required header {name}")
        return value.strip()

    def _read_body(self, max_body: int) -> bytes:
        length = self.headers.get("Content-Length")
        if length is None:
            raise ApiError(411, "LENGTH_REQUIRED", "Content-Length is required")
        try:
            size = int(length, 10)
        except ValueError:
            raise ApiError(400, "MALFORMED_HEADERS", "invalid Content-Length")
        if size < 0 or size > max_body:
            raise ApiError(413, "PAYLOAD_TOO_LARGE",
                           f"body exceeds {max_body} bytes")
        body = self.rfile.read(size)
        if len(body) != size:
            raise ApiError(400, "PAYLOAD_MALFORMED", "truncated request body")
        return body

    def _send_json(self, status: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args) -> None:  # 交给 logging 模块
        log.debug("%s - %s", self.address_string(), fmt % args)


def _error_dict(code: str, message: str) -> dict:
    return {"error": {"code": code, "message": message}}


class GatewayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64  # 并发突发时的监听积压队列


def create_server(config: Config) -> ThreadingHTTPServer:
    keystore = KeyStore.load(config.keys_file)
    os.makedirs(config.data_dir, exist_ok=True)
    store = Store(os.path.join(config.data_dir, "telemetry.db"))
    gateway = Gateway(config, keystore, store)
    httpd = GatewayHTTPServer((config.host, config.port), Handler)
    httpd.gateway = gateway  # type: ignore[attr-defined]
    return httpd


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    config = Config.from_env()
    httpd = create_server(config)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: threading.Thread(
            target=httpd.shutdown, daemon=True).start())
    log.info("listening on %s:%d, keys=%s, data=%s",
             config.host, config.port, config.keys_file, config.data_dir)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
