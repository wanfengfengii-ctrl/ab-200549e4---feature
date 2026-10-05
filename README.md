# 辐射监测站遥测接收网关

辐射监测站通过不稳定专网上报剂量事件。本网关接收 `POST /api/telemetry/events`
（JSON 或 gzip 压缩 JSON），通过 **HMAC-SHA256 签名**验证报文确由已登记设备发送，
并以 **持久化 nonce 登记**阻止截获数据被再次接纳（并发请求与服务重启后均至多成功一次）。

专网抖动可能使事件已被网关接纳、`202` 响应却在回程中丢失。监测站可改发
`POST /api/telemetry/events/recover` **确认原接纳结果**：沿用同一套鉴权头、
JSON/gzip 载荷与签名规则（仅签名路径不同），网关按站点、nonce 与稳定事件摘要
只读核对，恢复操作绝不再次接纳、不登记也不改写 nonce。

纯 Python 标准库实现，零第三方依赖。

## 快速启动

```bash
# 启动网关（默认宿主机端口 8080，可用 HOST_PORT 覆盖）
docker compose up --build app
HOST_PORT=9090 docker compose up --build app

# 运行一次性验证服务（构建检查 + 单元测试 + 签名/压缩/并发防重放/回执恢复冒烟）
docker compose up --build --exit-code-from verify --abort-on-container-exit verify
echo $?   # 0 = 全部通过

# 停止并清空持久化 nonce 数据
docker compose down -v
```

镜像内置默认测试密钥（`keys/keys.json`），无需任何配置即可直接启动。
本地无 Docker 时：

```bash
python3 -m app.server                                   # 启动网关（:8000）
python3 -m unittest discover -s tests -t .              # 单元测试
GATEWAY_URL=http://127.0.0.1:8000 python3 -m verify.run # 完整验证（含冒烟）
```

## verify 服务退出码

`verify` 一次性服务依次执行构建检查（全量源码编译 + 模块导入）、单元测试、
端到端冒烟（签名、压缩、时间窗、密钥有效期、失败不占 nonce、重放、16 路并发防重放、
回执恢复 200/404/409、旧数据卷、跨站点隔离与并发重试），
退出码按位汇总：

| 退出码 | 含义 |
|---|---|
| 0 | 全部通过 |
| 1 | 构建检查失败 |
| 2 | 单元测试失败 |
| 4 | 冒烟测试失败 |

位可组合（如 3 = 构建 + 单元测试均失败）。镜像构建本身也是一道门禁：
`Dockerfile` 中的 `compileall` 会在语法错误时直接使构建失败。

## 接口

### `POST /api/telemetry/events`

请求头：

| 请求头 | 说明 |
|---|---|
| `X-Station-Id` | 站点编号（须与密钥绑定的站点一致） |
| `X-Key-Id` | 密钥编号 |
| `X-Timestamp` | 发送时刻，Unix 秒；与网关当前时间相差不得超过 300 秒 |
| `X-Nonce` | 随机 nonce，8–128 位 `[A-Za-z0-9._~-]`；同站点至多成功一次 |
| `X-Signature` | Base64(HMAC-SHA256(secret, 规范化串)) |
| `Content-Encoding` | 可选，`gzip` 表示请求体为 gzip 压缩（缺失时按魔数自动识别） |

### 签名方案

规范化串为以下各项以换行 `\n` 连接（顺序固定）：

```
POST
/api/telemetry/events
<X-Station-Id>
<X-Key-Id>
<X-Timestamp>
<X-Nonce>
<传输原始字节的 SHA-256 十六进制摘要>
```

恢复接口 `POST /api/telemetry/events/recover` 的规范化串仅第二行替换为
`/api/telemetry/events/recover`，其余完全相同。

注意摘要覆盖的是**线上传输的原始字节**：发送 gzip 时即压缩后的字节。
HMAC 密钥为该 `X-Key-Id` 对应密钥的 UTF-8 字节。

### 事件载荷

```json
{
  "station_id": "station-alpha",
  "sent_at": 1791163600,
  "events": [
    {"event_id": "evt-0001", "measured_at": 1791163595,
     "dose_usv_h": 0.117, "instrument": "gm-1"}
  ]
}
```

- `station_id`：必填，须与 `X-Station-Id` 一致
- `events`：必填非空数组（≤1000 条）；每条须含 `event_id`（1–128 字符）、
  `measured_at`（Unix 秒数值）、`dose_usv_h`（0–1e6 数值）；允许额外字段

### 响应

成功 `202 Accepted`：

```json
{"status": "accepted", "station_id": "station-alpha", "nonce": "…",
 "event_digest": "<规范化载荷的 SHA-256 十六进制>", "received_at": 1791163601}
```

`event_digest` 为稳定事件摘要：同一事件内容（无论键序、空白、JSON 或 gzip 传输）
摘要恒定。

失败响应统一为 `{"error": {"code", "message", "detail?"}}`，可区分代码：

| HTTP | code | 含义 |
|---|---|---|
| 400 | `MALFORMED_HEADERS` | 必需请求头缺失或格式非法 |
| 400 | `PAYLOAD_MALFORMED` | 畸形载荷（gzip/JSON/字段校验失败） |
| 401 | `KEY_UNKNOWN` | 密钥编号未登记 |
| 401 | `TIMESTAMP_OUT_OF_RANGE` | 发送时刻偏差超过 300 秒 |
| 401 | `SIGNATURE_INVALID` | 签名校验失败 |
| 403 | `KEY_EXPIRED` | 密钥已过期或尚未生效 |
| 403 | `KEY_STATION_MISMATCH` | 密钥未绑定该站点 |
| 409 | `NONCE_REPLAY` | 同站点 nonce 已成功使用过（重放） |
| 404 | `RECEIPT_NOT_FOUND` | 恢复：该站点从未以此 nonce 成功接纳过事件 |
| 409 | `RECEIPT_MISMATCH` | 恢复：nonce 有接纳记录，但事件摘要与本次载荷不一致 |
| 409 | `RECEIPT_UNAVAILABLE` | 恢复：旧数据卷仅有防重放记录，无法核对回执 |
| 411 | `LENGTH_REQUIRED` | 缺少 Content-Length |
| 413 | `PAYLOAD_TOO_LARGE` | 请求体或解压后超限 |
| 415 | `UNSUPPORTED_ENCODING` | 不支持的 Content-Encoding |

### 处理顺序与防重放语义

1. 请求头齐全性/格式 → 2. 读取原始体 → 3. 时间窗 → 4. 密钥登记/有效期/站点绑定
→ 5. **验签** → 6. **解压与事件校验** → 7. 事务性登记 nonce → 8. `202`

- **先验签再解压**：签名覆盖传输原始字节，验签通过前不解压、不解析。
- **失败请求不占用 nonce**：nonce 仅在全部校验通过、即将接纳时写入；
  签名错误、载荷畸形等失败路径不留痕迹，客户端可修正后用同一 nonce 重试。
- **至多成功一次**：nonce 以 `(station_id, nonce)` 主键存入 SQLite（WAL +
  `synchronous=FULL`），插入即接纳；并发冲突由唯一约束兜底，16 路并发同一
  nonce 仅 1 个 `202`、其余 `409`。数据库落在 `DATA_DIR`（Compose 命名卷
  `app-data`），服务重启后重放仍返回 `409`。

## 回执恢复：`POST /api/telemetry/events/recover`

事件已被接纳但 `202` 在抖动专网上丢失时，监测站用本接口确认**首次接纳的原结果**，
而不是重新上报。

- **鉴权与载荷规则与接纳接口完全一致**：相同的 `X-Station-Id` / `X-Key-Id` /
  `X-Timestamp`（五分钟窗）/ `X-Nonce` / `X-Signature` 头，相同的 JSON 或
  gzip 载荷、大小限制与字段校验。
- **唯一区别是签名路径**：规范化串第二行改为
  `/api/telemetry/events/recover`，其余六项（方法、站点、密钥编号、时间戳、
  nonce、传输原始字节 SHA-256）不变。两个路径的签名不可互换。
- 恢复请求携带的事件内容应与首次接纳**完全一致**（允许键序/空白/传输压缩方式
  不同，按稳定事件摘要核对）。

响应：

| 情形 | HTTP | code / status |
|---|---|---|
| 站点 + nonce + 事件摘要全部一致 | 200 | `status="recovered"`，附首次接纳的 `event_digest` 与 `received_at` |
| 该站点从未以此 nonce 成功接纳 | 404 | `RECEIPT_NOT_FOUND` |
| nonce 有记录但事件摘要不一致 | 409 | `RECEIPT_MISMATCH` |
| 旧版本数据卷仅有防重放记录 | 409 | `RECEIPT_UNAVAILABLE` |

```json
{"status": "recovered", "station_id": "station-alpha", "nonce": "…",
 "event_digest": "<首次接纳时的稳定摘要>", "received_at": 1791163601}
```

语义保证：

- **只核对、不接纳**：恢复全流程只执行 SELECT，不登记、不改写任何 nonce 或
  事件记录；恢复成功/失败都不影响 nonce 的防重放状态。
- **404 不留痕**：未接纳过的 nonce 恢复返回 `404` 后，仍可正常走接纳接口成功。
- **按站点隔离**：核对严格以 `(X-Station-Id, nonce)` 为键，密钥必须绑定本站点；
  任何失败都不会泄露其他站点是否持有该 nonce。
- **旧卷可识别**：旧版本数据库迁移后历史 nonce 行摘要为 NULL，恢复返回
  `RECEIPT_UNAVAILABLE`，防重放依旧有效；新接纳的事件正常记录摘要。
- 时间窗、密钥有效期、签名、载荷等鉴权失败使用与接纳接口相同的错误码。

## 客户端示例

Python（标准库）：

```python
import base64, hashlib, hmac, json, secrets, time, urllib.request

SECRET, STATION, KEY_ID = "alpha-test-secret-3f9c1d7e2b48", "station-alpha", "test-key-1"
body = json.dumps({
    "station_id": STATION,
    "events": [{"event_id": "evt-0001", "measured_at": int(time.time()) - 5,
                "dose_usv_h": 0.117}],
}).encode()
ts, nonce = str(int(time.time())), secrets.token_hex(12)
canonical = "\n".join(["POST", "/api/telemetry/events", STATION, KEY_ID, ts, nonce,
                       hashlib.sha256(body).hexdigest()])
sig = base64.b64encode(hmac.new(SECRET.encode(), canonical.encode(),
                                hashlib.sha256).digest()).decode()
req = urllib.request.Request(
    "http://localhost:8080/api/telemetry/events", data=body, method="POST",
    headers={"X-Station-Id": STATION, "X-Key-Id": KEY_ID, "X-Timestamp": ts,
             "X-Nonce": nonce, "X-Signature": sig})
print(urllib.request.urlopen(req).read().decode())
```

gzip 发送：将 `body` 替换为 `gzip.compress(body)` 并加头
`"Content-Encoding": "gzip"` 即可（签名对压缩后字节计算）。

`202` 丢失后确认原结果（只改 URL 与签名路径，载荷与 nonce 保持首次上报内容）：

```python
RECOVER = "/api/telemetry/events/recover"
ts = str(int(time.time()))  # 恢复请求用当前时间重新签名，仍受五分钟窗约束
canonical = "\n".join(["POST", RECOVER, STATION, KEY_ID, ts, nonce,
                       hashlib.sha256(body).hexdigest()])
sig = base64.b64encode(hmac.new(SECRET.encode(), canonical.encode(),
                                hashlib.sha256).digest()).decode()
req = urllib.request.Request(
    "http://localhost:8080" + RECOVER, data=body, method="POST",
    headers={"X-Station-Id": STATION, "X-Key-Id": KEY_ID, "X-Timestamp": ts,
             "X-Nonce": nonce, "X-Signature": sig})
# 200 status=recovered 即首次接纳的 event_digest/received_at；
# 404 RECEIPT_NOT_FOUND 表示网关从未接纳，可安全走原接口重新上报。
```

## 配置

环境变量（Compose 中均可覆盖）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `HOST` / `PORT` | `0.0.0.0` / `8000` | 容器内监听地址 |
| `HOST_PORT` | `8080` | Compose 宿主机映射端口 |
| `KEYS_FILE` | `/app/keys/keys.json` | 密钥文件路径（生产环境挂载正式文件） |
| `DATA_DIR` | `/data` | SQLite 数据目录（Compose 命名卷持久化） |
| `SKEW_SECONDS` | `300` | 允许的发送时刻偏差（五分钟） |
| `MAX_BODY_BYTES` | `5242880` | 请求体上限 |
| `MAX_DECOMPRESSED_BYTES` | `10485760` | 解压后上限（防 zip 炸弹） |

密钥文件格式：

```json
{"keys": [{"key_id": "…", "station_id": "…", "secret": "…",
           "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-12-31T23:59:59Z"}]}
```

`keys/keys.json` 内置：`test-key-1`/`test-key-2`（有效）、`test-key-expired`
（已过期）、`test-key-future`（尚未生效），后两者用于验证失败路径。**测试密钥
仅供开发演示，生产部署必须替换。**

## 目录结构

```
app/            网关实现（server/auth/keystore/store/payload/config/errors）
keys/keys.json  默认测试密钥
tests/          单元与端到端测试（73 例，含并发、重启持久化与回执恢复）
verify/         一次性验证服务（run.py 汇总退出码，smoke.py 冒烟用例）
Dockerfile      应用镜像（python:3.12-slim，非 root 运行，构建期语法门禁）
docker-compose.yml  app（健康检查 + HOST_PORT 可配置）+ verify 一次性服务
```
