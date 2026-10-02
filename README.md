# keyescrow — AES-256 业务密钥托管库

由上层直接调用的 Python 库。业务密钥以加密形式托管在单个 SQLite 文件中，
启动口令由调用方提供；支持托管口令的安全换代，换代期间进程可在任意
落盘阶段被终止，重启后接续进度。

## 功能与规则

- 生成业务密钥（`generate_key` / `generate_keys`），按 Key ID 加解密短消息
  （`encrypt` / `decrypt`）。公开 API 不返回任何业务密钥明文。
- 磁盘上不出现口令或业务密钥明文；除 SQLite 文件外不依赖其他持久化秘密。
- 换代（`start_rotation` / `advance_rotation`）不改变 Key ID 与业务密钥，
  换代前的业务密文仍可由原 Key ID 正确解密。
- 换代请求被持久化接受后、完成前，单独提供旧口令或新口令都能打开库、
  使用全部业务密钥并继续换代；完成后只有新口令有效。
- 固定请求编号重试同一次换代会接续既有进度；已完成请求的重试直接返回
  完成状态，不会启动新一轮。

## 快速开始

```python
from keyescrow import EscrowStore

# 创建（文件已存在则抛 StoreExistsError）
store = EscrowStore.create("escrow.db", "old-passphrase")
key_id = store.generate_key()
ct = store.encrypt(key_id, b"short message", aad=b"optional-context")
store.close()

# 打开（换代未开始时只有旧口令有效）
store = EscrowStore.open("escrow.db", "old-passphrase")
assert store.decrypt(key_id, ct, aad=b"optional-context") == b"short message"

# 发起换代：请求被持久化接受后，旧/新口令各自都能重新打开库
store.start_rotation("rotation-2026-10", "new-passphrase")
while True:
    status = store.advance_rotation(100)   # 每批至多 100 把，提交后返回
    print(status.done, "/", status.total)  # 已确认的可恢复进度
    if status.complete:
        break
store.close()

# 完成后只有新口令有效；用同一请求编号重试直接返回完成
store = EscrowStore.open("escrow.db", "new-passphrase")
assert store.start_rotation("rotation-2026-10", "anything").complete
```

约束：换代期间不允许新增业务密钥（`generate_key` 抛
`RotationStateError`），但推进间隙可正常加解密已有消息；仅支持单进程
顺序调用。

## 保护结构

```
口令 ──PBKDF2-HMAC-SHA256(600k, 每库随机盐)──> KEK
KEK ──AES-256-GCM──> 包裹主密钥（slots 表）
主密钥 ──AES-256-GCM──> 包裹业务密钥（keys 表，AAD 绑定 key_id + 代次）
业务密钥 ──AES-256-GCM──> 业务密文（AAD 绑定 key_id + 调用方 AAD）
```

- **主密钥**：每库随机生成的 256 位密钥。换代时生成全新主密钥，全部业务
  密钥按代次（generation）逐批重新包裹；每条记录用哪一代主密钥由
  `generation` 列标明。
- **换代期间**：新主密钥同时被旧口令 KEK（slot 0）和新口令 KEK（slot 1）
  包裹，旧主密钥由新主密钥包裹保存（`old_master_wrapped`）。因此任一口令
  都能独立打开库并接续换代，无需同时保管两套口令。
- **完成边界**：最后一批重包裹与"删除旧 slot、旧主密钥、切换状态"在同一
  SQLite 事务中提交，进程在边界被终止只会落到"未完成"或"已完成"之一，
  不会出现半切换。
- **进度恢复**：进度即 `keys` 表中各代次记录数，每批（≤100 把）提交即
  确认；重启后从未完成的代次继续，已确认部分不重做，未确认部分最多
  重做一批（≤100 把）。

## 强度与成本依据

- **落盘保护强度 ≥ 128 位**：所有对称操作为 AES-256-GCM（密钥 256 位、
  随机 96 位 nonce、128 位认证标签）；主密钥与业务密钥均为 CSPRNG
  （`os.urandom`）生成的 256 位随机值。
- **离线猜测成本 ≥ 60 万次通用密码散列等效**：口令经
  PBKDF2-HMAC-SHA256 迭代 600,000 次派生 KEK。每次迭代含 2 次
  HMAC-SHA256（约 4 次 SHA-256 压缩），单次猜测成本约 2.4×10⁶ 次
  压缩运算，不低于 60 万次通用密码散列的等效等级（与 OWASP 对
  PBKDF2-HMAC-SHA256 的 600k 迭代建议一致）。迭代次数见
  `keyescrow/crypto.py` 的 `KDF_ITERATIONS`。
- **库间独立**：每库随机 128 位盐 + 随机主密钥，相同口令在不同库派生出
  完全不同的 KEK 与包裹记录。
- **篡改与互换检测**：业务密钥包裹记录的 AAD 绑定 `key_id` 与代次，跨
  Key ID 互换或任何比特篡改都会导致 GCM 认证失败（抛
  `IntegrityError`），不会静默使用错误密钥；错误口令抛
  `AuthenticationError`。

## 测试

```
python3 -m pytest tests/ -q
```

- `tests/test_basic.py`：生命周期、加解密、换代状态机、请求幂等。
- `tests/test_security.py`：密文/包裹记录篡改、跨 Key ID 互换、库间
  独立性、旧口令与旧保护秘密失效、KDF 成本。
- `tests/test_crash_recovery.py`：真实子进程在换代多处被 SIGKILL，分别
  用旧/新口令恢复并重试同一请求，验证进度不倒退、历史消息逐字节一致；
  最终完成边界反复终止，验证状态全有或全无。
- `tests/test_scale.py`：10 万把密钥规模测试，报告生成/换代耗时、峰值
  额外内存（< 64 MiB）、恢复查询耗时（< 2 s，口令派生不计）与中断后的
  重复处理量（已确认 0 把、未确认 ≤ 100 把）。

本机最近一次规模测试报告：生成 100k 把约 1.2 s；换代在 12,800 把处被
SIGKILL，已确认部分重做 0 把；恢复后查询进度并解密一条消息约 6 ms；
峰值额外内存约 0.1 MiB。

## 依赖

- Python ≥ 3.10，`cryptography` ≥ 41，SQLite（Python 标准库 `sqlite3`）。
