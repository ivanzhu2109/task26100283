# keyescrow — AES-256 业务密钥托管库

由上层直接调用的 Python 库。业务密钥（DEK）经口令派生密钥（KEK）封装后存入
SQLite，支持托管口令换代（re-key），换代期间业务密钥与 Key ID 不变，
进程在任意落盘阶段被终止都可接续进度。

## 安装与运行

依赖：Python ≥ 3.10、`cryptography`（AES-256-GCM）、标准库 `sqlite3`/`hashlib`。
无网络、无服务、无端口监听，持久化仅一个 SQLite 文件（含其 WAL 文件）。

```bash
python3 -m pytest            # 运行全部测试（含 10 万把密钥规模测试）
python3 -m pytest -q -s tests/test_scale.py   # 查看规模测试指标
```

## 使用说明

```python
from keyescrow import KeyStore

ks = KeyStore.create("escrow.db", "old-passphrase")   # 或 KeyStore.open(...)
kid = ks.generate_key()                                # 返回 Key ID，不返回密钥材料
ct = ks.encrypt(kid, b"short message")
pt = ks.decrypt(kid, ct)

st = ks.start_rotation("req-2026-10", "new-passphrase")  # 幂等：同请求号重试接续进度
while ks.rotation_status()["status"] == "active":
    st = ks.advance_rotation(100)        # 每批 ≤100 把，单事务落盘后即算已确认
    # st = {"status": "active", "request_id": ..., "done": n, "total": m}
ks.close()
```

- 换代进行中：旧口令或新口令**单独**都能 `open`、使用全部密钥、继续
  `advance_rotation`；期间不可新增业务密钥，但可加解密既有消息。
- 换代完成后：仅新口令有效，旧口令 `open` 抛 `AuthError`。
- 用同一 `request_id` 重试 `start_rotation`：进行中则返回当前进度，
  已完成则返回 `{"status": "completed", ...}`，不会另起一轮。
- 错误口令抛 `AuthError`；密文/记录被篡改或跨 Key ID 互换抛
  `cryptography.exceptions.InvalidTag`。

## 设计要点

- **封装**：每把 DEK 为 256 位随机数，`AES-256-GCM(KEK, DEK)` 落盘，
  AAD 绑定 `key_id`（防跨记录互换）；业务消息同样 AES-256-GCM，
  AAD 绑定 `key_id` 与调用方 AAD。
- **槽位**：口令槽位存 `salt + AES-GCM(KEK, {check, peer})`。`check` 校验口令；
  换代期间 `peer` 保存对方 KEK（桥接），因此任一口令都能解开两代记录。
  空闲时仅一个槽位且无桥接。
- **换代**：按 `key_id` 顺序每批 ≤100 把在**单个事务**内解旧封新并推进游标；
  崩溃只回滚当前批次（未确认部分最多重做 100 把）。完成边界（删旧槽位、
  断桥接、记完成状态）也是单事务，恢复后只会处于一致的未完成或已完成状态。
- **Key ID 与业务密钥全程不变**，历史密文由原 Key ID 正常解密。

## 强度与成本依据

- **落盘安全强度 ≥ 128 位**：DEK、KEK 均为 256 位；AES-256-GCM 提供 128 位
  认证标签；每库 16 字节随机 `lib_id` 与每槽位 16 字节随机 salt，
  不同库即使口令相同，派生结果也相互独立。
- **离线猜测成本 ≥ 60 万次通用密码散列**：KEK 派生使用
  PBKDF2-HMAC-SHA256，**600,000 次迭代**（`keyescrow/crypto.py`
  的 `KDF_ITERATIONS`），与 OWASP 2023 对 HMAC-SHA256 的推荐值一致；
  每次口令猜测需完整执行 60 万次 HMAC（约 120 万次 SHA-256 压缩），
  本机实测单次派生约 0.13–0.3 s。提升 `KDF_ITERATIONS` 可线性提高成本。
- **旧秘密失效**：换代完成后全部记录已用新 KEK 重封装，旧槽位（含旧 salt
  与桥接）被删除；测试验证旧口令派生的 KEK 对所有新记录解封均失败。
  按要求不保证旧备份副本失效。

## 规模测试实测（本机，10 万把密钥）

| 指标 | 实测 | 要求 |
|---|---|---|
| 生成 10 万把密钥 | 约 6 s | — |
| 全量换代（1001 批 × 100） | 约 1.4 s | — |
| 换代峰值额外内存 | 约 0.1 MiB | ≤ 64 MiB |
| 崩溃后重开 + 查进度 + 解密 1 条 | 约 0.13 s（不含 KDF） | ≤ 2 s |
| 中断后重复处理量 | 0 把（事务保证 ≤ 100） | ≤ 100 把 |

## 文件结构

- `keyescrow/crypto.py` — KDF 与 AES-256-GCM 原语
- `keyescrow/store.py` — SQLite 薄封装（meta / slots / keys 三表，显式事务）
- `keyescrow/keystore.py` — 公开 API 与换代状态机
- `tests/` — 基础、换代、真实进程终止恢复、10 万规模测试
