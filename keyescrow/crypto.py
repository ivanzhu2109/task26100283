"""加密原语。

- KEK 派生：PBKDF2-HMAC-SHA256，默认 600_000 次迭代（单次离线猜测成本
  ≥ 60 万次通用密码散列运算，与 OWASP 2023 对 HMAC-SHA256 的建议一致）。
  每库随机 16 字节 salt，保证不同库相同口令派生结果独立。
- 封装：AES-256-GCM，12 字节随机 nonce，输出格式 nonce||ciphertext||tag。
  GCM 的 128 位认证标签保证篡改与跨记录互换会被拒绝。
"""
from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KDF_ITERATIONS = 600_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # AES-256


def derive_kek(passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """从口令派生 32 字节 KEK（PBKDF2-HMAC-SHA256）。"""
    return hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, iterations, dklen=KEY_LEN
    )


def wrap_key(kek: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM 加密，输出 nonce||ct||tag。"""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(kek).encrypt(nonce, plaintext, aad)


def unwrap_key(kek: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM 解密；认证失败抛 cryptography.exceptions.InvalidTag。"""
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(kek).decrypt(nonce, ct, aad)


def random_bytes(n: int) -> bytes:
    return os.urandom(n)
