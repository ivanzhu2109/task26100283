"""业务密钥托管库公开 API。

保护模型：
- 每把业务密钥（DEK）为 256 位随机数，经 AES-256-GCM 用 KEK 封装后落盘，
  AAD 绑定 key_id；公开调用永不返回 DEK 明文。
- KEK 由口令经 PBKDF2-HMAC-SHA256（600k 迭代、每槽位随机 salt）派生。
- 槽位 payload 保存校验值（lib_id），换代期间另保存桥接秘密（对方 KEK），
  因此换代进行中旧口令或新口令单独都能打开库并使用全部密钥。
- 换代按 key_id 顺序每批 ≤100 把在一个事务内重写，游标持久化；
  完成边界（删旧槽位 + 记录完成状态）也在单个事务内，杜绝半切换。
"""
from __future__ import annotations

import json
import uuid

from cryptography.exceptions import InvalidTag

from . import crypto
from .store import Store

_SLOT_OF_GEN = {0: "A", 1: "B"}
_GEN_OF_SLOT = {"A": 0, "B": 1}


class KeyStoreError(Exception):
    pass


class AuthError(KeyStoreError):
    """口令错误。"""


class RotationError(KeyStoreError):
    pass


class KeyStore:
    """AES-256 业务密钥托管库。单进程顺序调用。"""

    def __init__(self, store: Store, lib_id: bytes, keks: dict[int, bytes]):
        self._store = store
        self._lib_id = lib_id
        self._keks = keks  # gen -> KEK

    # ------------------------------------------------------------------ 开关
    @classmethod
    def create(cls, path: str, passphrase: str) -> "KeyStore":
        store = Store(path)
        store.open()
        if store.get_meta("lib_id") is not None:
            store.close()
            raise KeyStoreError(f"library already exists: {path}")
        lib_id = crypto.random_bytes(16)
        salt = crypto.random_bytes(crypto.SALT_LEN)
        kek = crypto.derive_kek(passphrase, salt)
        with store.transaction():
            store.set_meta("lib_id", lib_id)
            store.set_meta("kdf_iterations", str(crypto.KDF_ITERATIONS).encode())
            store.set_meta("rotation", json.dumps({"status": "idle"}).encode())
            store.put_slot("A", salt, _slot_payload('A', kek, lib_id, None))
        return cls(store, lib_id, {0: kek})

    @classmethod
    def open(cls, path: str, passphrase: str) -> "KeyStore":
        store = Store(path)
        store.open()
        lib_id = store.get_meta("lib_id")
        if lib_id is None:
            store.close()
            raise KeyStoreError(f"not an escrow library: {path}")
        iterations = int(store.get_meta("kdf_iterations").decode())
        keks: dict[int, bytes] = {}
        for slot_id, (salt, payload) in store.get_slots().items():
            gen = _GEN_OF_SLOT[slot_id]
            kek = crypto.derive_kek(passphrase, salt, iterations)
            try:
                data = json.loads(
                    crypto.unwrap_key(kek, payload, _slot_aad(slot_id)).decode()
                )
            except (InvalidTag, ValueError):
                continue  # 该槽位口令不符，试下一个
            if data.get("check") != lib_id.hex():
                continue
            keks[gen] = kek
            if data.get("peer"):
                keks[1 - gen] = bytes.fromhex(data["peer"])
        if not keks:
            store.close()
            raise AuthError("invalid passphrase")
        return cls(store, lib_id, keks)

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "KeyStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------- 业务密钥
    def generate_key(self, key_id: str | None = None) -> str:
        """生成一把新的业务密钥，返回 Key ID（不返回密钥材料）。"""
        if self._rotation_state()["status"] == "active":
            raise RotationError("cannot generate keys during rotation")
        key_id = key_id or uuid.uuid4().hex
        if self._store.get_key(key_id) is not None:
            raise KeyStoreError(f"duplicate key_id: {key_id}")
        gen = self._current_gen()
        dek = crypto.random_bytes(crypto.KEY_LEN)
        ct = crypto.wrap_key(self._keks[gen], dek, _key_aad(key_id))
        with self._store.transaction():
            self._store.put_key(key_id, gen, ct)
        return key_id

    def encrypt(self, key_id: str, plaintext: bytes, aad: bytes = b"") -> bytes:
        dek = self._load_dek(key_id)
        return crypto.wrap_key(dek, plaintext, _msg_aad(key_id, aad))

    def decrypt(self, key_id: str, ciphertext: bytes, aad: bytes = b"") -> bytes:
        dek = self._load_dek(key_id)
        return crypto.unwrap_key(dek, ciphertext, _msg_aad(key_id, aad))

    def _load_dek(self, key_id: str) -> bytes:
        row = self._store.get_key(key_id)
        if row is None:
            raise KeyStoreError(f"unknown key_id: {key_id}")
        gen, ct = row
        return crypto.unwrap_key(self._keks[gen], ct, _key_aad(key_id))

    def _current_gen(self) -> int:
        # 空闲时只有一个槽位；其 gen 即当前写入代。
        return min(self._keks) if len(self._keks) == 1 else self._rotation_dst_gen()

    # ----------------------------------------------------------------- 换代
    def start_rotation(self, request_id: str, new_passphrase: str) -> dict:
        """发起换代。同一 request_id 重试接续既有进度，不另起一轮。"""
        state = self._rotation_state()
        if state["status"] == "completed":
            if state["request_id"] == request_id:
                return self.rotation_status()
            # 上一轮已完成，允许用新请求号发起下一轮（槽位乒乓）。
        elif state["status"] == "active":
            if state["request_id"] != request_id:
                raise RotationError(
                    f"rotation already in progress: {state['request_id']}"
                )
            return self.rotation_status()

        src_gen = self._current_gen()
        dst_gen = 1 - src_gen
        src_kek = self._keks[src_gen]
        salt = crypto.random_bytes(crypto.SALT_LEN)
        dst_kek = crypto.derive_kek(new_passphrase, salt)
        total = self._store.count_keys()
        new_state = {
            "status": "active",
            "request_id": request_id,
            "src_gen": src_gen,
            "dst_gen": dst_gen,
            "cursor": "",
            "done": 0,
            "total": total,
        }
        with self._store.transaction():
            self._store.put_slot(
                _SLOT_OF_GEN[dst_gen], salt, _slot_payload(_SLOT_OF_GEN[dst_gen], dst_kek, self._lib_id, src_kek)
            )
            self._store.put_slot(
                _SLOT_OF_GEN[src_gen],
                self._store.get_slots()[_SLOT_OF_GEN[src_gen]][0],
                _slot_payload(_SLOT_OF_GEN[src_gen], src_kek, self._lib_id, dst_kek),
            )
            self._store.set_meta("rotation", json.dumps(new_state).encode())
        self._keks[dst_gen] = dst_kek
        return self.rotation_status()

    def advance_rotation(self, limit: int = 100) -> dict:
        """推进至多 limit 把密钥的重封装，返回可恢复的持久化进度。"""
        state = self._rotation_state()
        if state["status"] != "active":
            return self.rotation_status()
        src_gen, dst_gen = state["src_gen"], state["dst_gen"]
        cursor = state["cursor"]
        batch = self._store.fetch_batch(src_gen, cursor, limit)
        if not batch:
            return self._finalize_rotation(state)
        src_kek, dst_kek = self._keks[src_gen], self._keks[dst_gen]
        with self._store.transaction():
            for key_id, ct in batch:
                dek = crypto.unwrap_key(src_kek, ct, _key_aad(key_id))
                self._store.update_key(
                    key_id, dst_gen, crypto.wrap_key(dst_kek, dek, _key_aad(key_id))
                )
            state["cursor"] = batch[-1][0]
            state["done"] += len(batch)
            self._store.set_meta("rotation", json.dumps(state).encode())
        return self.rotation_status()

    def _finalize_rotation(self, state: dict) -> dict:
        """完成边界：单事务内删旧槽位、断开桥接、记录完成状态。"""
        dst_gen = state["dst_gen"]
        dst_slot = _SLOT_OF_GEN[dst_gen]
        dst_kek = self._keks[dst_gen]
        salt = self._store.get_slots()[dst_slot][0]
        done_state = {"status": "completed", "request_id": state["request_id"]}
        with self._store.transaction():
            self._store.delete_slot(_SLOT_OF_GEN[1 - dst_gen])
            self._store.put_slot(dst_slot, salt, _slot_payload(dst_slot, dst_kek, self._lib_id, None))
            self._store.set_meta("rotation", json.dumps(done_state).encode())
        del self._keks[1 - dst_gen]
        return self.rotation_status()

    def rotation_status(self) -> dict:
        state = self._rotation_state()
        out = {"status": state["status"]}
        if state["status"] == "active":
            out.update(
                request_id=state["request_id"],
                done=state["done"],
                total=state["total"],
            )
        elif state["status"] == "completed":
            out["request_id"] = state["request_id"]
        return out

    # ----------------------------------------------------------------- 内部
    def _rotation_state(self) -> dict:
        return json.loads(self._store.get_meta("rotation").decode())

    def _rotation_dst_gen(self) -> int:
        return self._rotation_state()["dst_gen"]


def _slot_aad(slot_id: str) -> bytes:
    return b"slot:" + slot_id.encode()


def _key_aad(key_id: str) -> bytes:
    return b"key:" + key_id.encode()


def _msg_aad(key_id: str, aad: bytes) -> bytes:
    return b"msg:" + key_id.encode() + b":" + aad


def _slot_payload(
    slot_id: str, kek: bytes, lib_id: bytes, peer_kek: bytes | None
) -> bytes:
    data = {
        "check": lib_id.hex(),
        "peer": None if peer_kek is None else peer_kek.hex(),
    }
    return crypto.wrap_key(kek, json.dumps(data).encode(), _slot_aad(slot_id))
