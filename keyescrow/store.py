"""SQLite-backed AES-256 business key escrow store.

Layout of protection layers:

* A random 256-bit *master key* wraps every business key (AES-256-GCM,
  AAD binds the key id and the master-key generation).
* The master key is itself wrapped by a KEK derived from the caller
  supplied passphrase (PBKDF2-HMAC-SHA256, per-library random salt).
* A rotation generates a fresh master key and re-wraps business keys in
  committed batches of at most 100, so progress is crash recoverable.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import time
from dataclasses import dataclass

from . import crypto
from .errors import (
    AuthenticationError,
    EscrowError,
    IntegrityError,
    KeyNotFoundError,
    RequestMismatchError,
    RotationStateError,
    StoreExistsError,
    StoreNotFoundError,
)

SCHEMA_VERSION = 1

#: Maximum number of business keys re-wrapped per committed batch.
MAX_BATCH = 100

_SLOT_AAD = b"keyescrow:v1:slot"
_OLD_MASTER_AAD = b"keyescrow:v1:old-master"

# Test hook: when set, transactions sleep this many milliseconds before
# COMMIT so crash-recovery tests can reliably kill the process mid-commit.
_COMMIT_DELAY_MS = int(os.environ.get("KEYESCROW_COMMIT_DELAY_MS", "0"))


def _pre_commit_pause() -> None:
    if _COMMIT_DELAY_MS:
        time.sleep(_COMMIT_DELAY_MS / 1000.0)


def _wrap_aad(key_id: str, generation: int) -> bytes:
    return b"keyescrow:v1:wrap:" + key_id.encode("ascii") + b":" + str(generation).encode("ascii")


def _msg_aad(key_id: str, aad: bytes) -> bytes:
    return b"keyescrow:v1:msg:" + key_id.encode("ascii") + b":" + aad

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS slots (
    slot     INTEGER PRIMARY KEY,
    salt     BLOB NOT NULL,
    wrapped  BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
    key_id     TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    wrapped    BLOB NOT NULL
);
"""


@dataclass(frozen=True)
class RotationStatus:
    """Snapshot of the rotation state machine."""

    state: str  # "idle" or "rotating"
    request_id: str | None
    total: int
    done: int

    @property
    def complete(self) -> bool:
        """True when no rotation is in progress."""
        return self.state == "idle"


class EscrowStore:
    """Escrow store handle. Use :meth:`create` or :meth:`open`."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._masters: dict[int, bytes] = {}
        self._keks: dict[int, bytes] = {}
        self._state = "idle"
        self._current_gen = 1
        self._pending_gen: int | None = None
        self._rotation_request: str | None = None
        self._last_completed: str | None = None

    # -- internal helpers -----------------------------------------------

    def _load_state(self) -> None:
        meta = {k: v for k, v in self._conn.execute("SELECT key, value FROM meta")}
        if int(meta.get("schema_version", "0")) != SCHEMA_VERSION:
            raise EscrowError("unsupported schema version")
        self._state = str(meta["state"])
        self._current_gen = int(meta["current_gen"])
        self._pending_gen = int(meta["pending_gen"]) if "pending_gen" in meta else None
        self._rotation_request = meta.get("rotation_request")
        self._last_completed = meta.get("last_completed_request")

    def _business_key(self, key_id: str) -> bytes:
        row = self._conn.execute(
            "SELECT generation, wrapped FROM keys WHERE key_id = ?", (key_id,)
        ).fetchone()
        if row is None:
            raise KeyNotFoundError(key_id)
        generation, wrapped = int(row[0]), row[1]
        master = self._masters.get(generation)
        if master is None:
            raise EscrowError("master key for generation unavailable")
        return crypto.aead_decrypt(master, wrapped, _wrap_aad(key_id, generation))

    def _finalize_txn(self, new_gen: int) -> None:
        """Rotation finalization; must run inside an open transaction."""
        self._conn.execute("DELETE FROM slots WHERE slot = 0")
        self._conn.execute("UPDATE slots SET slot = 0 WHERE slot = 1")
        self._conn.execute(
            "DELETE FROM meta WHERE key IN ('pending_gen', 'old_master_wrapped', 'rotation_request')"
        )
        self._conn.execute("UPDATE meta SET value = 'idle' WHERE key = 'state'")
        self._conn.execute("UPDATE meta SET value = ? WHERE key = 'current_gen'", (str(new_gen),))
        if self._rotation_request is not None:
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('last_completed_request', ?)",
                (self._rotation_request,),
            )

    # -- lifecycle ------------------------------------------------------

    @classmethod
    def create(cls, path: str, passphrase: str) -> "EscrowStore":
        """Create a new store at ``path`` protected by ``passphrase``."""
        if os.path.exists(path) and os.path.getsize(path) > 0:
            raise StoreExistsError(path)
        conn = sqlite3.connect(path, isolation_level=None)
        conn.executescript(_SCHEMA)
        store = cls(conn)
        master = crypto.random_bytes(crypto.KEY_SIZE)
        salt = crypto.random_bytes(crypto.SALT_SIZE)
        kek = crypto.derive_kek(passphrase, salt)
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            conn.execute("INSERT INTO meta (key, value) VALUES ('state', 'idle')")
            conn.execute("INSERT INTO meta (key, value) VALUES ('current_gen', '1')")
            conn.execute(
                "INSERT INTO slots (slot, salt, wrapped) VALUES (0, ?, ?)",
                (salt, crypto.aead_encrypt(kek, master, _SLOT_AAD)),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            conn.close()
            raise
        store._masters = {1: master}
        store._keks = {0: kek}
        store._load_state()
        return store

    @classmethod
    def open(cls, path: str, passphrase: str) -> "EscrowStore":
        """Open an existing store; ``passphrase`` may be the current one or,
        while a rotation is in progress, either the old or the new one."""
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            raise StoreNotFoundError(path)
        conn = sqlite3.connect(path, isolation_level=None)
        store = cls(conn)
        store._load_state()
        target_gen = store._pending_gen if store._state == "rotating" else store._current_gen
        unlocked = False
        for slot, salt, wrapped in conn.execute(
            "SELECT slot, salt, wrapped FROM slots ORDER BY slot"
        ):
            kek = crypto.derive_kek(passphrase, bytes(salt))
            try:
                master = crypto.aead_decrypt(kek, bytes(wrapped), _SLOT_AAD)
            except IntegrityError:
                continue
            store._keks[int(slot)] = kek
            store._masters[target_gen] = master
            unlocked = True
            break
        if not unlocked:
            conn.close()
            raise AuthenticationError("passphrase does not unlock this store")
        if store._state == "rotating":
            old_wrapped = conn.execute(
                "SELECT value FROM meta WHERE key = 'old_master_wrapped'"
            ).fetchone()[0]
            old_master = crypto.aead_decrypt(
                store._masters[target_gen], bytes(old_wrapped), _OLD_MASTER_AAD
            )
            store._masters[store._current_gen] = old_master
        return store

    def close(self) -> None:
        """Close the underlying database handle."""
        self._conn.close()

    def __enter__(self) -> "EscrowStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- business keys --------------------------------------------------

    def generate_key(self) -> str:
        """Create a new business key and return its key id."""
        return self.generate_keys(1)[0]

    def generate_keys(self, count: int) -> list[str]:
        """Create ``count`` business keys in one transaction; returns key ids."""
        if self._state != "idle":
            raise RotationStateError("cannot generate keys while a rotation is in progress")
        if count < 1:
            raise ValueError("count must be positive")
        generation = self._current_gen
        master = self._masters[generation]
        key_ids: list[str] = []
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            for _ in range(count):
                key_id = secrets.token_hex(16)
                business_key = crypto.random_bytes(crypto.KEY_SIZE)
                self._conn.execute(
                    "INSERT INTO keys (key_id, generation, wrapped) VALUES (?, ?, ?)",
                    (
                        key_id,
                        generation,
                        crypto.aead_encrypt(master, business_key, _wrap_aad(key_id, generation)),
                    ),
                )
                key_ids.append(key_id)
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        return key_ids

    def encrypt(self, key_id: str, plaintext: bytes, aad: bytes = b"") -> bytes:
        """Encrypt ``plaintext`` under the business key ``key_id``."""
        business_key = self._business_key(key_id)
        return crypto.aead_encrypt(business_key, plaintext, _msg_aad(key_id, aad))

    def decrypt(self, key_id: str, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """Decrypt data produced by :meth:`encrypt`."""
        business_key = self._business_key(key_id)
        return crypto.aead_decrypt(business_key, ciphertext, _msg_aad(key_id, aad))

    # -- rotation -------------------------------------------------------

    def start_rotation(self, request_id: str, new_passphrase: str) -> RotationStatus:
        """Begin or resume a passphrase rotation identified by ``request_id``."""
        if self._state == "rotating":
            if request_id != self._rotation_request:
                raise RequestMismatchError(
                    f"rotation already in progress for request {self._rotation_request!r}"
                )
            return self.rotation_status()
        if request_id is not None and request_id == self._last_completed:
            return self.rotation_status()
        old_gen = self._current_gen
        new_gen = old_gen + 1
        old_master = self._masters[old_gen]
        kek_old = self._keks.get(0)
        if kek_old is None:
            raise EscrowError("current passphrase KEK unavailable; reopen the store")
        new_master = crypto.random_bytes(crypto.KEY_SIZE)
        salt_new = crypto.random_bytes(crypto.SALT_SIZE)
        kek_new = crypto.derive_kek(new_passphrase, salt_new)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "UPDATE slots SET wrapped = ? WHERE slot = 0",
                (crypto.aead_encrypt(kek_old, new_master, _SLOT_AAD),),
            )
            self._conn.execute(
                "INSERT INTO slots (slot, salt, wrapped) VALUES (1, ?, ?)",
                (salt_new, crypto.aead_encrypt(kek_new, new_master, _SLOT_AAD)),
            )
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('pending_gen', ?)", (str(new_gen),)
            )
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('rotation_request', ?)", (request_id,)
            )
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES ('old_master_wrapped', ?)",
                (crypto.aead_encrypt(new_master, old_master, _OLD_MASTER_AAD),),
            )
            self._conn.execute("UPDATE meta SET value = 'rotating' WHERE key = 'state'")
            _pre_commit_pause()
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._masters[new_gen] = new_master
        self._keks[1] = kek_new
        self._load_state()
        return self.rotation_status()

    def advance_rotation(self, max_keys: int = MAX_BATCH) -> RotationStatus:
        """Re-wrap up to ``max_keys`` business keys, commit, return status."""
        if self._state != "rotating":
            return self.rotation_status()
        max_keys = max(1, min(int(max_keys), MAX_BATCH))
        old_gen = self._current_gen
        new_gen = self._pending_gen
        assert new_gen is not None
        old_master = self._masters[old_gen]
        new_master = self._masters[new_gen]
        rows = self._conn.execute(
            "SELECT key_id, wrapped FROM keys WHERE generation = ? ORDER BY key_id LIMIT ?",
            (old_gen, max_keys),
        ).fetchall()
        self._conn.execute("BEGIN IMMEDIATE")
        finalized = False
        try:
            for key_id, wrapped in rows:
                business_key = crypto.aead_decrypt(
                    old_master, bytes(wrapped), _wrap_aad(key_id, old_gen)
                )
                self._conn.execute(
                    "UPDATE keys SET generation = ?, wrapped = ? WHERE key_id = ? AND generation = ?",
                    (
                        new_gen,
                        crypto.aead_encrypt(new_master, business_key, _wrap_aad(key_id, new_gen)),
                        key_id,
                        old_gen,
                    ),
                )
            remaining = self._conn.execute(
                "SELECT COUNT(*) FROM keys WHERE generation = ?", (old_gen,)
            ).fetchone()[0]
            if remaining == 0:
                self._finalize_txn(new_gen)
                finalized = True
            _pre_commit_pause()
            self._conn.execute("COMMIT")
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        if finalized:
            self._masters = {new_gen: new_master}
            self._keks = {0: self._keks[1]} if 1 in self._keks else {}
        self._load_state()
        return self.rotation_status()

    def rotation_status(self) -> RotationStatus:
        """Return the current rotation progress without changing it."""
        total = self._conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        if self._state == "rotating":
            done = self._conn.execute(
                "SELECT COUNT(*) FROM keys WHERE generation = ?", (self._pending_gen,)
            ).fetchone()[0]
            return RotationStatus("rotating", self._rotation_request, total, done)
        return RotationStatus("idle", self._last_completed, total, total)
