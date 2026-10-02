"""SQLite 持久化层。

三张表：
- meta(key, value)：库标识、KDF 参数、换代状态等单值元数据。
- slots(slot_id, salt, payload)：口令槽位。payload 为 KEK 加密的 JSON，
  内含校验值与（换代期间的）桥接秘密。空闲时只有槽位 'A'，
  换代期间存在 'A' 与 'B'，完成后只剩 'B'。
- keys(key_id, gen, ct)：受保护业务密钥。ct = AES-GCM(KEK_gen, DEK)，
  AAD 绑定 key_id，防止跨 Key ID 互换记录。

所有多行写都在显式事务中完成，进程在任意落盘阶段被杀，
SQLite 事务保证要么整批生效要么整体回滚。
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS slots (
    slot_id TEXT PRIMARY KEY,
    salt    BLOB NOT NULL,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
    key_id TEXT PRIMARY KEY,
    gen    INTEGER NOT NULL,
    ct     BLOB NOT NULL
);
"""


class Store:
    """对 escrow 库文件的薄封装，不含业务逻辑。"""

    def __init__(self, path: str) -> None:
        self.path = path
        self.conn: sqlite3.Connection | None = None

    def open(self) -> None:
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.executescript(_SCHEMA)

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """显式事务：正常结束提交，异常回滚。"""
        assert self.conn is not None
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            yield
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise

    # ---- meta ----
    def get_meta(self, key: str) -> bytes | None:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        return None if row is None else bytes(row[0])

    def set_meta(self, key: str, value: bytes) -> None:
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # ---- slots ----
    def get_slots(self) -> dict[str, tuple[bytes, bytes]]:
        rows = self.conn.execute("SELECT slot_id, salt, payload FROM slots").fetchall()
        return {r[0]: (bytes(r[1]), bytes(r[2])) for r in rows}

    def put_slot(self, slot_id: str, salt: bytes, payload: bytes) -> None:
        self.conn.execute(
            "INSERT INTO slots(slot_id,salt,payload) VALUES(?,?,?) "
            "ON CONFLICT(slot_id) DO UPDATE SET salt=excluded.salt, "
            "payload=excluded.payload",
            (slot_id, salt, payload),
        )

    def delete_slot(self, slot_id: str) -> None:
        self.conn.execute("DELETE FROM slots WHERE slot_id=?", (slot_id,))

    # ---- keys ----
    def put_key(self, key_id: str, gen: int, ct: bytes) -> None:
        self.conn.execute(
            "INSERT INTO keys(key_id,gen,ct) VALUES(?,?,?)", (key_id, gen, ct)
        )

    def get_key(self, key_id: str) -> tuple[int, bytes] | None:
        row = self.conn.execute(
            "SELECT gen, ct FROM keys WHERE key_id=?", (key_id,)
        ).fetchone()
        return None if row is None else (row[0], bytes(row[1]))

    def count_keys(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM keys").fetchone()[0]

    def fetch_batch(self, gen: int, cursor: str, limit: int) -> list[tuple[str, bytes]]:
        """按 key_id 顺序取 gen 匹配且 key_id > cursor 的至多 limit 条。"""
        rows = self.conn.execute(
            "SELECT key_id, ct FROM keys WHERE gen=? AND key_id>? "
            "ORDER BY key_id LIMIT ?",
            (gen, cursor, limit),
        ).fetchall()
        return [(r[0], bytes(r[1])) for r in rows]

    def update_key(self, key_id: str, gen: int, ct: bytes) -> None:
        self.conn.execute(
            "UPDATE keys SET gen=?, ct=? WHERE key_id=?", (gen, ct, key_id)
        )
