"""换代流程测试（无进程终止，进程终止见 test_crash.py）。"""
import sqlite3

import pytest
from cryptography.exceptions import InvalidTag

from keyescrow import AuthError, KeyStore, RotationError
from keyescrow import crypto


def _read_slot(lib_path, slot_id):
    conn = sqlite3.connect(lib_path)
    row = conn.execute(
        "SELECT salt, payload FROM slots WHERE slot_id=?", (slot_id,)
    ).fetchone()
    conn.close()
    return row


@pytest.fixture()
def lib(tmp_path):
    path = str(tmp_path / "lib.db")
    ks = KeyStore.create(path, "old-pw")
    kids = [ks.generate_key() for _ in range(250)]
    msgs = {k: ks.encrypt(k, f"msg-{i}".encode()) for i, k in enumerate(kids)}
    ks.close()
    return path, kids, msgs


def _reopen_all(path, kids, msgs, pw):
    ks = KeyStore.open(path, pw)
    for k in kids:
        assert ks.decrypt(k, msgs[k]) == ks.decrypt(k, msgs[k])
    return ks


def test_rotation_progress_batches(lib):
    path, kids, msgs = lib
    ks = KeyStore.open(path, "old-pw")
    st = ks.start_rotation("req-1", "new-pw")
    assert st == {"status": "active", "request_id": "req-1", "done": 0, "total": 250}
    seen = 0
    while ks.rotation_status()["status"] == "active":
        st = ks.advance_rotation(100)
        if st["status"] == "active":
            assert st["done"] == min(seen + 100, 250)
            seen = st["done"]
    assert seen == 250
    assert ks.rotation_status() == {"status": "completed", "request_id": "req-1"}
    for k in kids:
        assert ks.decrypt(k, msgs[k]) is not None
    ks.close()


def test_confirmed_progress_needs_at_most_100_keys(lib):
    """每批 ≤100 即向调用方确认持久化进度。"""
    path, kids, msgs = lib
    ks = KeyStore.open(path, "old-pw")
    ks.start_rotation("req-1", "new-pw")
    st = ks.advance_rotation(100)
    assert st["done"] == 100
    ks.close()
    ks = KeyStore.open(path, "new-pw")
    assert ks.rotation_status()["done"] == 100  # 重启后已确认进度不回退
    ks.close()


def test_same_request_id_resumes_not_restarts(lib):
    path, kids, msgs = lib
    ks = KeyStore.open(path, "old-pw")
    ks.start_rotation("req-1", "new-pw")
    ks.advance_rotation(100)
    st = ks.start_rotation("req-1", "new-pw")  # 重试同一请求
    assert st["done"] == 100  # 接续进度而非重启
    ks.close()
    ks = KeyStore.open(path, "new-pw")
    st = ks.start_rotation("req-1", "new-pw")
    assert st["done"] == 100
    ks.close()


def test_completed_request_retry_returns_completed(lib):
    path, kids, msgs = lib
    ks = KeyStore.open(path, "old-pw")
    ks.start_rotation("req-1", "new-pw")
    while ks.rotation_status()["status"] == "active":
        ks.advance_rotation(100)
    st = ks.start_rotation("req-1", "new-pw")
    assert st == {"status": "completed", "request_id": "req-1"}
    ks.close()


def test_conflicting_request_id_rejected(lib):
    path, kids, msgs = lib
    ks = KeyStore.open(path, "old-pw")
    ks.start_rotation("req-1", "new-pw")
    with pytest.raises(RotationError):
        ks.start_rotation("req-2", "other-pw")
    ks.close()


def test_either_passphrase_opens_during_rotation(lib):
    path, kids, msgs = lib
    ks = KeyStore.open(path, "old-pw")
    ks.start_rotation("req-1", "new-pw")
    ks.advance_rotation(100)  # 让记录处于新旧混合状态
    ks.close()
    for pw in ("old-pw", "new-pw"):
        ks = KeyStore.open(path, pw)
        assert ks.rotation_status()["status"] == "active"
        for k in kids:  # 全部业务密钥均可用
            ks.decrypt(k, msgs[k])
        ks.close()


def test_old_passphrase_rejected_after_completion(lib):
    path, kids, msgs = lib
    ks = KeyStore.open(path, "old-pw")
    ks.start_rotation("req-1", "new-pw")
    while ks.rotation_status()["status"] == "active":
        ks.advance_rotation(100)
    ks.close()
    with pytest.raises(AuthError):
        KeyStore.open(path, "old-pw")
    ks = KeyStore.open(path, "new-pw")
    for k in kids:
        ks.decrypt(k, msgs[k])
    ks.close()


def test_old_protection_secret_cannot_unwrap_new_records(lib):
    """换代前的保护秘密（旧口令派生的 KEK）不能解开新的受保护记录。"""
    path, kids, msgs = lib
    salt, _ = _read_slot(path, "A")
    old_kek = crypto.derive_kek("old-pw", salt)
    ks = KeyStore.open(path, "old-pw")
    ks.start_rotation("req-1", "new-pw")
    while ks.rotation_status()["status"] == "active":
        ks.advance_rotation(100)
    ks.close()
    conn = sqlite3.connect(path)
    rows = conn.execute("SELECT key_id, gen, ct FROM keys").fetchall()
    conn.close()
    assert rows and all(gen == 1 for _, gen, _ in rows)
    for key_id, _, ct in rows:
        with pytest.raises(InvalidTag):
            crypto.unwrap_key(old_kek, ct, b"key:" + key_id.encode())


def test_key_ids_and_plaintexts_unchanged_by_rotation(lib):
    path, kids, msgs = lib
    ks = KeyStore.open(path, "old-pw")
    before = {k: ks.decrypt(k, c) for k, c in msgs.items()}
    ks.start_rotation("req-1", "new-pw")
    while ks.rotation_status()["status"] == "active":
        ks.advance_rotation(37)  # 非整百批次
    ks.close()
    ks = KeyStore.open(path, "new-pw")
    for k in kids:
        assert ks.decrypt(k, msgs[k]) == before[k]
    ks.close()


def test_no_key_generation_during_rotation(lib):
    path, kids, msgs = lib
    ks = KeyStore.open(path, "old-pw")
    ks.start_rotation("req-1", "new-pw")
    with pytest.raises(RotationError):
        ks.generate_key()
    ks.close()


def test_second_rotation_after_completion(lib):
    """完成后可用新请求号再换一代（槽位乒乓）。"""
    path, kids, msgs = lib
    ks = KeyStore.open(path, "old-pw")
    ks.start_rotation("req-1", "new-pw")
    while ks.rotation_status()["status"] == "active":
        ks.advance_rotation(100)
    ks.start_rotation("req-2", "third-pw")
    while ks.rotation_status()["status"] == "active":
        ks.advance_rotation(100)
    ks.close()
    with pytest.raises(AuthError):
        KeyStore.open(path, "new-pw")
    ks = KeyStore.open(path, "third-pw")
    for k in kids:
        ks.decrypt(k, msgs[k])
    ks.close()
