"""基础功能与安全属性测试。"""
import sqlite3

import pytest
from cryptography.exceptions import InvalidTag

from keyescrow import AuthError, KeyStore, KeyStoreError
from keyescrow import crypto


@pytest.fixture()
def lib_path(tmp_path):
    return str(tmp_path / "lib.db")


def test_create_open_encrypt_decrypt(lib_path):
    ks = KeyStore.create(lib_path, "pw-1")
    kid = ks.generate_key()
    ct = ks.encrypt(kid, b"short message")
    assert ks.decrypt(kid, ct) == b"short message"
    ks.close()
    ks = KeyStore.open(lib_path, "pw-1")
    assert ks.decrypt(kid, ct) == b"short message"
    ks.close()


def test_public_api_never_returns_key_material(lib_path):
    ks = KeyStore.create(lib_path, "pw-1")
    kid = ks.generate_key()
    assert isinstance(kid, str)
    ct = ks.encrypt(kid, b"x")
    assert isinstance(ct, bytes)
    ks.close()


def test_wrong_passphrase_rejected(lib_path):
    KeyStore.create(lib_path, "right").close()
    with pytest.raises(AuthError):
        KeyStore.open(lib_path, "wrong")


def test_unknown_key_id(lib_path):
    ks = KeyStore.create(lib_path, "pw")
    with pytest.raises(KeyStoreError):
        ks.decrypt("no-such-key", b"00")
    ks.close()


def test_tampered_message_rejected(lib_path):
    ks = KeyStore.create(lib_path, "pw")
    kid = ks.generate_key()
    ct = bytearray(ks.encrypt(kid, b"data"))
    ct[-1] ^= 1
    with pytest.raises(InvalidTag):
        ks.decrypt(kid, bytes(ct))
    ks.close()


def test_tampered_stored_key_record_rejected(lib_path):
    ks = KeyStore.create(lib_path, "pw")
    kid = ks.generate_key()
    ct = ks.encrypt(kid, b"data")
    ks.close()
    conn = sqlite3.connect(lib_path)
    blob = bytearray(conn.execute("SELECT ct FROM keys WHERE key_id=?", (kid,)).fetchone()[0])
    blob[-1] ^= 1
    conn.execute("UPDATE keys SET ct=? WHERE key_id=?", (bytes(blob), kid))
    conn.commit(); conn.close()
    ks = KeyStore.open(lib_path, "pw")
    with pytest.raises(InvalidTag):
        ks.decrypt(kid, ct)
    ks.close()


def test_cross_key_id_record_swap_rejected(lib_path):
    """把 key B 的受保护记录换到 key A 名下，不得被当作 A 的有效密钥。"""
    ks = KeyStore.create(lib_path, "pw")
    ka = ks.generate_key()
    kb = ks.generate_key()
    ct_a = ks.encrypt(ka, b"message-for-a")
    ks.close()
    conn = sqlite3.connect(lib_path)
    gen_b, ct_b = conn.execute("SELECT gen, ct FROM keys WHERE key_id=?", (kb,)).fetchone()
    conn.execute("UPDATE keys SET gen=?, ct=? WHERE key_id=?", (gen_b, ct_b, ka))
    conn.commit(); conn.close()
    ks = KeyStore.open(lib_path, "pw")
    with pytest.raises(InvalidTag):
        ks.decrypt(ka, ct_a)
    ks.close()


def test_same_passphrase_different_libraries_independent(tmp_path):
    p1, p2 = str(tmp_path / "a.db"), str(tmp_path / "b.db")
    KeyStore.create(p1, "same-pw").close()
    KeyStore.create(p2, "same-pw").close()
    conn1, conn2 = sqlite3.connect(p1), sqlite3.connect(p2)
    salt1 = conn1.execute("SELECT salt FROM slots").fetchone()[0]
    salt2 = conn2.execute("SELECT salt FROM slots").fetchone()[0]
    assert salt1 != salt2
    assert crypto.derive_kek("same-pw", salt1) != crypto.derive_kek("same-pw", salt2)


def test_kdf_cost_at_least_600k_generic_hashes():
    assert crypto.KDF_ITERATIONS >= 600_000
