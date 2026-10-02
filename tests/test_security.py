"""Security property tests: tamper evidence, record binding, KDF independence."""

import sqlite3
import time

import pytest

from keyescrow import AuthenticationError, EscrowStore, IntegrityError
from keyescrow import crypto


@pytest.fixture()
def store_path(tmp_path):
    return str(tmp_path / "store.db")


def test_ciphertext_tamper_rejected(store_path):
    store = EscrowStore.create(store_path, "pw")
    key_id = store.generate_key()
    ct = bytearray(store.encrypt(key_id, b"payload"))
    for pos in (0, len(ct) // 2, len(ct) - 1):
        bad = bytearray(ct)
        bad[pos] ^= 0x01
        with pytest.raises(IntegrityError):
            store.decrypt(key_id, bytes(bad))
    store.close()


def test_wrapped_record_swap_between_key_ids_rejected(store_path):
    store = EscrowStore.create(store_path, "pw")
    id_a, id_b = store.generate_keys(2)
    ct_a = store.encrypt(id_a, b"secret-a")
    store.close()

    # Swap the wrapped key material rows of the two key ids on disk.
    conn = sqlite3.connect(store_path)
    row_a = conn.execute("SELECT wrapped FROM keys WHERE key_id = ?", (id_a,)).fetchone()
    row_b = conn.execute("SELECT wrapped FROM keys WHERE key_id = ?", (id_b,)).fetchone()
    conn.execute("UPDATE keys SET wrapped = ? WHERE key_id = ?", (row_a[0], id_b))
    conn.execute("UPDATE keys SET wrapped = ? WHERE key_id = ?", (row_b[0], id_a))
    conn.commit()
    conn.close()

    store = EscrowStore.open(store_path, "pw")
    # The swapped records must not be silently accepted as valid keys.
    with pytest.raises(IntegrityError):
        store.decrypt(id_a, ct_a)
    with pytest.raises(IntegrityError):
        store.encrypt(id_b, b"x")
    store.close()


def test_wrapped_record_tamper_rejected(store_path):
    store = EscrowStore.create(store_path, "pw")
    key_id = store.generate_key()
    ct = store.encrypt(key_id, b"data")
    store.close()

    conn = sqlite3.connect(store_path)
    wrapped = bytearray(conn.execute("SELECT wrapped FROM keys WHERE key_id = ?", (key_id,)).fetchone()[0])
    wrapped[-1] ^= 0x01
    conn.execute("UPDATE keys SET wrapped = ? WHERE key_id = ?", (bytes(wrapped), key_id))
    conn.commit()
    conn.close()

    store = EscrowStore.open(store_path, "pw")
    with pytest.raises(IntegrityError):
        store.decrypt(key_id, ct)
    store.close()


def test_same_passphrase_different_libraries_are_independent(tmp_path):
    path_a = str(tmp_path / "a.db")
    path_b = str(tmp_path / "b.db")
    store_a = EscrowStore.create(path_a, "same-pw")
    store_b = EscrowStore.create(path_b, "same-pw")
    key_a = store_a.generate_key()
    ct_a = store_a.encrypt(key_a, b"hello")
    store_a.close()
    store_b.close()

    # salts differ, so derived KEKs differ even for the same passphrase
    conn_a = sqlite3.connect(path_a)
    salt_a, wrapped_a = conn_a.execute("SELECT salt, wrapped FROM slots WHERE slot = 0").fetchone()
    conn_b = sqlite3.connect(path_b)
    salt_b, wrapped_b = conn_b.execute("SELECT salt, wrapped FROM slots WHERE slot = 0").fetchone()
    assert salt_a != salt_b
    assert crypto.derive_kek("same-pw", salt_a) != crypto.derive_kek("same-pw", salt_b)

    # moving a wrapped business key record to the other library must fail
    row = conn_a.execute("SELECT key_id, generation, wrapped FROM keys WHERE key_id = ?", (key_a,)).fetchone()
    conn_b.execute("INSERT INTO keys (key_id, generation, wrapped) VALUES (?, ?, ?)", row)
    conn_b.commit()
    conn_a.close()
    conn_b.close()
    store_b = EscrowStore.open(path_b, "same-pw")
    with pytest.raises(IntegrityError):
        store_b.decrypt(key_a, ct_a)
    store_b.close()


def test_old_protection_secret_cannot_open_new_records(store_path):
    """After rotation, the pre-rotation KEK must not unwrap new records."""
    store = EscrowStore.create(store_path, "old-pw")
    key_id = store.generate_key()
    ct = store.encrypt(key_id, b"before")
    store.close()

    # capture the pre-rotation protection secret (salt + wrapped master blob)
    conn = sqlite3.connect(store_path)
    old_salt, old_wrapped = conn.execute("SELECT salt, wrapped FROM slots WHERE slot = 0").fetchone()
    conn.close()
    old_kek = crypto.derive_kek("old-pw", old_salt)
    old_master = crypto.aead_decrypt(old_kek, old_wrapped, b"keyescrow:v1:slot")

    store = EscrowStore.open(store_path, "old-pw")
    store.start_rotation("req-1", "new-pw")
    while not store.advance_rotation().complete:
        pass
    ct_after = store.encrypt(key_id, b"after")
    key_id2 = store.generate_key()
    store.close()

    # old passphrase is rejected
    with pytest.raises(AuthenticationError):
        EscrowStore.open(store_path, "old-pw")

    # the old master key cannot unwrap any record written after rotation
    conn = sqlite3.connect(store_path)
    wrapped2 = conn.execute("SELECT wrapped FROM keys WHERE key_id = ?", (key_id2,)).fetchone()[0]
    gen2 = conn.execute("SELECT generation FROM keys WHERE key_id = ?", (key_id2,)).fetchone()[0]
    conn.close()
    from keyescrow.store import _wrap_aad

    with pytest.raises(IntegrityError):
        crypto.aead_decrypt(old_master, wrapped2, _wrap_aad(key_id2, gen2))

    # new passphrase still decrypts pre-rotation ciphertexts
    store = EscrowStore.open(store_path, "new-pw")
    assert store.decrypt(key_id, ct) == b"before"
    assert store.decrypt(key_id, ct_after) == b"after"
    store.close()


def test_kdf_cost_at_least_600k_hash_equivalents():
    # Each PBKDF2-HMAC-SHA256 iteration evaluates HMAC twice (~4 SHA-256
    # compression runs), so 600k iterations cost >= 1.2M generic hashes.
    assert crypto.KDF_ITERATIONS >= 600_000
    salt = crypto.random_bytes(crypto.SALT_SIZE)
    start = time.perf_counter()
    crypto.derive_kek("pw", salt)
    elapsed = time.perf_counter() - start
    # sanity: derivation is deliberately expensive but must stay usable
    assert elapsed > 0.05
    assert elapsed < 10.0
