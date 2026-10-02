"""Basic functional tests: lifecycle, encrypt/decrypt, rotation state machine."""

import pytest

from keyescrow import (
    AuthenticationError,
    EscrowStore,
    KeyNotFoundError,
    RequestMismatchError,
    RotationStateError,
    StoreExistsError,
    StoreNotFoundError,
)


@pytest.fixture()
def store_path(tmp_path):
    return str(tmp_path / "store.db")


def test_create_open_roundtrip(store_path):
    store = EscrowStore.create(store_path, "pw")
    key_id = store.generate_key()
    ct = store.encrypt(key_id, b"message one")
    store.close()

    store = EscrowStore.open(store_path, "pw")
    assert store.decrypt(key_id, ct) == b"message one"
    store.close()


def test_public_api_never_returns_key_material(store_path):
    store = EscrowStore.create(store_path, "pw")
    key_id = store.generate_key()
    assert isinstance(key_id, str)
    ct = store.encrypt(key_id, b"x")
    assert isinstance(ct, bytes)
    store.close()


def test_create_refuses_existing_file(store_path):
    EscrowStore.create(store_path, "pw").close()
    with pytest.raises(StoreExistsError):
        EscrowStore.create(store_path, "pw")


def test_open_missing_file(store_path):
    with pytest.raises(StoreNotFoundError):
        EscrowStore.open(store_path, "pw")


def test_wrong_passphrase_rejected(store_path):
    EscrowStore.create(store_path, "right").close()
    with pytest.raises(AuthenticationError):
        EscrowStore.open(store_path, "wrong")


def test_unknown_key_id(store_path):
    store = EscrowStore.create(store_path, "pw")
    with pytest.raises(KeyNotFoundError):
        store.encrypt("no-such-key", b"x")
    with pytest.raises(KeyNotFoundError):
        store.decrypt("no-such-key", b"x")
    store.close()


def test_aad_is_authenticated(store_path):
    store = EscrowStore.create(store_path, "pw")
    key_id = store.generate_key()
    ct = store.encrypt(key_id, b"data", aad=b"context")
    assert store.decrypt(key_id, ct, aad=b"context") == b"data"
    with pytest.raises(Exception):
        store.decrypt(key_id, ct, aad=b"other")
    store.close()


def test_generate_key_forbidden_during_rotation(store_path):
    store = EscrowStore.create(store_path, "old")
    store.generate_key()
    store.start_rotation("req-1", "new")
    with pytest.raises(RotationStateError):
        store.generate_key()
    store.close()


def test_conflicting_request_id_rejected(store_path):
    store = EscrowStore.create(store_path, "old")
    store.start_rotation("req-1", "new")
    with pytest.raises(RequestMismatchError):
        store.start_rotation("req-2", "new")
    store.close()


def test_completed_request_retry_is_idempotent(store_path):
    store = EscrowStore.create(store_path, "old")
    key_id = store.generate_key()
    ct_before = store.encrypt(key_id, b"stable")
    store.start_rotation("req-1", "new")
    while not store.advance_rotation().complete:
        pass
    status = store.start_rotation("req-1", "totally-different-pw")
    assert status.complete
    assert status.request_id == "req-1"
    store.close()
    # the retry must not have started another rotation: only "new" works
    with pytest.raises(AuthenticationError):
        EscrowStore.open(store_path, "totally-different-pw")
    store = EscrowStore.open(store_path, "new")
    assert store.decrypt(key_id, ct_before) == b"stable"
    store.close()


def test_business_work_during_rotation_gaps(store_path):
    store = EscrowStore.create(store_path, "old")
    ids = store.generate_keys(50)
    cts = {kid: store.encrypt(kid, f"msg-{i}".encode()) for i, kid in enumerate(ids)}
    store.start_rotation("req-1", "new")
    while True:
        status = store.advance_rotation(10)
        for kid in ids[:5]:
            ct2 = store.encrypt(kid, b"mid-rotation")
            assert store.decrypt(kid, ct2) == b"mid-rotation"
        if status.complete:
            break
    for i, kid in enumerate(ids):
        assert store.decrypt(kid, cts[kid]) == f"msg-{i}".encode()
    store.close()
