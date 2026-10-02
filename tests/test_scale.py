"""10 万把密钥规模测试：内存、恢复耗时、中断后重复处理量。"""
import json
import os
import resource
import subprocess
import sys
import time

import pytest

from keyescrow import AuthError, KeyStore

HERE = os.path.dirname(os.path.abspath(__file__))
WORKER = os.path.join(HERE, "crash_worker.py")
N = 100_000
BATCH = 100
MEM_LIMIT = 64 * 1024 * 1024  # 64 MiB
OLD_PW = "scale-old"
NEW_PW = "scale-new"
REQ = "req-scale"


def rss():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # macOS: bytes


@pytest.fixture(scope="module")
def scale_lib(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("scale")
    db = str(tmp / "scale.db")
    ks = KeyStore.create(db, OLD_PW)
    t0 = time.perf_counter()
    for i in range(N):
        ks.generate_key(f"key-{i:06d}")
    gen_s = time.perf_counter() - t0
    sample = {}
    for i in range(0, N, 997):  # 约 100 条抽样
        kid = f"key-{i:06d}"
        pt = f"scale-message-{i}".encode()
        sample[kid] = (pt, ks.encrypt(kid, pt))
    ks.close()
    print(f"\n[scale] generate {N} keys: {gen_s:.1f}s")
    return db, sample


def test_scale_rotation_memory_and_speed(scale_lib):
    db, sample = scale_lib
    base = rss()
    t0 = time.perf_counter()
    ks = KeyStore.open(db, OLD_PW)
    ks.start_rotation(REQ, NEW_PW)
    batches = 0
    while ks.rotation_status()["status"] == "active":
        ks.advance_rotation(BATCH)
        batches += 1
    rot_s = time.perf_counter() - t0
    extra = rss() - base
    print(f"[scale] rotation {N} keys: {rot_s:.1f}s, {batches} batches, "
          f"peak extra RSS {extra/1024/1024:.1f} MiB")
    assert extra < MEM_LIMIT, f"peak extra memory {extra} >= 64 MiB"
    for kid, (pt, ct) in sample.items():
        assert ks.decrypt(kid, ct) == pt
    ks.close()
    with pytest.raises(AuthError):
        KeyStore.open(db, OLD_PW)


def test_scale_crash_recovery_and_redo(scale_lib):
    """中断后：恢复 <2s（不含口令派生），重复处理量 ≤100。"""
    db, sample = scale_lib
    # 第二轮换代，推进 5 批后硬杀
    proc = subprocess.run(
        [sys.executable, WORKER, "rotate", db, "5", str(BATCH),
         NEW_PW, "scale-third", "req-scale-2"],
        capture_output=True, text=True, timeout=600,
    )
    lines = [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
    confirmed = [l["status"]["done"] for l in lines if l["phase"] == "advanced"]
    last_confirmed = confirmed[-1]

    # 测口令派生耗时以便扣除
    from keyescrow import crypto
    t0 = time.perf_counter()
    crypto.derive_kek("x", b"0" * 16)
    kdf_s = time.perf_counter() - t0

    t0 = time.perf_counter()
    ks = KeyStore.open(db, "scale-third")
    st = ks.rotation_status()
    kid = next(iter(sample))
    ks.decrypt(kid, sample[kid][1])
    recover_s = time.perf_counter() - t0 - kdf_s
    print(f"[scale] reopen+status+decrypt after crash: {recover_s:.3f}s "
          f"(KDF {kdf_s:.2f}s excluded)")
    assert recover_s < 2.0

    redo = last_confirmed - st["done"]
    print(f"[scale] confirmed before kill={last_confirmed}, "
          f"persisted done={st['done']}, redo={redo} keys")
    assert 0 <= redo <= BATCH

    # 用任一口令继续到完成，抽样消息逐字节一致
    while ks.rotation_status()["status"] == "active":
        ks.advance_rotation(BATCH)
    for k, (pt, ct) in sample.items():
        assert ks.decrypt(k, ct) == pt
    ks.close()
    with pytest.raises(AuthError):
        KeyStore.open(db, NEW_PW)
    ks = KeyStore.open(db, "scale-third")
    ks.close()
