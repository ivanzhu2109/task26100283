"""真实进程终止后的恢复测试：子进程用 os._exit 模拟 kill -9。"""
import json
import os
import subprocess
import sys
import time

import pytest

from keyescrow import AuthError, KeyStore

HERE = os.path.dirname(os.path.abspath(__file__))
WORKER = os.path.join(HERE, "crash_worker.py")
OLD_PW = "old-pw"
NEW_PW = "new-pw"
REQ_ID = "req-crash"
NKEYS = 250
BATCH = 100


def run_worker(*args):
    proc = subprocess.run(
        [sys.executable, WORKER, *args], capture_output=True, text=True, timeout=300
    )
    lines = [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
    return proc.returncode, lines


@pytest.fixture()
def crashed_lib(tmp_path):
    db = str(tmp_path / "lib.db")
    sidecar = str(tmp_path / "expected.json")
    run_worker("setup", db, sidecar, str(NKEYS))
    with open(sidecar) as f:
        expected = json.load(f)
    return db, expected


def check_all_messages(db, expected, pw):
    ks = KeyStore.open(db, pw)
    for kid, rec in expected.items():
        assert ks.decrypt(kid, bytes.fromhex(rec["ct"])) == bytes.fromhex(rec["pt"])
    ks.close()


@pytest.mark.parametrize("crash_after", [0, 1, 2])
def test_crash_mid_rotation_resume_with_either_passphrase(crashed_lib, crash_after):
    db, expected = crashed_lib
    _, lines = run_worker("rotate", db, str(crash_after), str(BATCH))
    confirmed = [l["status"]["done"] for l in lines if l["phase"] == "advanced"]
    last_confirmed = confirmed[-1] if confirmed else 0

    # 用旧口令恢复：进度不倒退，历史消息逐字节一致
    ks = KeyStore.open(db, OLD_PW)
    st = ks.rotation_status()
    assert st["status"] == "active"
    assert st["done"] >= last_confirmed - BATCH  # 未确认部分最多重做 100
    assert st["done"] <= last_confirmed
    for kid, rec in expected.items():
        assert ks.decrypt(kid, bytes.fromhex(rec["ct"])) == bytes.fromhex(rec["pt"])
    ks.close()

    # 用新口令恢复：同样可用全部密钥，且进度一致
    ks = KeyStore.open(db, NEW_PW)
    assert ks.rotation_status()["done"] == st["done"]
    for kid, rec in expected.items():
        assert ks.decrypt(kid, bytes.fromhex(rec["ct"])) == bytes.fromhex(rec["pt"])

    # 重试同一请求号：接续进度而非重启
    st2 = ks.start_rotation(REQ_ID, NEW_PW)
    assert st2["done"] == st["done"]
    while ks.rotation_status()["status"] == "active":
        ks.advance_rotation(BATCH)
    assert ks.rotation_status() == {"status": "completed", "request_id": REQ_ID}
    ks.close()

    # 完成后：旧口令被拒，新口令解密全部历史消息
    with pytest.raises(AuthError):
        KeyStore.open(db, OLD_PW)
    check_all_messages(db, expected, NEW_PW)


def test_crash_at_finalize_boundary(crashed_lib):
    db, expected = crashed_lib
    run_worker("rotate-until-done", db, str(BATCH))

    # 恢复后处于未完成或已完成之一，且口令有效性与状态一致
    try:
        ks = KeyStore.open(db, NEW_PW)
        new_ok = True
    except AuthError:
        new_ok = False
    assert new_ok
    st = ks.rotation_status()
    if st["status"] == "active":
        # 未完成：旧口令也必须能打开
        ks.close()
        ks_old = KeyStore.open(db, OLD_PW)
        ks_old.close()
        ks = KeyStore.open(db, NEW_PW)
        while ks.rotation_status()["status"] == "active":
            ks.advance_rotation(BATCH)
    ks.close()

    # 最终：只有新口令有效，全部消息逐字节一致
    with pytest.raises(AuthError):
        KeyStore.open(db, OLD_PW)
    check_all_messages(db, expected, NEW_PW)

    # 已完成请求的重试仍返回完成，不另起一轮
    ks = KeyStore.open(db, NEW_PW)
    assert ks.start_rotation(REQ_ID, NEW_PW) == {
        "status": "completed",
        "request_id": REQ_ID,
    }
    ks.close()


def test_reopen_and_decrypt_within_2s_after_crash(crashed_lib):
    db, expected = crashed_lib
    run_worker("rotate", db, "1", str(BATCH))
    t0 = time.perf_counter()
    ks = KeyStore.open(db, NEW_PW)
    st = ks.rotation_status()
    kid = next(iter(expected))
    ks.decrypt(kid, bytes.fromhex(expected[kid]["ct"]))
    ks.close()
    elapsed = time.perf_counter() - t0
    # 口令派生（约 0.3s/次）不计入预算
    assert elapsed - 0.6 < 2.0, f"recovery too slow: {elapsed:.2f}s"
    assert st["status"] == "active"
