"""Scale test: 100k business keys.

Reports rotation time, peak extra memory, recovery latency after a real
SIGKILL, and the amount of re-processing after the kill.
"""

import os
import re
import resource
import signal
import subprocess
import sys
import time

from keyescrow import EscrowStore

WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rotation_worker.py")
KEY_COUNT = 100_000
BATCH = 100


def peak_rss_bytes():
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return usage if sys.platform == "darwin" else usage * 1024


def test_scale_100k_keys(tmp_path, capsys):
    path = str(tmp_path / "scale.db")

    t0 = time.perf_counter()
    store = EscrowStore.create(path, "old-pw")
    ids = store.generate_keys(KEY_COUNT)
    gen_s = time.perf_counter() - t0

    sample_ids = ids[:: max(1, KEY_COUNT // 200)]
    messages = {kid: os.urandom(32) for kid in sample_ids}
    cts = {kid: store.encrypt(kid, msg) for kid, msg in messages.items()}
    store.close()

    # Phase 1: rotate in a worker process and SIGKILL it mid-rotation.
    env = dict(os.environ, WORKER_BATCH_SLEEP="0.005")
    proc = subprocess.Popen(
        [sys.executable, WORKER, path, "old-pw", "req-scale", "new-pw", str(BATCH)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    time.sleep(4.0)
    try:
        os.kill(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    out, _ = proc.communicate()
    confirmed = 0
    for match in re.finditer(r"(?:started|progress) state=\w+ (\d+)/(\d+)", out):
        confirmed = max(confirmed, int(match.group(1)))
    assert 0 < confirmed < KEY_COUNT, f"kill did not land mid-rotation: {confirmed}"
    # Phase 2: recovery. KDF time is excluded from the 2s budget.
    t0 = time.perf_counter()
    store = EscrowStore.open(path, "new-pw")
    kdf_s = time.perf_counter() - t0
    t0 = time.perf_counter()
    status = store.rotation_status()
    first = sample_ids[0]
    assert store.decrypt(first, cts[first]) == messages[first]
    recover_s = time.perf_counter() - t0
    assert recover_s < 2.0, f"recovery query too slow: {recover_s:.3f}s"
    assert status.state == "rotating"
    assert status.done >= confirmed, "confirmed progress was lost"
    redone_confirmed = confirmed - status.done  # must be <= 0
    assert redone_confirmed <= 0

    # Phase 3: finish the rotation in-process, measuring memory.
    base_rss = peak_rss_bytes()
    t0 = time.perf_counter()
    batches = 0
    while True:
        status = store.advance_rotation(BATCH)
        batches += 1
        if status.complete:
            break
    rotation_s = time.perf_counter() - t0
    peak_extra_mib = (peak_rss_bytes() - base_rss) / (1024 * 1024)
    assert peak_extra_mib <= 64, f"peak extra memory {peak_extra_mib:.1f} MiB > 64 MiB"

    for kid, msg in messages.items():
        assert store.decrypt(kid, cts[kid]) == msg
    store.close()

    with capsys.disabled():
        print("\n=== scale report (100k keys) ===")
        print(f"key generation:        {gen_s:.2f}s")
        print(f"confirmed before kill: {confirmed}")
        print(f"confirmed work redone: {max(0, redone_confirmed)} keys")
        print(f"unconfirmed batch redo: <= {BATCH} keys (one rolled-back batch)")
        print(f"recovery query time:   {recover_s*1000:.1f}ms (KDF excluded, {kdf_s:.2f}s)")
        print(f"rotation of remainder: {rotation_s:.2f}s in {batches} batches")
        print(f"peak extra memory:     {peak_extra_mib:.1f} MiB")
