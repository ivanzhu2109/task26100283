"""Crash-recovery tests: SIGKILL a real worker process mid-rotation and
verify progress, passphrase validity and message integrity after recovery."""

import os
import random
import re
import signal
import subprocess
import sys
import time

import pytest

from keyescrow import AuthenticationError, EscrowStore

WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rotation_worker.py")


def launch_worker(path, passphrase, request_id, new_passphrase, batch, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.Popen(
        [sys.executable, WORKER, path, passphrase, request_id, new_passphrase, str(batch)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def kill_hard(proc):
    try:
        os.kill(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def confirmed_progress(output):
    done = 0
    for match in re.finditer(r"(?:started|progress) state=\w+ (\d+)/(\d+)", output):
        done = max(done, int(match.group(1)))
    return done


def test_kill_mid_rotation_recover_with_both_passphrases(tmp_path):
    path = str(tmp_path / "store.db")
    store = EscrowStore.create(path, "old-pw")
    ids = store.generate_keys(350)
    messages = {kid: os.urandom(48) for kid in ids}
    cts = {kid: store.encrypt(kid, msg) for kid, msg in messages.items()}
    store.close()

    confirmed = 0
    worker_passphrases = ["old-pw", "new-pw"]
    rounds = 0
    while True:
        proc = launch_worker(
            path, worker_passphrases[rounds % 2], "req-rotate", "new-pw", 7
        )
        time.sleep(random.uniform(0.8, 2.0))
        kill_hard(proc)
        out, _ = proc.communicate()
        confirmed = max(confirmed, confirmed_progress(out))

        # The new passphrase must always open the store; progress must not
        # regress; every historical message must decrypt byte-identically.
        store = EscrowStore.open(path, "new-pw")
        status = store.rotation_status()
        assert status.done >= confirmed
        for kid, msg in messages.items():
            assert store.decrypt(kid, cts[kid]) == msg
        store.close()

        if status.state == "rotating":
            # Before completion the old passphrase alone must also work.
            store = EscrowStore.open(path, "old-pw")
            assert store.rotation_status().done >= confirmed
            for kid, msg in messages.items():
                assert store.decrypt(kid, cts[kid]) == msg
            store.close()
        else:
            # After completion the old passphrase must be rejected.
            with pytest.raises(AuthenticationError):
                EscrowStore.open(path, "old-pw")
            break
        rounds += 1
        assert rounds < 200, "rotation made no progress across kills"

    assert confirmed > 0, "worker never confirmed any batch"


def test_finalize_boundary_kill_is_all_or_nothing(tmp_path):
    for trial in range(8):
        path = str(tmp_path / f"store{trial}.db")
        store = EscrowStore.create(path, "old-pw")
        ids = store.generate_keys(5)
        messages = {kid: os.urandom(32) for kid in ids}
        cts = {kid: store.encrypt(kid, msg) for kid, msg in messages.items()}
        store.start_rotation("req-fin", "new-pw")
        while True:
            status = store.advance_rotation(4)
            if status.total - status.done <= 4:
                break
        store.close()

        # The worker runs the final advance (last batch + finalize in one
        # transaction) with an artificially wide commit window; kill inside it.
        proc = launch_worker(
            path,
            "new-pw",
            "req-fin",
            "new-pw",
            100,
            {"KEYESCROW_COMMIT_DELAY_MS": "900", "WORKER_BATCH_SLEEP": "0"},
        )
        time.sleep(random.uniform(0.05, 1.6))
        kill_hard(proc)
        proc.communicate()

        store = EscrowStore.open(path, "new-pw")
        status = store.rotation_status()
        for kid, msg in messages.items():
            assert store.decrypt(kid, cts[kid]) == msg
        store.close()

        if status.state == "idle":
            # fully switched: old passphrase rejected
            with pytest.raises(AuthenticationError):
                EscrowStore.open(path, "old-pw")
        else:
            # not switched: both passphrases still work, progress kept
            assert status.state == "rotating"
            store = EscrowStore.open(path, "old-pw")
            for kid, msg in messages.items():
                assert store.decrypt(kid, cts[kid]) == msg
            store.close()
            store = EscrowStore.open(path, "new-pw")
            while not store.advance_rotation().complete:
                pass
            store.close()
