"""Crash-test worker: runs a phase, then os._exit(0) to simulate kill -9."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyescrow import KeyStore  # noqa: E402

OLD_PW = "old-pw"
NEW_PW = "new-pw"
REQ_ID = "req-crash"


def emit(obj):
    print(json.dumps(obj), flush=True)


def setup(db, sidecar, nkeys):
    ks = KeyStore.create(db, OLD_PW)
    expected = {}
    for i in range(nkeys):
        kid = ks.generate_key(f"key-{i:06d}")
        pt = f"message-{i}".encode()
        expected[kid] = {"pt": pt.hex(), "ct": ks.encrypt(kid, pt).hex()}
    ks.close()
    with open(sidecar, "w") as f:
        json.dump(expected, f)
    emit({"phase": "setup", "keys": nkeys})


def rotate(db, batches, batch_size, old_pw=OLD_PW, new_pw=NEW_PW, req_id=REQ_ID):
    ks = KeyStore.open(db, old_pw)
    st = ks.start_rotation(req_id, new_pw)
    emit({"phase": "accepted", "status": st})
    for _ in range(batches):
        st = ks.advance_rotation(batch_size)
        emit({"phase": "advanced", "status": st})
    os._exit(0)  # hard kill: no close, no cleanup


def rotate_until_done(db, batch_size):
    ks = KeyStore.open(db, OLD_PW)
    st = ks.start_rotation(REQ_ID, NEW_PW)
    emit({"phase": "accepted", "status": st})
    while True:
        st = ks.advance_rotation(batch_size)
        emit({"phase": "advanced", "status": st})
        if st["status"] == "completed":
            break
    os._exit(0)  # killed right at the finalize boundary


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "setup":
        setup(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    elif cmd == "rotate":
        rotate(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), *sys.argv[5:])
    elif cmd == "rotate-until-done":
        rotate_until_done(sys.argv[2], int(sys.argv[3]))
    else:
        raise SystemExit(f"unknown command: {cmd}")
