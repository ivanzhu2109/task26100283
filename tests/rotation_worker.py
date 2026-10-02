"""Worker process for crash-recovery tests.

Usage: rotation_worker.py <db> <passphrase> <request_id> <new_passphrase> <batch>

Opens the store, starts/resumes the rotation request and advances it in
batches, printing one progress line per committed batch. The parent test
kills this process with SIGKILL at arbitrary points.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from keyescrow import EscrowStore  # noqa: E402


def main() -> None:
    path, passphrase, request_id, new_passphrase, batch = sys.argv[1:6]
    store = EscrowStore.open(path, passphrase)
    status = store.start_rotation(request_id, new_passphrase)
    print(f"started state={status.state} {status.done}/{status.total}", flush=True)
    sleep_s = float(os.environ.get("WORKER_BATCH_SLEEP", "0.05"))
    while True:
        status = store.advance_rotation(int(batch))
        print(f"progress state={status.state} {status.done}/{status.total}", flush=True)
        if status.complete:
            break
        time.sleep(sleep_s)
    store.close()
    print("done", flush=True)


if __name__ == "__main__":
    main()
