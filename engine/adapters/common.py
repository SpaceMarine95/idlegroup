# engine/adapters/common.py
import time, json, os
from datetime import datetime
from pathlib import Path

def iso_to_epoch(ts: str | None, default: float | None = None) -> float:
    if not ts:
        return default if default is not None else time.time()
    try:
        return datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
    except Exception:
        return default if default is not None else time.time()
"""
Follow a JSONL file without writing to it (works with read-only mounts).
If the file doesn't exist yet, we just wait until it appears.
"""
def tail_jsonl(p, interval=0.2):
    pos = 0
    while True:
        try:
            with open(p, "rb") as f:
                if pos == 0:
                    f.seek(0, 2)
                    pos = f.tell()
                else:
                    f.seek(pos)
                line = f.readline()
                if not line:
                    pos = f.tell()
                    # no yield here; yield None only if you like your current poll design
                    yield None
                    time.sleep(interval)
                    continue
                pos = f.tell()
                try:
                    obj = json.loads(line.decode("utf-8", "ignore"))
                    # DEBUG:
                    print(f"[tail] {p} +1", flush=True)
                    yield obj
                except Exception:
                    continue
        except FileNotFoundError:
            time.sleep(interval)
            continue