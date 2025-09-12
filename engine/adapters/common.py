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

def tail_jsonl(path: str, poll_sec: float = 0.2):
    """Tail a JSONL (one JSON per line) file safely."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    open(p, "a+b").close()  # ensure exists
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(poll_sec)
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                # skip partial/garbled line; continue tailing
                continue