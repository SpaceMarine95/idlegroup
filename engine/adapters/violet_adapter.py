# engine/adapters/violet_adapter.py
import time
from .common import tail_jsonl, iso_to_epoch

def stream_violet(path: str):
    for ev in tail_jsonl(path):
        if ev is None:
            yield None
            continue
        src = ev.get("src_ip") or ev.get("src_id") or "agent"
        ts = iso_to_epoch(ev.get("timestamp"), time.time())
        yield {
            "ts": ts,
            "vector": "llm_attack",
            "src_ip": str(src),
            "sid": None,
            "meta": ev,
        }