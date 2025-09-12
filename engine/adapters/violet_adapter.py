# engine/adapters/violet_adapter.py
import time
from .common import tail_jsonl, iso_to_epoch

def stream_violet(path: str):
    """
    Expect JSONL lines like:
    {"timestamp":"2025-09-12T02:34:56Z","src_id":"agent-42","threat":"prompt_injection","tool":"delete_all","severity":"high"}
    """
    for ev in tail_jsonl(path):
        src = ev.get("src_ip") or ev.get("src_id") or "agent"
        ts = iso_to_epoch(ev.get("timestamp"), time.time())
        # You can split vectors per threat if you like
        vector = "llm_attack"
        yield {
            "ts": ts,
            "vector": vector,
            "src_ip": str(src),  # keep string if it's an agent id
            "sid": None,
            "meta": ev,
        }