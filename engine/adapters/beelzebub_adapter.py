# engine/adapters/beelzebub_adapter.py
import time
from .common import tail_jsonl, iso_to_epoch

VECTOR_MAP = {
    "ssh_bruteforce": "ssh_bruteforce",
    "http_lfi": "web_lfi",
    "http_sqli": "web_sqli",
}

def stream_beelzebub(path: str):
    for ev in tail_jsonl(path):
        if ev is None:
            yield None
            continue
        etype = (ev.get("type") or ev.get("vector") or "").lower()
        vector = VECTOR_MAP.get(etype)
        if not vector:
            continue
        src = ev.get("src_ip") or ev.get("ip") or ev.get("remote_addr")
        if not src:
            continue
        ts = iso_to_epoch(ev.get("timestamp"), time.time())
        yield {
            "ts": ts,
            "vector": vector,
            "src_ip": src,
            "sid": None,
            "meta": ev,
        }