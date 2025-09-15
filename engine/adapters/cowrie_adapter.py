# engine/adapters/cowrie_adapter.py
import time
from .common import tail_jsonl, iso_to_epoch

def is_failed_login(ev: dict) -> tuple[bool, str | None, float]:
    src = ev.get("src_ip") or ev.get("peer_ip")
    if not src:
        return False, None, time.time()
    eventid = (ev.get("eventid") or "").lower()
    msg = (ev.get("message") or "").lower()
    success = ev.get("success")
    failed = ("cowrie.login.failed" in eventid) or ("login attempt" in msg and (success in (False,"false","0",None)))
    ts = iso_to_epoch(ev.get("timestamp"), time.time())
    return failed, src, ts

def stream_cowrie(cowrie_json: str):
    for ev in tail_jsonl(cowrie_json):
        if ev is None:
            yield None
            continue
        ok, src, ts = is_failed_login(ev)
        if not ok:
            continue
        yield {
            "ts": ts,
            "vector": "ssh_bruteforce",
            "src_ip": src,
            "sid": None,
            "meta": ev,
        }