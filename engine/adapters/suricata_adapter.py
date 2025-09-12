# engine/adapters/suricata_adapter.py
import time
from .common import tail_jsonl, iso_to_epoch

def stream_suricata(eve_path: str):
    for ev in tail_jsonl(eve_path):
        if ev.get("event_type") != "alert":
            continue
        alert = ev.get("alert") or {}
        sid = alert.get("signature_id") or alert.get("sid")
        src = ev.get("src_ip")
        if not sid or not src:
            continue
        ts = iso_to_epoch(ev.get("timestamp"), time.time())
        # map SIDs to vectors elsewhere; default to ssh_syn_burst if that's your SID set
        yield {
            "ts": ts,
            "vector": "ssh_syn_burst",   # or map via your RuleMap if you prefer
            "src_ip": src,
            "sid": int(sid),
            "meta": ev,
        }