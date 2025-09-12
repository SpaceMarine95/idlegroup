from typing import List, Dict
import orch_client as oc

def exec_actions(ip: str, actions: List[Dict]):
    for a in actions:
        typ = a["type"].upper()
        p = a.get("params", {})
        if typ == "FEATURE":
            oc.feature(ip, p.get("flag", {"style":"alt"}), p.get("ttl_sec",1800))
        elif typ == "SPAWN":
            oc.spawn(p["template"])
        elif typ == "ASSIGN":
            oc.assign(ip, p["backend"], p.get("ttl_sec",7200))
        elif typ == "BLOCK":
            oc.block(ip)
        elif typ == "RATELIMIT":
            oc.ratelimit(ip, p.get("pps",60))
        elif typ == "SSH_ROTATE":
            oc.ssh_rotate(p.get("persona","A"))
