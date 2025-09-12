import json
from eve_stream import tail_file

def tail_cowrie_json(path: str):
    for line in tail_file(path):
        try:
            ev = json.loads(line)
        except:
            continue
        if isinstance(ev, dict):
            yield ev

def to_bf_event(ev):
    if ev.get("eventid") != "cowrie.login.failed":
        return None
    src = ev.get("src_ip") or ev.get("src_ip_addr")
    if not src: return None
    return {"vector":"ssh_bf","src_ip":src,"username":ev.get("username"),"password":ev.get("password")}
