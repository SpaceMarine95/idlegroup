import os
import yaml
from eve_stream import tail_eve_json
from cowrie_tail import tail_cowrie_json, to_bf_event
from rulemap import RuleMap
from correlator import Correlator
from policy import exec_actions
from shun_worker import ShunWorker

EVE = os.getenv("EVE_FILE","/var/log/suricata/eve.json")
COWRIE = os.getenv("COWRIE_JSON","/var/log/cowrie/cowrie.json")

def eve_to_event(ev):
    if ev.get("event_type") != "alert": return None
    sid = ev.get("alert",{}).get("signature_id") or ev.get("alert",{}).get("sid")
    src = ev.get("src_ip")
    if not sid or not src: return None
    return {"sid": int(sid), "src_ip": src}

def load_cfg():
    with open("/app/rules.yaml","r") as f:
        return yaml.safe_load(f)

def main():
    rules = RuleMap("/app/rules.yaml")
    corr  = Correlator()
    # NEW: shun worker (queue writer with cooldown)
    shun  = ShunWorker(queue_dir=os.getenv("SHUN_QUEUE", "/app/shun_queue"),
                       default_ttl_sec=3600, cooldown_sec=900)

    # Helper to run actions:
    def run_actions(src_ip: str, actions: list, source: str):
        # 1) Handle SHUN locally (so we can de-dupe and write to queue)
        for a in actions:
            if a.get("type") == "SHUN":
                ttl = int(a.get("params", {}).get("ttl_sec", 3600))
                shun.shun(src_ip, ttl_sec=ttl, source=source)
        # 2) Pass the rest to your existing action pipeline
        remaining = [a for a in actions if a.get("type") != "SHUN"]
        if remaining:
            exec_actions(src_ip, remaining)

    eve_stream     = tail_eve_json(EVE)
    cowrie_stream  = tail_cowrie_json(COWRIE)

    while True:
        # Suricata
        try:
            ev = next(eve_stream)
            e  = eve_to_event(ev)
            if e:
                vec = rules.to_vector_by_sid(e["sid"])
                if vec:
                    vr = rules.get_vector_rule(vec)
                    cnt = corr.hit(vec, e["src_ip"], vr.window_sec)
                    for th in sorted(vr.thresholds, key=lambda x: x.count):
                        if cnt >= th.count and not corr.in_cooldown(vec, e["src_ip"], th.count):
                            # CHANGED: use run_actions()
                            run_actions(e["src_ip"], th.actions, source="suricata")
                            corr.set_cooldown(vec, e["src_ip"], th.count, sec=20)
        except StopIteration:
            pass
        except Exception:
            pass

        # Cowrie (SSH failures)
        try:
            cev = next(cowrie_stream)
            bf  = to_bf_event(cev)
            if bf:
                for window, threshold, actions in [
                    (30, 5,  [{"type":"SSH_ROTATE","params":{"persona":"A"}}]),
                    (300,15, [{"type":"RATELIMIT","params":{"pps":60}}, {"type":"BLOCK"}]),
                    # NEW: fast demo threshold (add a SHUN)
                    (60, 10, [{"type":"SHUN","params":{"ttl_sec":3600}}]),
                ]:
                    cnt = corr.hit("ssh_bf", bf["src_ip"], window)
                    if cnt >= threshold and not corr.in_cooldown("ssh_bf", bf["src_ip"], threshold):
                        # CHANGED: use run_actions()
                        run_actions(bf["src_ip"], actions, source="cowrie")
                        corr.set_cooldown("ssh_bf", bf["src_ip"], threshold, sec=60)
        except StopIteration:
            pass
        except Exception:
            pass

if __name__ == "__main__":
    main()