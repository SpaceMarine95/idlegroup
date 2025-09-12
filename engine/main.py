# main.py (patched)
import os, yaml, time
from rulemap import RuleMap
from correlator import Correlator
from policy import exec_actions
from shun_worker import ShunWorker

from adapters.suricata_adapter import stream_suricata
from adapters.cowrie_adapter   import stream_cowrie
from adapters.beelzebub_adapter import stream_beelzebub
from adapters.violet_adapter    import stream_violet

EVE     = os.getenv("EVE_FILE","/var/log/suricata/eve.json")
COWRIE  = os.getenv("COWRIE_JSON","/var/log/cowrie/cowrie.json")
BZ_JSON = os.getenv("BZ_JSON","/var/log/beelzebub/events.jsonl")
VIOLET  = os.getenv("VIOLET_JSON","/var/log/violet/defense.jsonl")

def main():
    rules = RuleMap("/app/rules.yaml")
    corr  = Correlator()
    shun  = ShunWorker(queue_dir=os.getenv("SHUN_QUEUE","/app/shun_queue"),
                       default_ttl_sec=3600, cooldown_sec=900)

    def run_actions(src_ip: str, actions: list, source: str):
        # SHUN locally; forward the rest to exec_actions
        for a in actions:
            if a.get("type") == "SHUN":
                ttl = int(a.get("params",{}).get("ttl_sec", 3600))
                shun.shun(src_ip, ttl_sec=ttl, source=source)
        rest = [a for a in actions if a.get("type") != "SHUN"]
        if rest:
            exec_actions(src_ip, rest)

    # Start streams
    s_stream = stream_suricata(EVE)
    c_stream = stream_cowrie(COWRIE)
    b_stream = stream_beelzebub(BZ_JSON)
    v_stream = stream_violet(VIOLET)

    while True:
        # Non-blocking poll pattern (keep it simple like your current code)
        for source, gen in (("suricata", s_stream),
                            ("cowrie",   c_stream),
                            ("beelzebub",b_stream),
                            ("violet",   v_stream)):
            try:
                e = next(gen)
            except StopIteration:
                continue
            except Exception:
                continue

            if not e:
                continue

            vector = e["vector"]
            src_ip = e["src_ip"]
            # Look up rules (YAML vectors) by vector name
            vr = rules.get_vector_rule(vector)
            if not vr:
                continue

            cnt = corr.hit(vector, src_ip, vr.window_sec)
            for th in sorted(vr.thresholds, key=lambda x: x.count):
                if cnt >= th.count and not corr.in_cooldown(vector, src_ip, th.count):
                    run_actions(src_ip, th.actions, source=source)
                    # prefer vector-specific cooldown if present
                    cd = getattr(vr, "cooldown_sec", None) or 30
                    corr.set_cooldown(vector, src_ip, th.count, sec=cd)

        # tiny sleep to avoid busy spin
        time.sleep(0.05)

if __name__ == "__main__":
    main()