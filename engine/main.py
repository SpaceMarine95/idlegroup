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
                print(f"[action] SHUN {src_ip} ttl={ttl}s (source={source})", flush=True)
                shun.shun(src_ip, ttl_sec=ttl, source=source)
        rest = [a for a in actions if a.get("type") != "SHUN"]
        if rest:
            exec_actions(src_ip, rest)

    # Start streams
    s_stream = stream_suricata(EVE)
    c_stream = stream_cowrie(COWRIE)
    b_stream = stream_beelzebub(BZ_JSON)
    v_stream = stream_violet(VIOLET)
    print("[engine] started; tailing suricata/cowrie/beelzebub/violet", flush=True)

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
            except Exception as ex:
                print(f"[ingest-error] source={source}: {type(ex).__name__}: {ex}", flush=True)
                continue

            if not e:
                continue
            print(f"[ingest] {source} → vec={e.get('vector')} ip={e.get('src_ip')}", flush=True)

            vector = e["vector"]
            src_ip = e["src_ip"]
            # Look up rules (YAML vectors) by vector name
            vr = rules.get_vector_rule(vector)
            if not vr:
                continue

            cnt = corr.hit(vector, src_ip, vr.window_sec)
            print(f"[corr] vector={vector} ip={src_ip} count={cnt}/{vr.window_sec}s", flush=True)
            for th in sorted(vr.thresholds, key=lambda x: x.count):
                if cnt >= th.count and not corr.in_cooldown(vector, src_ip, th.count):
                    print(f"[fire] vector={vector} ip={src_ip} threshold={th.count} actions={th.actions}", flush=True)
                    run_actions(src_ip, th.actions, source=source)
                    # prefer vector-specific cooldown if present
                    cd = getattr(vr, "cooldown_sec", None) or 30
                    corr.set_cooldown(vector, src_ip, th.count, sec=cd)

        # tiny sleep to avoid busy spin
        time.sleep(0.05)

if __name__ == "__main__":
    def _stat(p):
        try:
            st = os.stat(p)
            return f"ok inode={st.st_ino} size={st.st_size}"
        except Exception as ex:
            return f"ERR {ex}"

    print("[start] engine up", flush=True)
    print(f"[start] EVE={EVE} -> {_stat(EVE)}", flush=True)
    print(f"[start] COWRIE={COWRIE} -> {_stat(COWRIE)}", flush=True)
    print(f"[start] BZ_JSON={BZ_JSON} -> {_stat(BZ_JSON)}", flush=True)
    print(f"[start] VIOLET={VIOLET} -> {_stat(VIOLET)}", flush=True)
    
    main()
    