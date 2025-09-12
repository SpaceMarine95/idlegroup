import os, json, time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from threading import Thread, Event

def _iso_to_epoch(ts: str, default: float) -> float:
    try:
        return datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
    except Exception:
        return default

class ShunWorker:
    def __init__(self, cfg):
        self.enabled = cfg.get("shun", {}).get("enabled", True)
        self.queue_dir = Path(cfg.get("shun", {}).get("queue_dir", "/app/shun_queue"))
        self.ban_ttl = int(cfg.get("shun", {}).get("ban_ttl_sec", 3600))
        self.cooldown = int(cfg.get("shun", {}).get("cooldown_sec", 900))
        self.cowrie_cfg = cfg.get("cowrie_bruteforce", {})
        self.suri_cfg = cfg.get("suricata_burst", {})
        self.stop_evt = Event()
        self.last_banned = {}          # ip -> epoch
        self.fail_windows = defaultdict(deque)  # ip -> deque[timestamps]

    def start(self):
        if not self.enabled: return
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        self.t1 = Thread(target=self._watch_cowrie, daemon=True); self.t1.start()
        if self.suri_cfg.get("enabled", False):
            self.t2 = Thread(target=self._watch_suricata, daemon=True); self.t2.start()

    def stop(self):
        self.stop_evt.set()

    # ---- Cowrie watcher ----
    def _watch_cowrie(self):
        path = Path("/var/log/cowrie/cowrie.json")
        thr = int(self.cowrie_cfg.get("threshold", 10))
        win = int(self.cowrie_cfg.get("window_sec", 60))

        # open & seek end (tail -F)
        path.parent.mkdir(parents=True, exist_ok=True)
        f = path.open("a+b"); f.close()
        f = path.open("r", encoding="utf-8", errors="ignore")
        f.seek(0, os.SEEK_END)

        while not self.stop_evt.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.2); continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            src = ev.get("src_ip") or ev.get("peer_ip") or ev.get("srcid")
            if not src: continue
            ts = _iso_to_epoch(ev.get("timestamp"), time.time())
            eventid = (ev.get("eventid") or "").lower()
            msg = (ev.get("message") or "").lower()
            success = ev.get("success")

            failed = ("cowrie.login.failed" in eventid) or ("login attempt" in msg and (success in (False,"false","0",None)))
            if not failed: continue

            dq = self.fail_windows[src]
            dq.append(ts)
            cutoff = ts - win
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= thr:
                self._ban_once(src, ts)

    # ---- Suricata watcher (optional) ----
    def _watch_suricata(self):
        path = Path("/var/log/suricata/eve.json")
        min_alerts = int(self.suri_cfg.get("min_alerts", 10))
        win = int(self.suri_cfg.get("window_sec", 45))
        severities = set([s.lower() for s in self.suri_cfg.get("severities", [])])

        f = path.open("a+b"); f.close()
        f = path.open("r", encoding="utf-8", errors="ignore")
        f.seek(0, os.SEEK_END)

        buckets = defaultdict(deque)  # ip -> deque[timestamps]

        while not self.stop_evt.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.2); continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") != "alert": continue
            ip = ev.get("src_ip")
            if not ip: continue
            sev = (ev.get("alert", {}).get("severity_label") or ev.get("alert", {}).get("severity") or "")
            if severities and str(sev).lower() not in severities: 
                continue
            ts = _iso_to_epoch(ev.get("timestamp"), time.time())

            dq = buckets[ip]
            dq.append(ts)
            cutoff = ts - win
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= min_alerts:
                self._ban_once(ip, ts)

    # ---- queue write with cooldown ----
    def _ban_once(self, ip: str, now_ts: float):
        last = self.last_banned.get(ip, 0)
        if now_ts - last < self.cooldown:
            return
        self.last_banned[ip] = now_ts
        # Write a request file that shun_apply will consume
        fname = self.queue_dir / f"ban-{ip}-{int(now_ts)}.txt"
        # Either just the IP, or JSON including TTL if you prefer
        fname.write_text(ip + "\n")