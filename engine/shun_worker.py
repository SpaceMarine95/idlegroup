# engine/shun_worker.py
import os, time, json
from pathlib import Path
from typing import Optional

class ShunWorker:
    def __init__(self,
                 queue_dir: Optional[str] = None,
                 default_ttl_sec: int = 3600,
                 cooldown_sec: int = 900):
        # allow env override if not provided
        q = queue_dir or os.getenv("SHUN_QUEUE", "/app/shun_queue")
        self.queue = Path(q)
        self.default_ttl = int(default_ttl_sec)
        self.cooldown = int(cooldown_sec)
        self.queue.mkdir(parents=True, exist_ok=True)
        self._last_banned: dict[str, float] = {}

    def shun(self, ip: str, ttl_sec: Optional[int] = None, source: str = "engine"):
        if not ip:
            return
        now = time.time()
        last = self._last_banned.get(ip, 0.0)
        if now - last < self.cooldown:
            return
        self._last_banned[ip] = now
        ttl = int(ttl_sec or self.default_ttl)
        # write a JSON line the shun_apply loop can parse
        (self.queue / f"ban-{ip}-{int(now)}.txt").write_text(
            json.dumps({"ip": ip, "ttl": ttl, "source": source}) + "\n",
            encoding="utf-8"
        )