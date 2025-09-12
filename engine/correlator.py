import time
from collections import defaultdict
from typing import Tuple, Dict, List

class Correlator:
    def __init__(self):
        self.win: Dict[Tuple[str,str], List[float]] = defaultdict(list)
        self.cooldown: Dict[Tuple[str,str,int], float] = {}

    def hit(self, vector: str, ip: str, window_sec: int) -> int:
        now = time.time()
        key = (vector, ip)
        self.win[key] = [t for t in self.win[key] if now - t <= window_sec]
        self.win[key].append(now)
        return len(self.win[key])

    def in_cooldown(self, vector: str, ip: str, count: int) -> bool:
        now = time.time()
        return now < self.cooldown.get((vector, ip, count), 0)

    def set_cooldown(self, vector: str, ip: str, count: int, sec: int=20):
        self.cooldown[(vector, ip, count)] = time.time() + sec
