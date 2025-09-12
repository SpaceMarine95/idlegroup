import yaml
from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class Threshold:
    count: int
    actions: List[Dict[str, Any]]

@dataclass
class VectorRule:
    name: str
    sids: List[int] | None
    window_sec: int
    thresholds: List[Threshold]

class RuleMap:
    def __init__(self, path: str):
        self.by_sid: Dict[int, str] = {}
        self.vectors: Dict[str, VectorRule] = {}
        self.load(path)

    def load(self, path: str):
        data = yaml.safe_load(open(path))
        for vname, vd in data["vectors"].items():
            sids = vd.get("sids")
            vr = VectorRule(
                name=vname,
                sids=sids,
                window_sec=vd["window_sec"],
                thresholds=[Threshold(**t) for t in vd["thresholds"]]
            )
            self.vectors[vname] = vr
            if sids:
                for sid in sids: self.by_sid[int(sid)] = vname

    def to_vector_by_sid(self, sid: int):
        return self.by_sid.get(int(sid))

    def get_vector_rule(self, vector: str):
        return self.vectors.get(vector)
