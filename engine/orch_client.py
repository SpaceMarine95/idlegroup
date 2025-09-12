import os, requests
ORCH = os.getenv("ORCH_URL","http://orchestrator:8080")

def feature(ip: str, flag: dict, ttl_sec: int=1800):
    requests.post(f"{ORCH}/feature", json={"ip":ip,"flags":flag,"ttl_sec":ttl_sec}, timeout=3)

def spawn(template: str):
    requests.post(f"{ORCH}/spawn", json={"template":template}, timeout=10)

def assign(ip: str, backend: str, ttl_sec: int=7200):
    requests.post(f"{ORCH}/assign", json={"ip":ip,"backend":backend,"ttl_sec":ttl_sec}, timeout=3)

def block(ip: str):
    requests.post(f"{ORCH}/actions/block", json={"src_cidr":f"{ip}/32"}, timeout=3)

def ratelimit(ip: str, pps: int=60):
    requests.post(f"{ORCH}/actions/ratelimit", json={"src_cidr":f"{ip}/32","pps":pps}, timeout=3)

def ssh_rotate(persona: str="A"):
    requests.post(f"{ORCH}/ssh/rotate", json={"persona":persona}, timeout=3)
