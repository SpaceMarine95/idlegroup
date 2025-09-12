import json, subprocess

def tail_file(path: str):
    p = subprocess.Popen(["tail","-F",path], stdout=subprocess.PIPE, text=True)
    for line in iter(p.stdout.readline, ''):
        if line.strip():
            yield line

def tail_eve_json(path: str):
    for line in tail_file(path):
        try:
            yield json.loads(line)
        except:
            continue
