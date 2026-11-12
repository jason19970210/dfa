#!/usr/bin/env python3
"""DFA batch-1 visibility check: drive the DFA MCP server over stdio and
assert each fixture's expected artifacts are visible through the tools.

Usage: python3 visibility_check.py
Env: DFA_VOL_BIN must point at the vol binary; DFA_CUSTODY_LOG should point
at a throwaway custody log so the real one is untouched.
"""
import json
import os
import subprocess
import sys

DFA_DIR = os.environ.get("DFA_DIR") or os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
FIX = os.path.join(DFA_DIR, "eval/fixtures/batch1")
S1 = os.path.join(FIX, "s1-cryptominer.mem")
S2 = os.path.join(FIX, "s2-reverseshell.mem")
CLEAN = os.path.join(FIX, "clean-baseline.mem")

server = subprocess.Popen(
    ["node", os.path.join(DFA_DIR, "dist/main.js"), "serve"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1,
    env={**os.environ,
         "DFA_VOL_BIN": os.path.join(DFA_DIR, ".venv/bin/vol"),
         "DFA_CUSTODY_LOG": "/tmp/dfa-visibility-custody.jsonl"},
)
req_id = [0]

def call(tool, args):
    req_id[0] += 1
    req = {"jsonrpc": "2.0", "id": req_id[0], "method": "tools/call",
           "params": {"name": tool, "arguments": args}}
    server.stdin.write(json.dumps(req) + "\n")
    server.stdin.flush()
    while True:
        line = server.stdout.readline()
        if not line:
            raise RuntimeError("server closed stdout")
        try:
            resp = json.loads(line)
        except json.JSONDecodeError:
            continue
        if resp.get("id") == req_id[0]:
            break
    result = resp["result"]
    if result.get("isError"):
        return {"_error": result["content"][0]["text"][:300]}
    return json.loads(result["content"][0]["text"])

results = []
def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + (f" — {detail}" if detail and not cond else ""))

def rows_of(res):
    return res.get("rows", []) if isinstance(res, dict) else []

# ---------- S1 ----------
print("== S1 cryptominer ==")
r = call("dfa_volatility_linux_pslist", {"image": S1})
rows = rows_of(r)
hit = [x for x in rows if x.get("COMM") == "xmrig"]
check("S1 pslist finds xmrig", len(hit) == 1, f"hits={len(hit)}")
if hit:
    check("S1 xmrig PID==1546", hit[0].get("PID") == 1546, f"PID={hit[0].get('PID')}")
    check("S1 xmrig PPID==1", hit[0].get("PPID") == 1, f"PPID={hit[0].get('PPID')}")

def count_tree(nodes):
    n = 0
    for x in nodes:
        n += 1 + count_tree(x.get("__children") or [])
    return n

def find_pid(nodes, pid):
    for x in nodes:
        if x.get("PID") == pid:
            return x
        f = find_pid(x.get("__children") or [], pid)
        if f:
            return f
    return None

# sockstat: page through with offset until the C2 row is found
found = None
for off in range(0, 2000, 200):
    r = call("dfa_volatility_linux_sockstat", {"image": S1, "offset": off})
    for x in rows_of(r):
        if str(x.get("Destination Addr")) == "10.0.2.2" and str(x.get("Destination Port")) == "3333":
            found = x
            break
    if found or not r.get("truncated"):
        break
check("S1 sockstat shows 10.0.2.2:3333 (paged)", found is not None)
if found:
    check("S1 conn is ESTABLISHED xmrig/1546",
          found.get("State") == "ESTABLISHED" and found.get("PID") == 1546,
          json.dumps(found)[:160])

r = call("dfa_volatility_linux_psaux", {"image": S1})
rows = rows_of(r)
hit = [x for x in rows if "xmrig.py" in json.dumps(x)]
check("S1 psaux shows miner cmdline", len(hit) >= 1, f"hits={len(hit)}")

r = call("dfa_volatility_linux_pstree", {"image": S1})
rows = rows_of(r)
total = count_tree(rows)
check("S1 pstree enumerates processes", total > 10, f"total={total}")
check("S1 pstree finds xmrig/1546", find_pid(rows, 1546) is not None)

# ---------- S2 ----------
print("== S2 reverse shell ==")
r = call("dfa_volatility_linux_pslist", {"image": S2})
rows = rows_of(r)
hit = [x for x in rows if x.get("PID") == 1299]
check("S2 pslist finds beacon PID 1299", len(hit) == 1, f"hits={len(hit)}")

r = call("dfa_volatility_linux_psaux", {"image": S2})
blob = json.dumps(rows_of(r))
check("S2 psaux shows implant path", ".systemd-cache.py" in blob)

found = None
for off in range(0, 2000, 200):
    r = call("dfa_volatility_linux_sockstat", {"image": S2, "offset": off})
    for x in rows_of(r):
        if str(x.get("Destination Addr")) == "10.0.2.2" and str(x.get("Destination Port")) == "4444":
            found = x
            break
    if found or not r.get("truncated"):
        break
check("S2 sockstat shows 10.0.2.2:4444 (paged)", found is not None)
if found:
    check("S2 conn is ESTABLISHED pid 1299",
          found.get("State") == "ESTABLISHED" and found.get("PID") == 1299,
          json.dumps(found)[:160])

r = call("dfa_volatility_linux_bash", {"image": S2})
blob = json.dumps(rows_of(r))
check("S2 bash history has attacker cmds",
      "systemd-cache" in blob or "nohup" in blob, f"rows={len(rows_of(r))}")

# ---------- CLEAN ----------
print("== clean baseline ==")
r = call("dfa_volatility_linux_pslist", {"image": CLEAN})
blob = json.dumps(rows_of(r))
check("clean: no xmrig", "xmrig" not in blob)
check("clean: no systemd-cache implant", "systemd-cache" not in blob)

for tool in ["dfa_volatility_linux_check_afinfo",
             "dfa_volatility_linux_check_syscall",
             "dfa_volatility_linux_check_modules",
             "dfa_volatility_linux_tty_check"]:
    r = call(tool, {"image": CLEAN})
    if isinstance(r, dict) and "_error" in r:
        check(f"clean {tool} runs", False, r["_error"][:100])
    else:
        check(f"clean {tool} runs", True)

server.stdin.close()
server.terminate()

fails = [n for n, ok, _ in results if not ok]
print(f"\n{len(results) - len(fails)}/{len(results)} checks passed")
sys.exit(1 if fails else 0)
