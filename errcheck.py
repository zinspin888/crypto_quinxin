"""Assess what the exposed error_log files actually disclose."""
import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HOSTS = ["jlmes.nit.ac.tz", "sumajkt.go.tz", "uwekezaji.iringa.go.tz",
         "www.mbeyauwsa.go.tz", "www.ncaa.go.tz", "www.ppra.go.tz",
         "www.tasuba.ac.tz", "www.viwanda.go.tz"]

for h in HOSTS:
    r = scan.fetch("https://" + h + "/error_log")
    if not r:
        print(h, "DOWN")
        continue
    b = r["body"]
    paths = sorted(set(re.findall(r"/data/[\w./-]+", b)))
    creds = re.findall(r"Access denied for user '[^']*'", b)
    print(f"{h} {r['status']} {len(b)}B paths={len(paths)} creds={len(creds)}")
    for p in paths[:3]:
        print("    path:", p)
    for c in creds[:2]:
        print("    cred:", c)
    m = re.search(r"PHP (Fatal error|Warning|Notice)[^\n]{0,120}", b)
    if m:
        print("    sample:", m.group(0)[:120])
