"""Read the leaked lock file in full (bypasses the 120KB fetch cap)."""
import json
import ssl
import sys
import urllib.request

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def big(url):
    req = urllib.request.Request(url, headers={"User-Agent": scan.UA})
    with urllib.request.urlopen(req, timeout=30, context=CTX) as r:
        return r.read(4_000_000).decode("utf-8", "replace")


for host in ("www.ddca.go.tz", "www.tasuba.ac.tz"):
    try:
        lock = json.loads(big(f"https://{host}/composer.lock"))
    except Exception as e:
        print(host, "ERR", e)
        continue
    pkgs = lock.get("packages", [])
    print(f"\n== {host}: {len(pkgs)} locked packages")
    for p in pkgs:
        if p["name"].startswith(("october/", "laravel/", "symfony/")) or p["name"] == "php":
            print(f"   {p['name']:44} {p.get('version')}")
