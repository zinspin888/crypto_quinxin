"""Spot-check the remaining artefact hits by eye."""
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

URLS = ["https://jlmes.nit.ac.tz/composer.json",
        "https://www.ddca.go.tz/composer.json",
        "https://www.ddca.go.tz/package.json",
        "https://www.tasuba.ac.tz/composer.json",
        "https://www.veta.go.tz/web.config",
        "https://www.ncaa.go.tz/wp-login.php",
        "https://www.nimr.or.tz/wp-login.php",
        "https://www.sbt.go.tz/wp-login.php"]

for u in URLS:
    r = scan.fetch(u)
    if not r:
        print(f"\n== {u} DOWN")
        continue
    body = " ".join(r["body"].split())
    print(f"\n== {u} [{r['status']}] {len(r['body'])}B")
    print("   ", body[:220])
