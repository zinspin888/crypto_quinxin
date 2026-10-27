"""Follow the October CMS exposure on ddca and WP user enumeration on ncaa."""
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CHECKS = [
    "https://www.ddca.go.tz/backend/",
    "https://www.ddca.go.tz/vendor/october/rain/src/Database/Model.php",
    "https://www.ddca.go.tz/vendor/autoload.php",
    "https://www.ddca.go.tz/modules/system/ServiceProvider.php",
    "https://www.ddca.go.tz/composer.lock",
    "https://www.tasuba.ac.tz/backend/",
    "https://www.ncaa.go.tz/?author=1",
    "https://www.ncaa.go.tz/wp-json/wp/v2/users",
]

for u in CHECKS:
    r = scan.fetch(u)
    if not r:
        print(f"{u:62} DOWN")
        continue
    body = " ".join(r["body"].split())
    print(f"{u:62} [{r['status']}] {len(r['body'])}B :: {body[:110]}")
