"""Count live authentication surfaces across the vulnerable hosts."""
import concurrent.futures as cf
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

scan.TIMEOUT = 6
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PATHS = ["/admin/", "/administrator/", "/phpmyadmin/", "/user/login",
         "/wp-login.php", "/adminer.php"]
TITLES = ("login", "admin", "sign in", "masuk", "panel", "console")


def check(host):
    hits = []
    for p in PATHS:
        for scheme in ("https", "http"):
            r = scan.fetch(f"{scheme}://{host}{p}")
            if r and r["status"] in (200, 401):
                body = r["body"].lower()
                t = ""
                i = body.find("<title")
                if i >= 0:
                    t = body[i:i + 120]
                if r["status"] == 401 or any(k in t for k in TITLES):
                    hits.append((p, r["status"], len(r["body"])))
                    break
    return host, hits


targets = [l.split(",")[0].strip() for l in open(sys.argv[1], encoding="utf-8")
           if l.strip() and not l.startswith("#")]
with cf.ThreadPoolExecutor(max_workers=10) as pool:
    for host, hits in pool.map(check, targets):
        if hits:
            print(f"{host}: " + ", ".join(f"{p} [{s}] {n}B" for p, s, n in hits))
