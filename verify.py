"""Verify candidate findings by sniffing real content (not just status)."""
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CANDIDATES = [
    ("https://www.nje.go.tz", ["/", "/db.sql", "/backup.zip", "/adminer.php"]),
    ("https://www.nec.go.tz", ["/", "/backup.zip"]),
    ("https://www.ntdcp.go.tz", ["/", "/.env", "/db.sql", "/backup.zip", "/adminer.php"]),
    ("https://www.pasiansiwildlife.ac.tz", ["/", "/phpinfo.php", "/adminer.php"]),
]


def sniff(url):
    r = scan.fetch(url)
    if not r:
        return "ERR"
    b = r["body"]
    low = b.lower()
    tags = []
    if b.startswith("PK"):
        tags.append("ZIP")
    if low.lstrip().startswith(("--", "/*", "#")) or "create table" in low:
        tags.append("SQL")
    if "<html" in low[:400]:
        tags.append("HTML")
    if "adminer" in low[:3000]:
        tags.append("ADMINER")
    if "phpinfo" in low[:2000] and "php version" in low:
        tags.append("PHPINFO")
    if "name='auth[username]'" in low or 'name="auth[username]"' in low:
        tags.append("ADMINER-LOGIN")
    return f"{r['status']} {len(b)}B {'+'.join(tags) or 'other'} :: {b[:70]!r}"


for base, paths in CANDIDATES:
    print(f"\n=== {base}")
    for p in paths:
        print(f"  {p:16} {sniff(base + p)}")
