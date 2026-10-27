"""Drupal 7 version on uonbi - decides whether Drupalgeddon2 applies."""
import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

r = scan.fetch("https://uonbi.ac.ke/CHANGELOG.txt")
if r and r["status"] == 200:
    m = re.search(r"Drupal (\d+\.\d+(?:\.\d+)?)", r["body"][:200])
    print("CHANGELOG:", r["status"], m.group(0) if m else r["body"][:80])
else:
    print("CHANGELOG:", r["status"] if r else "DOWN")

for p in ("/user/login", "/user/register", "/?q=user/login",
          "/includes/bootstrap.inc", "/core/CHANGELOG.txt", "/INSTALL.txt"):
    x = scan.fetch("https://uonbi.ac.ke" + p)
    print(f"  {p:28} {x['status'] if x else 'DOWN'} {len(x['body']) if x else 0}B")
