"""Fetch a 100k common-password list for the admin-only escalation."""
import sys
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
CANDS = [
    "Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt",
    "Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
]

for c in CANDS:
    try:
        got = urllib.request.urlopen(ROOT + c, timeout=60).read().decode("utf-8", "replace")
    except Exception as e:
        print("miss", c, e)
        continue
    words = [w.strip() for w in got.splitlines() if w.strip()]
    open("words3.txt", "w", encoding="utf-8").write("\n".join(words) + "\n")
    print(f"fetched {c} -> {len(words)} words")
    break
