"""Fetch a common-password list and merge with the curated one."""
import sys
import urllib.request

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SRC = ("https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
       "Passwords/Common-Credentials/10-million-password-list-top-2000.txt")
CANDIDATES = [
    "Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "Passwords/Common-Credentials/10k-most-common.txt",
    "Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt",
]

got = None
root = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
for c in CANDIDATES:
    try:
        got = urllib.request.urlopen(root + c, timeout=40).read().decode("utf-8", "replace")
        print("fetched:", c)
        break
    except Exception as e:
        print("miss", c, e)
if got is None:
    sys.exit("no wordlist source reachable")

base = [w.rstrip("\n") for w in open("words.txt", encoding="utf-8") if w.strip()]
extra = [w.strip() for w in got.splitlines() if w.strip()]

seen, merged = set(), []
for w in base + extra:
    if w not in seen:
        seen.add(w)
        merged.append(w)
open("words2.txt", "w", encoding="utf-8").write("\n".join(merged) + "\n")
print(f"words.txt={len(base)} fetched={len(extra)} merged={len(merged)}")
