"""Module CHANGELOG.txt as the version channel (only .txt is served)."""
import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MODS = ["views", "ctools", "token", "pathauto", "webform", "ckeditor",
        "captcha", "imce", "media", "colorbox"]
for m in MODS:
    r = scan.fetch(f"https://uonbi.ac.ke/sites/all/modules/{m}/CHANGELOG.txt")
    if r and r["status"] == 200 and len(r["body"]) > 50:
        first = " ".join(r["body"].split())[:70]
        print(f"  {m:10} readable :: {first}")
    else:
        print(f"  {m:10} {r['status'] if r else 'DOWN'}")
