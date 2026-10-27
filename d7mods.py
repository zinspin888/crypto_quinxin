"""Are contrib module readmes readable on uonbi (a CVE map if so)?"""
import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MODS = ["views", "ctools", "token", "pathauto", "webform", "ckeditor",
        "services", "restws", "captcha", "colorbox", "imce", "media"]
for m in MODS:
    for base in ("/sites/all/modules", "/sites/all/modules/contrib"):
        u = f"https://uonbi.ac.ke{base}/{m}/README.txt"
        r = scan.fetch(u)
        if r and r["status"] == 200 and len(r["body"]) > 100:
            ver = re.search(r"(\d+\.\d+(?:-\w+)?)", r["body"])
            print(f"  {m:10} {base:26} readable {len(r['body'])}B {ver.group(1) if ver else ''}")
            break
