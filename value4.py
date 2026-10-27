"""Does ptf have a CF7 form carrying a file field (CVE-2020-35489 prereq)?"""
import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

r = scan.fetch("https://www.ptf.or.tz/")
links = re.findall(r'href="(https?://www\.ptf\.or\.tz/[^"#?]*)"', r["body"]) if r else []
links = list(dict.fromkeys(links))[:40]
print("internal links:", len(links))

for u in links:
    x = scan.fetch(u)
    if not x:
        continue
    b = x["body"]
    if "wpcf7" in b:
        files = re.findall(r'<input[^>]*type="file"[^>]*>', b)
        print(f"\n{u} [{x['status']}] CF7 form")
        print("   file inputs:", files or "none")
        for m in re.findall(r'name="([^"]*_file[^"]*|file-\d+)"', b):
            print("   field:", m)
