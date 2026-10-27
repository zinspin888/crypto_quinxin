"""Pull exact module versions from readable .info files on uonbi."""
import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

MODS = ["views", "ctools", "token", "pathauto", "webform", "ckeditor",
        "captcha", "imce", "media", "colorbox"]
for m in MODS:
    for f in (f"/sites/all/modules/{m}/{m}.info", f"/sites/all/modules/{m}/README.txt"):
        r = scan.fetch("https://uonbi.ac.ke" + f)
        if not r or r["status"] != 200:
            continue
        ver = re.search(r"^version\s*=\s*(\S+)", r["body"], re.M)
        date = re.search(r"Date:\s*(\$Date[^$]*\$)", r["body"])
        print(f"  {m:10} {f.rsplit('/',1)[-1]:12} {ver.group(1) if ver else '-'} {date.group(1) if date else ''}")
        break
