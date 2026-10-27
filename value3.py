"""Is ptf re-installable, and which plugins (RCE-prone ones first) are present."""
import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

for p in ("/wp-admin/install.php", "/wp-admin/setup-config.php",
          "/wp-admin/upgrade.php"):
    r = scan.fetch("https://www.ptf.or.tz" + p)
    txt = " ".join(re.sub(r"<[^>]+>", " ", r["body"]).split())[:120] if r else ""
    print(f"{p:28} {r['status'] if r else 'DOWN'} :: {txt}")

print("\n== plugin readme probe (ptf)")
PLUGINS = ["revslider", "js_composer", "elementor", "contact-form-7",
           "wordpress-seo", "akismet", "woocommerce", "wp-file-manager",
           "duplicator", "backup-backup"]
for pl in PLUGINS:
    r = scan.fetch(f"https://www.ptf.or.tz/wp-content/plugins/{pl}/readme.txt")
    if not r or r["status"] != 200:
        continue
    ver = re.search(r"Stable tag:\s*([\w.\-]+)", r["body"])
    print(f"  {pl:18} present  stable={ver.group(1) if ver else '?'}")
