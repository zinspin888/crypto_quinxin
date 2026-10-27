"""Malicious-value checks: WP version, xmlrpc amplification, October tree exposure."""
import re
import sys
import urllib.request

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

print("== WP version via feed generator / readme title")
for h in ("www.ncaa.go.tz", "www.nimr.or.tz", "www.ptf.or.tz", "www.sbt.go.tz"):
    r = scan.fetch(f"https://{h}/feed/")
    gen = re.search(r"<generator>([^<]+)</generator>", r["body"]) if r else None
    rd = scan.fetch(f"https://{h}/readme.html")
    title = re.search(r"<title>([^<]+)</title>", rd["body"]) if rd else None
    print(f"  {h:20} generator={gen.group(1) if gen else '-'} readme={title.group(1)[:40] if title else '-'}")

print("\n== xmlrpc POST (system.listMethods)")
body = (b'<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName>'
        b'<params></params></methodCall>')
for h in ("www.ncaa.go.tz", "www.nimr.or.tz", "www.ptf.or.tz", "www.sbt.go.tz"):
    req = urllib.request.Request(f"https://{h}/xmlrpc.php", data=body,
                                 headers={"User-Agent": scan.UA,
                                          "Content-Type": "text/xml"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=scan.CTX) as r:
            txt = r.read(3000).decode("utf-8", "replace")
            print(f"  {h:20} [{r.status}] methods={len(re.findall('<string>', txt))} "
                  f"multicall={'system.multicall' in txt}")
    except Exception as e:
        print(f"  {h:20} ERR {str(e)[:60]}")

print("\n== October CMS tree exposure (ddca)")
for p in ("/storage/", "/config/", "/themes/", "/modules/", "/plugins/",
          "/vendor/october/rain/LICENSE.md", "/artisan", "/index.php/backend"):
    r = scan.fetch("https://www.ddca.go.tz" + p)
    print(f"  {p:34} {r['status'] if r else 'DOWN'} {len(r['body']) if r else 0}B")
