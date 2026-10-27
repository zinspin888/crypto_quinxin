"""Extract parameterised / dynamic links from the public site."""
import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

for page in ["https://www.pc.go.tz/", "https://www.pc.go.tz/index.php"]:
    r = scan.fetch(page)
    if not r:
        print("ERR", page)
        continue
    b = r["body"]
    print(f"\n=== {page} status={r['status']} len={len(b)}")
    qs = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']*\?[^"\']+)["\']', b, re.I)
    for q in list(dict.fromkeys(qs))[:20]:
        print("   ?", q[:110])
    phps = re.findall(r'["\']([^"\']+\.php(?:\?[^"\']*)?)["\']', b, re.I)
    print("   php refs:", list(dict.fromkeys(phps))[:15])
