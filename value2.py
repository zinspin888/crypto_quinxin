"""Follow-ups: October backend path/artisan, and ptf's 4.9.26 surface."""
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

print("== ddca artisan + backend hunt")
r = scan.fetch("https://www.ddca.go.tz/artisan")
print("  artisan:", " ".join(r["body"].split())[:200] if r else "DOWN")
for p in ("/backend", "/manage", "/admin", "/october", "/backend/backend"):
    x = scan.fetch("https://www.ddca.go.tz" + p)
    print(f"  {p:20} {x['status'] if x else 'DOWN'} {len(x['body']) if x else 0}B")

print("\n== ptf (WP 4.9.26) surface")
for p in ("/wp-content/", "/wp-content/uploads/", "/wp-json/",
          "/wp-links-opml.php", "/wp-sitemap.xml", "/?author=1",
          "/wp-admin/install.php", "/wp-content/debug.log"):
    x = scan.fetch("https://www.ptf.or.tz" + p)
    body = " ".join(x["body"].split())[:70] if x else ""
    print(f"  {p:26} {x['status'] if x else 'DOWN'} {len(x['body']) if x else 0}B {body}")
