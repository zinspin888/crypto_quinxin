import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

r = scan.fetch("https://uonbi.ac.ke/phpmyadmin/")
print("status", r["status"], len(r["body"]))
b = r["body"]
print("server:", r["headers"].get("Server"))
print("xpb:", r["headers"].get("X-Powered-By"))
print("version hints:", re.findall(r"phpMyAdmin[^\"<\n]{0,30}", b)[:6])
print("generator:", re.findall(r'name="?generator"?[^>]*', b)[:2])
print("pw fields:", re.findall(r'name="pma_username"|name="pma_password"|name="input_username"', b)[:4])
print("cookies:", [h for h in r["headers"] if "cookie" in h.lower()])
