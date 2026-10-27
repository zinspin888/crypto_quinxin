"""Explore the PC MIS application surface."""
import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

BASE = "https://mis.pc.go.tz"


def show(path):
    r = scan.fetch(BASE + path)
    if not r:
        print(f"{path:60} ERR")
        return
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ",
                 re.sub(r"<(script|style)[^>]*>.*?</\1>", "", r["body"],
                        flags=re.S)))
    print(f"{path:60} {r['status']} {len(r['body'])} :: {text.strip()[:110]}")


print("== root view")
r = scan.fetch(BASE + "/pcmis.data/")
if r:
    print("status", r["status"], "len", len(r["body"]))
    print("forms:", re.findall(r'<form[^>]*>', r["body"], re.I))
    print("links:", list(dict.fromkeys(
        re.findall(r'href=["\']([^"\']+)["\']', r["body"])))[:20])

print("\n== module / endpoint probes")
for p in ["/pcmis.data/index.php", "/pcmis.data/view/", "/pcmis.data/model/",
          "/pcmis.data/controller/", "/pcmis.data/view/modules/",
          "/pcmis.data/view/modules/registration/",
          "/pcmis.data/view/modules/login/", "/pcmis.data/login.php",
          "/pcmis.data/upload/", "/pcmis.data/files/", "/pcmis.data/uploads/",
          "/pcmis.data/phpinfo.php", "/pcmis.data/info.php"]:
    show(p)
