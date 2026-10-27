"""Look for a routing parameter on the single-file admin app."""
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

BASE = "https://www.pc.go.tz/root/index.php"
BASE_NAMES = ["page", "p", "view", "action", "act", "id", "mod", "do", "screen",
              "tab", "section", "file", "inc", "url"]
VALUES = ["users", "home", "dashboard", "1"]

ref = len(scan.fetch(BASE)["body"])
print("baseline length:", ref)

for name in BASE_NAMES:
    seen = {}
    for v in VALUES:
        r = scan.fetch(f"{BASE}?{name}={v}")
        if r:
            seen[v] = (r["status"], len(r["body"]))
    if len({s for s in seen.values()}) > 1 or any(l != ref for _, l in seen.values()):
        print(f"  INTERESTING ?{name}= -> {seen}")
    else:
        print(f"  {name:8} -> flat {list(seen.values())[0]}")
