"""Rapid triage of candidate foothold targets before committing to one."""
import re
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

CANDIDATES = [
    "lawyers.gov.go.tz", "www.chaliwasa.go.tz", "www.ntdcp.go.tz",
    "www.pc.go.tz", "www.arimo.ac.tz", "www.brela.go.tz",
    "www.inec.go.tz", "www.moh.go.tz",
]

CMS = {
    "WordPress": ["wp-content", "wp-includes", "wp-json"],
    "Joomla": ["/media/system/js/", "option=com_", "joomla"],
    "Drupal": ["/sites/default/", "drupal", "sites/all/"],
    "CodeIgniter": ["ci_session"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "phpMyAdmin": ["pma_", "phpmyadmin"],
}
PATHS = ["/phpinfo.php", "/info.php", "/admin/", "/administrator/", "/wp-login.php",
         "/user/login", "/.git/HEAD", "/.env", "/backup.zip", "/config.php.bak",
         "/web.config", "/phpmyadmin/", "/db/", "/api/"]

for h in CANDIDATES:
    r = scan.fetch(f"https://{h}/")
    body = r["body"] if r else ""
    low = body.lower()
    kind = [k for k, marks in CMS.items() if any(m.lower() in low for m in marks)]
    title = (re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S) or [None, ""])[1]
    forms = re.findall(r"<form[^>]*>", body, re.I)
    uploads = sum(1 for f in forms if "multipart" in f.lower())
    print(f"\n=== {h}  status={r['status'] if r else 'ERR'} len={len(body)}")
    print(f"    server={(r['headers'].get('Server') if r else '')}")
    print(f"    cms={kind or '-'}  title={title.strip()[:70]!r}")
    print(f"    forms={len(forms)} multipart={uploads}")
    hits = []
    for p in PATHS:
        s = scan.fetch(f"https://{h}{p}")
        if s and s["status"] not in (404, 0):
            hits.append(f"{p}={s['status']}({len(s['body'])})")
    print(f"    paths: {' '.join(hits) or '-'}")
