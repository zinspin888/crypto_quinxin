"""Cross-reference the new artefact hits against the exposure scan."""
import csv
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

rows = {r["host"]: r for r in csv.DictReader(open("results_tz.csv", encoding="utf-8"))}
for h in ["jlmes.nit.ac.tz", "sumajkt.go.tz", "uwekezaji.iringa.go.tz",
          "www.mbeyauwsa.go.tz", "www.ncaa.go.tz", "www.ppra.go.tz",
          "www.tasuba.ac.tz", "www.viwanda.go.tz", "www.nhc.co.tz",
          "www.ddca.go.tz", "www.nimr.or.tz", "www.ptf.or.tz", "www.sbt.go.tz",
          "www.tagla.go.tz", "www.veta.go.tz"]:
    r = rows.get(h)
    if not r:
        print(f"{h:28} (not in scan)")
        continue
    print(f"{h:28} {r['verdict']:22} {r.get('php_version','') or '-':10} {r.get('ip','')}")
