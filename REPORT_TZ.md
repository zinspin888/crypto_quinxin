# PHP CVE-2026-109618 / CVE-2026-109619 - Tanzania government exposure report

Generated: 2026-10-26 18:27 UTC  
Targets probed: 251 (Tanzania government organisations)

## What the vulnerability is

Two *critical* PHP engine bugs were published 2026-10-21 and fixed in
8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Both are unauthenticated remote code
execution requiring no credentials, no admin panel and no crafted file upload.

| ID | GHSA | Class | Mechanism |
|---|---|---|---|
| CVE-2026-109618 | GHSA-w8hw-w9fx-j79w | RCE via OOM corruption | A multipart request that bypasses `post_max_size` (missing usable content-length, or thousands of part headers) forces an OOM `longjmp()` while request memory is reachable-but-uninitialised; cleanup then walks invalid memory. |
| CVE-2026-109619 | GHSA-6wmf-4rv5-p3rp | RCE via stale global state | Error/session state surviving a worker across a request boundary, plus a fatal error or late warning, leaves a dangling pointer; the next request consumes the stale state and heap grooming turns it into RCE. |

CVSS v4.0 for both: `AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`.
`AC:H` means a single packet will not prove exploitability - detection here is
**version fingerprinting**, not payload firing.

Affected: every PHP release below the fixed values above, i.e. **all** of
7.x and 5.x (EOL, never backported), 8.0.x, 8.1.x, and 8.2.0-8.2.34,
8.3.0-8.3.35, 8.4.0-8.4.26, 8.5.0-8.5.11.

## Headline

- **Vulnerable PHP confirmed: 54**
- Patched already: 4
- PHP present, version hidden: 133
- No PHP observed: 60

## Confirmed vulnerable

| Host | Category | PHP | Evidence | Resolves to |
|---|---|---|---|---|
| asdp.kilimo.go.tz | gov | 5.6.40 | header x-powered-by: PHP/5.6.40; version disclosed: 5.6.40 | 154.118.230.167 |
| lawyers.gov.go.tz | gov | 5.6.40 | header x-powered-by: PHP/5.6.40; version disclosed: 5.6.40 | 154.118.230.167 |
| miradi.uwezeshaji.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 196.192.79.159 |
| sumajkt.go.tz | gov | 8.0.30 | header x-powered-by: PHP/8.0.30; version disclosed: 8.0.30 | 196.192.79.159 |
| tanipac.kilimo.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 154.118.230.167 |
| uwekezaji.iringa.go.tz | gov | 7.4.33 | header x-powered-by: PHP/7.4.33; version disclosed: 7.4.33 | 154.118.230.167 |
| www.arimo.ac.tz | gov | 5.6.40 | header x-powered-by: PHP/5.6.40; version disclosed: 5.6.40 | 154.118.230.167 |
| www.brela.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 196.192.79.159 |
| www.camartec.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 196.192.79.159 |
| www.chaliwasa.go.tz | gov | 5.6.40 | header x-powered-by: PHP/5.6.40; version disclosed: 5.6.40 | 154.118.230.167 |
| www.chawassa.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; PHPSESSID cookie; version disclosed: 7.2.34 | 196.192.79.159 |
| www.ethicssecretariat.go.tz | gov | 8.0.30 | header x-powered-by: PHP/8.0.30; version disclosed: 8.0.30 | 196.192.79.159 |
| www.fiti.ac.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 196.192.79.159 |
| www.foreign.go.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 154.118.230.167 |
| www.geuwasa.go.tz | gov | 7.4.33 | header x-powered-by: PHP/7.4.33; version disclosed: 7.4.33 | 196.192.79.159 |
| www.gpsa.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 196.192.79.159 |
| www.hlpc.go.tz | gov | 7.0.33 | header x-powered-by: PHP/7.0.33; version disclosed: 7.0.33 | 154.118.230.167 |
| www.inec.go.tz | gov | 8.0.30 | header x-powered-by: PHP/8.0.30; version disclosed: 8.0.30 | 196.192.79.159 |
| www.lita.go.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 196.192.79.159 |
| www.maji.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 196.192.79.159 |
| www.masasi.go.tz | gov | 7.0.33 | header x-powered-by: PHP/7.0.33; version disclosed: 7.0.33 | 154.118.230.167 |
| www.mkurabita.go.tz | gov | 7.4.33 | header x-powered-by: PHP/7.4.33; version disclosed: 7.4.33 | 196.192.79.159 |
| www.moh.go.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 196.192.79.159 |
| www.morogorotc.ac.tz | gov | 7.4.33 | header x-powered-by: PHP/7.4.33; version disclosed: 7.4.33 | 196.192.79.159 |
| www.mwauwasa.go.tz | gov | 7.4.33 | header x-powered-by: PHP/7.4.33; version disclosed: 7.4.33 | 196.192.79.159 |
| www.mwtc.go.tz | gov | 8.0.30 | header x-powered-by: PHP/8.0.30; version disclosed: 8.0.30 | 196.192.79.159 |
| www.nbts.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 196.192.79.159 |
| www.ncaa.go.tz | gov | 8.1.34 | header x-powered-by: PHP/8.1.34; version disclosed: 8.1.34 | 154.118.230.167 |
| www.nec.go.tz | gov | 8.0.30 | header x-powered-by: PHP/8.0.30; version disclosed: 8.0.30 | 154.118.230.167 |
| www.nfqclab.go.tz | gov | 5.6.40 | header x-powered-by: PHP/5.6.40; version disclosed: 5.6.40 | 154.118.230.167 |
| www.nhbra.go.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 196.192.79.159 |
| www.nje.go.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 154.118.230.167 |
| www.nlupc.go.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 196.192.79.159 |
| www.ntdcp.go.tz | gov | 5.6.40 | header x-powered-by: PHP/5.6.40; version disclosed: 5.6.40 | 154.118.230.167 |
| www.nyaraka.go.tz | gov | 7.4.33 | header x-powered-by: PHP/7.4.33; version disclosed: 7.4.33 | 196.192.79.159 |
| www.orci.or.tz | gov | 7.4.33 | header x-powered-by: PHP/7.4.33; PHPSESSID cookie; version disclosed: 7.4.33 | 154.118.230.167 |
| www.pasiansiwildlife.ac.tz | gov | 8.0.30 | /phpinfo.php -> 8.0.30 | 197.149.178.6 |
| www.pc.go.tz | gov | 5.6.40 | header x-powered-by: PHP/5.6.40; PHPSESSID cookie; version disclosed: 5.6.40 | 154.118.230.167 |
| www.pmo.go.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 196.192.79.159 |
| www.psrb.go.tz | gov | 5.6.40 | header x-powered-by: PHP/5.6.40; version disclosed: 5.6.40 | 154.118.230.167 |
| www.ptf.or.tz | gov | 7.4.33 | header x-powered-by: PHP/7.4.33; version disclosed: 7.4.33 | 154.118.230.167 |
| www.sbt.go.tz | gov | 8.0.30 | header x-powered-by: PHP/8.0.30; PHPSESSID cookie; version disclosed: 8.0.30 | 154.118.230.167 |
| www.sumajkt.go.tz | gov | 8.0.30 | header x-powered-by: PHP/8.0.30; version disclosed: 8.0.30 | 196.192.79.159 |
| www.taa.go.tz | gov | 8.1.34 | header x-powered-by: PHP/8.1.34; version disclosed: 8.1.34 | 154.118.230.167 |
| www.tacaids.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 154.118.230.167 |
| www.tagla.go.tz | gov | 7.0.33 | header x-powered-by: PHP/7.0.33; version disclosed: 7.0.33 | 154.118.230.167 |
| www.tasaf.go.tz | gov | 8.1.34 | header x-powered-by: PHP/8.1.34; version disclosed: 8.1.34 | 154.118.230.167 |
| www.tawa.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 154.118.230.167 |
| www.tcra-ccc.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 154.118.230.167 |
| www.teiti.go.tz | gov | 7.2.34 | header x-powered-by: PHP/7.2.34; version disclosed: 7.2.34 | 154.118.230.167 |
| www.tprb.go.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 196.192.79.159 |
| www.trc.co.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 196.192.79.159 |
| www.ushirika.go.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 154.118.230.167 |
| www.viwanda.go.tz | gov | 7.3.33 | header x-powered-by: PHP/7.3.33; version disclosed: 7.3.33 | 154.118.230.167 |


## Confirmed patched

| Host | Category | PHP | Evidence | Resolves to |
|---|---|---|---|---|
| www.cpaafricaregion.or.tz | gov | 8.2.35 | /phpinfo.php -> 8.2.35 | 197.149.178.5 |
| www.feta.ac.tz | gov | 8.3.36 | header x-powered-by: PHP/8.3.36; version disclosed: 8.3.36 | 154.118.230.167 |
| www.metfund.go.tz | gov | 8.2.35 | header x-powered-by: PHP/8.2.35; version disclosed: 8.2.35 | 196.192.79.159 |
| www.vpo.go.tz | gov | 8.4.27 | header x-powered-by: PHP/8.4.27; version disclosed: 8.4.27 | 196.192.79.254 |


## PHP confirmed, version not disclosed

| Host | Category | PHP | Evidence | Resolves to |
|---|---|---|---|---|
| blog.maelezo.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| blog.maliasili.go.tz | gov |  | /wp-login.php present (HTTP 200) | 41.59.90.210 |
| jlmes.nit.ac.tz | gov |  | /index.php served (PHP handler present) | 41.93.71.17 |
| register.papu40anniversary.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| register.sadctanzania.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| tomsha.tacaids.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.77.90 |
| www.adem.ac.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.agitf.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.ajira.go.tz | gov |  | /wp-login.php present (HTTP 200) | 197.149.179.228 |
| www.aqrb.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.asa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.atf.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.auwsa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.bakita.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.bammata.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.basata.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.bmh.or.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.bunge.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.cfr.ac.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.chragg.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.cma.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.cpb.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.dart.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.dawasa.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.dcea.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.ddca.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.dib.go.tz | gov |  | /wp-includes/version.php present (HTTP 200) | 102.223.8.61 |
| www.dmi.ac.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.dsfa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.duwasa.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.ewuraccc.go.tz | gov |  | WordPress asset paths in body | 196.192.79.246 |
| www.filmboard.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.fiu.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.gasco.co.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.gst.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.ictc.go.tz | gov |  | /index.php served (PHP handler present) | 41.59.225.216 |
| www.idbwb.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.iruwasa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.isw.ac.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.jamii.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.judiciary.go.tz | gov |  | /wp-login.php present (HTTP 200) | 196.192.77.14 |
| www.kariakoomarket.co.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.kashwasa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.kec.or.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.kilimanjaroairport.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.kuwasa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.lvbwb.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.maadili.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.maliasili.go.tz | gov |  | /wp-login.php present (HTTP 200) | 41.59.90.210 |
| www.manawasa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.marineparks.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.mawasiliano.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.mbeyauwsa.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.meteo.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.michezo.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.mifugouvuvi.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.mnma.ac.tz | gov |  | /index.php served (PHP handler present) | 154.118.230.167 |
| www.moe.go.tz | gov |  | /wp-login.php present (HTTP 200) | 197.149.179.215 |
| www.moha.go.tz | gov |  | /wp-login.php present (HTTP 200) | 197.149.178.5 |
| www.moi.ac.tz | gov |  | /index.php served (PHP handler present) | 197.149.179.198 |
| www.mow.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.mtuwasa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.muwsa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.mwekawildlife.ac.tz | gov |  | WordPress asset paths in body | 197.149.178.5 |
| www.nbaa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.nbs.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.ncc.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.nemc.or.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.nfra.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.nhc.co.tz | gov |  | /wp-login.php present (HTTP 200) | 197.149.179.156 |
| www.nhif.or.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.nictanzania.co.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.nimr.or.tz | gov |  | /wp-login.php present (HTTP 200) | 41.59.225.156 |
| www.nirc.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.nmt.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.nmtc.ac.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.nwf.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.orpp.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.osg.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.osha.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.panganibasin.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.parliament.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.pbpa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.ppra.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.179.225 |
| www.psc.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.psptb.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.pura.go.tz | gov |  | WordPress asset paths in body | 196.192.79.246 |
| www.rufijibasin.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.ruwasa.go.tz | gov |  | PHPSESSID cookie | 196.192.79.246 |
| www.sadctanzania.go.tz | gov |  | /wp-login.php present (HTTP 302) | 196.192.79.246 |
| www.sheria.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.shuwasa.go.tz | gov |  | /wp-login.php present (HTTP 200) | 197.149.178.5 |
| www.stamico.co.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.tamisemi.go.tz | gov |  | /wp-login.php present (HTTP 200) | 102.219.172.39 |
| www.tangauwasa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tanroads.go.tz | gov |  | /index.php served (PHP handler present) | 154.118.230.167 |
| www.tantrade.go.tz | gov |  | /index.php served (PHP handler present) | 196.192.77.103 |
| www.tari.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.tarura.go.tz | gov |  | /wp-login.php present (HTTP 301) | 196.192.77.39 |
| www.tasac.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tasuba.ac.tz | gov |  | /index.php served (PHP handler present) | 196.192.79.246 |
| www.tba.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.tbs.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tcaa-ccc.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.tcaa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tcb.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.tdb.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tfnc.go.tz | gov |  | WordPress asset paths in body | 197.149.178.6 |
| www.tfra.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tfs.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tgdc.go.tz | gov |  | /adminer.php present (HTTP 200) | 197.149.179.169 |
| www.tie.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.tirdo.or.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tmb.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.tmda.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.tmx.co.tz | gov |  | /wp-login.php present (HTTP 404) | 154.118.230.167 |
| www.tnbc.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tnmc.go.tz | gov |  | /wp-login.php present (HTTP 200) | 197.149.179.209 |
| www.tobaccoboard.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.torita.or.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.tosci.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tphpa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tpsc.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.trita.ac.tz | gov |  | /wp-login.php present (HTTP 200) | 197.149.178.6 |
| www.tro.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tsc.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.tuwasa.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.5 |
| www.tvla.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.uongozi.go.tz | gov |  | /wp-includes/version.php present (HTTP 404) | 41.59.85.30 |
| www.uwezeshaji.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.veta.go.tz | gov |  | /wp-includes/version.php present (HTTP 200) | 196.192.79.246 |
| www.waterinstitute.ac.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |
| www.wcf.go.tz | gov |  | /index.php served (PHP handler present) | 197.149.178.6 |


## Method

Read-only HTTP GETs, ~8 concurrent, 15s timeout, no exploitation.

Version extracted from, in order: `Server` / `X-Powered-By` / `X-PHP-Version`
headers, `phpinfo.php`-style leftovers, PHP error output in 404 bodies, and
`composer.json`. PHP presence additionally inferred from `PHPSESSID` cookies,
`/wp-login.php`, WordPress asset paths and `/index.php` being handled.

Verdicts compare the parsed version against the per-branch fix list; EOL
branches (5.x, 7.x, 8.0, 8.1) are marked vulnerable because these fixes were
never backported to them.


## Remediation

There is no config mitigation that removes the risk - the flaws are in the
engine. Patch PHP, then restart the FPM/Apache workers so the new binary is
actually in use.

```bash
# Debian/Ubuntu (Ondrej Sury PPA / distro packages)
sudo apt-get update && sudo apt-get install --only-upgrade \
  php8.2-fpm php8.3-fpm php8.4-fpm
sudo systemctl restart php8.3-fpm apache2 nginx
php -v   # confirm the new patch level
```

```bash
# RHEL/Alma/Rocky (Remi)
sudo dnf upgrade --refresh 'php82*' 'php83*' 'php84*'
sudo systemctl restart php-fpm httpd
```

For hosts stuck on 7.x/8.1 (kenet.or.ke, uonbi.ac.ke) an upgrade is a
branch bump, not a patch - budget an app compatibility pass. If they cannot
move, put them behind a WAF and rate-limit large `multipart/form-data` posts,
which blunts the OOM vector but does not eliminate it.


## Caveats

1. **Negative is not proof.** A version hidden behind a CDN/WAF cannot be
   graded from outside; `PHP-UNKNOWN-VERSION` needs server-side confirmation
   (`php -v`, package version).
2. **Behind a reverse proxy** the edge PHP may differ from the origin. Test
   the origin directly.
3. `AC:H` means an affected version is *exposed*, not *demonstrably
   exploitable*. Confirming RCE needs the advisory PoCs against a staging clone.
4. Cloudflare/JS-challenged hosts (jumia, safaricom, nation) under-report.
