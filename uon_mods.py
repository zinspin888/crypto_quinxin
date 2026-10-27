"""Enumerate contrib modules/themes on uonbi by reading their .info files.

The directory listing is 403 but individual files are served, so name guessing
works. A hit is only reported when the body parses as a Drupal .info file
(`name =` plus `core =`), which keeps catch-all hosts out.
"""
from __future__ import annotations

import concurrent.futures as cf
import sys

sys.path.insert(0, ".")
import scan  # noqa: E402

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
scan.TIMEOUT = 10

BASE = "https://uonbi.ac.ke"
MODS = """views ctools token pathauto webform ckeditor captcha imce media
admin_menu backup_migrate chaos_tool_suite cshs date devel draggableviews
entity features feeds field_collection file_entity google_analytics
i18n job_scheduler libraries link mailchimp metatag misc module_filter
node_export oauth panels pathologic print redirect references rules
search_api services sharethis simpletest smtp strongarm taxonomy_menu
token transliteration variable views_bulk_operations views_slideshow
wysiwyg xmlsitemap yuicompressor restws clientside_validation
ajax_loader beautytips colorbox ctm ctools_views entityreference
fivestar flexslider galleria media_youtube menu_block nice_menus
owlcarousel scald slick superfish tb_megamenu twitter_block
video_embed_field workbench bootstrap carouseljquery jquery_update
lightbox2 magnific_popup nivo_slider photoswipe pretty_photo
responsive_menus simple_gmap slideshow views_isotope
""".split()

THEMES = """porto_sub omega zen bartik bootstrap_sub seven tao
rubik twitter_bootstrap adaptivetheme""".split()


def check(kind, name):
    for sub in ("modules", "modules/contrib"):
        if kind == "theme":
            sub = "themes"
        url = f"{BASE}/sites/all/{sub}/{name}/{name}.info"
        r = scan.fetch(url)
        if not r or r["status"] != 200:
            continue
        body = r["body"]
        if "core = " not in body and "core=" not in body:
            continue
        meta = {}
        for line in body.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                meta[k.strip()] = v.strip().strip('"')
        return {"kind": kind, "name": name, "path": f"/sites/all/{sub}/{name}",
                "version": meta.get("version", ""), "core": meta.get("core", ""),
                "project": meta.get("project", ""), "title": meta.get("name", "")}
    return None


jobs = [("module", m) for m in MODS] + [("theme", t) for t in THEMES]
hits = []
with cf.ThreadPoolExecutor(max_workers=8) as pool:
    for res in pool.map(lambda j: check(*j), jobs):
        if res:
            hits.append(res)

for h in sorted(hits, key=lambda x: (x["kind"], x["name"])):
    print(f"  {h['kind']:6} {h['name']:24} {h['version'] or '?':12} core={h['core']:6} {h['path']}")

print(f"\n{len(hits)} modules/themes identified out of {len(jobs)} probed")
