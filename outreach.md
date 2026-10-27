# Outreach copy

Three things to get right: it must be short, it must contain one fact that is
provably about *their* host, and it must not ask for a meeting in the first email.

## Email - English (first contact)

Subject: `[agency] website - PHP version from the 21 Oct advisory`

> Ndugu [name],
>
> I run external read-only checks on Tanzanian public-sector websites. Your site
> `[host]` is currently running **PHP [version]**, which is below the fix for
> CVE-2026-109618/109619 published on 21 October.
>
> Two things I can confirm from outside, without touching anything:
>
> - `[specific second finding, e.g. "the web root error_log is publicly readable
>   and discloses your server path">`
> - `[third, if short]>`
>
> One page attached. If useful, I can do the deeper read-only pass and hand your
> web team a fix list with effort estimates - that part is paid, and the price is
> fixed before we start.
>
> Regards,
> [name] - [phone] - [site]

## Email - Swahili (first contact)

Subject: `Tovuti ya [agency] - toleo la PHP baada ya tangazo la 21 Oktoba`

> Ndugu [jina],
>
> Nafanya ukaguzi wa nje (read-only) wa tovuti za taasisi za umma. Tovuti yako
> `[host]` inatumia **PHP [version]**, toleo lililo chini ya marekebisho ya
> CVE-2026-109618/109619 yaliyotolewa 21 Oktoba.
>
> Mambo mawili ninayoweza kuthibitisha bila kugusa chochote:
>
> - `[finding ya pili]>`
> - `[finding ya tatu]>`
>
> Ukurasa mmoja umeambatishwa. Ikiwa unahitajika, naweza kufanya ukaguzi wa kina
> na kuwapa timu yako orodha ya marekebisho pamoja na makadirio ya muda - hii ni
> ya kulipia, na bei inakubaliwa kabla ya kuanza.
>
> Wasalaam,
> [jina] - [simu]

## Follow-up (day 4, same thread, one line)

> Ndugu [name], kuongeza tu: [agency] bado iko kwenye toleo `[version]` leo.
> Ukurasa ule ule umeambatishwa. - [name]

## The phone call (after a reply, not before)

- Open with what they asked about, not your methodology.
- If they say "our vendor handles it": offer the re-test. Vendors dislike being
  checked, which is exactly why the agency wants it.
- If they say "no budget": ask who owns the budget next quarter, and whether you
  may send the fix list to their vendor anyway. Free list now, paid re-test later.
- Never quote on the call. "I'll send a scope and price today."

## Six facts worth leading with, per agency

Pull from the verified set, one per target, never generic:

| Host | Lead fact |
|---|---|
| www.ppra.go.tz | `error_log` readable, discloses `/data/pprago/private/` (Laravel private tree) |
| www.ncaa.go.tz | `error_log` readable (38 KB of PHP fatals) + `/wp-json/wp/v2/users` publishes the admin username |
| www.nimr.or.tz | four staff usernames enumerable and `xmlrpc.php` accepts bulk login attempts |
| www.ddca.go.tz | `composer.lock` published: Laravel 5.1.45 / Symfony 2.7, both EOL |
| www.pasiansiwildlife.ac.tz | `phpinfo.php` fully exposed, `open_basedir` unset |
| www.hlpc.go.tz, www.masasi.go.tz | PHP 7.0.33 - EOL since January 2019 |

## Do not

- Do not attach the 251-row estate table to a single-agency email. Attach one page.
- Do not write "you can be hacked". Write "vulnerable build".
- Do not send more than two follow-ups. Silence after two means wrong person.
- Do not phone a ministry switchboard and ask for "IT". Ask for "Mkurugenzi wa TEHAMA"
  or the ICT officer by title.
