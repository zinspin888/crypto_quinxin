# How to turn this into money

Blunt version first: **there is no Tanzania government bug bounty.** No .go.tz
programme pays per bug, so "report and collect" does not exist here. Money comes
from four places only, and the recon is a door-opener for all of them, not a
product by itself.

## What you actually have

Strip the noise and the sellable assets are:

1. **A national dataset** - 251 government hosts fingerprinted, 54 confirmed on
   vulnerable PHP, with the shared hosting topology mapped. Nobody else has
   assembled this.
2. **A live, dated CVE** - CVE-2026-109618/19, published 2026-10-21, patched five
   days ago. Urgency is the single best sales lever available and it expires.
3. **A systemic story** - one phpMyAdmin fronting 41 agencies, one phpinfo
   showing no `open_basedir`, one published `composer.lock` pinning Laravel
   5.1.45. These are *host-level* faults, which is what a hosting provider buys.
4. **Proof of method** - the detector's own false-negative/false-positive history
   (159 to 1, then the 300-hit multicall bug) is evidence you verify instead of
   guessing. Clients pay for that discipline more than for findings.

The recon is worth ~nothing as a document. It is worth money as the reason
someone takes a meeting.

## The four revenue paths, ranked by realism

### 1. Paid assessments (highest realistic income)

Use the estate report as a portfolio piece, sell **per-site fixed-scope audits**
to individual agencies, schools and parastatals. This is the only path that pays
a meaningful amount from this work, and it is repeatable.

Anchor on the CVE, not on hygiene: *"your PHP is on the vulnerable build from
last week, here is what a migration-readiness check costs"*. Hygiene findings
ride along free.

### 2. The hosting provider, not the 41 agencies

`154.118.230.167` fronts dozens of `.go.tz` sites on one phpMyAdmin. Selling to
41 agencies individually is 41 procurement fights. Selling one hardening
engagement to whoever runs that box is one fight, and it is a far better story:
*"one credential reaches every database behind your platform."*

Same for the shared cPanel stack named in the phpinfo leak.

### 3. Donor / programme-funded audits

Digital-government programmes funded by World Bank, GIZ, Hivos, UN agencies and
similar carry budget lines for security review and need local vendors - foreign
firms are expensive and slow. The report is your sample. This is where a
five-figure engagement actually lives, but it needs a registered entity and
patience.

### 4. Subcontracting

Firms that build government sites (and eGA-registered vendors) periodically need
a tester for their own delivery. Less money, no procurement, and it starts
immediately. This is the realistic entry point while you have no company.

## What the market will bear

Ranges, benchmarked on East African freelance and small-shop work - starting
points, and expect to be argued down by half at first:

| Deliverable | Realistic price | Effort |
|---|---|---|
| One-vhost audit (verified findings + fixes) | TZS 800k-2.5M / USD 300-950 | 1-2 days |
| 10-site batch for one agency | TZS 4-8M / USD 1.5-3k | 1 week |
| Shared-platform hardening review | USD 2-5k | 2 weeks |
| Re-test after remediation | 40-60% of original | 1 day |
| Donor programme assessment | USD 5-15k | 3-6 weeks |

Price the **re-test** explicitly at quote stage. It is the most profitable line
and the one clients forget to compare.

## What to package (gaps you must close)

Right now the artefacts are hacker notes. Nobody signs an LPO against markdown.
Before first outreach you need:

- **PDF, not .md.** Convert what `report.py` emits.
- **A one-page executive summary per target** in plain language, business impact
  first, TZS figures for downtime and data loss, no CVE IDs on page one.
  `sample-exec-summary.md` is the shape.
- **Remediation with effort estimates** (PHP `ea-php81` switch, an `open_basedir`
  value, phpMyAdmin behind VPN) so the client sees the fix, not just the hole.
- **Scope, methodology, limits.** "Read-only, 2-5 requests per host, no
  exploitation, no data extracted." This is what makes an unsolicited report
  safe to accept.
- **What their own staff must do**, in their terms: who acts, how long, what it
  costs in hours.

## Legal posture, because you are selling it

Testing without permission is tolerated in practice, but selling to an agency you
were never authorised by means you cannot answer "who allowed this?". Sequence
that works:

1. First contact frames it as a **read-only external check** already performed,
   one-pager attached - you are reporting, not asking.
2. Ask for a two-line email authorising deeper testing before anything intrusive.
3. Keep a per-target action log from the moment you go intrusive: timestamps,
   request counts, what changed.
4. Do not leave shells, do not create accounts, do not run writes.

## Invoicing reality

- Government pays 30-90 days and wants an LPO. Budget the gap or you starve
  before the first cheque.
- To invoice: BRELA registration (TZS 300k+ with fees), TIN, VAT if you cross the
  threshold, and NeST/PPRA supplier registration for government work.
- Until then, subcontract or invoice through someone already registered.

## Order of operations

1. Publish the estate report, sanitised, Swahili + English, CVE specifics held
   back from the free copy. Inbound beats cold calls.
2. Cold-contact 5 agencies from the vulnerable list with a one-pager and one
   specific, verifiable fact about *their* host.
3. Take the SPOF story to the hosting provider separately.
4. Register the entity once two clients say yes; before that, subcontract.
5. Put a re-test in every quote.

## Honest failure modes

- **Most cold reports get no reply.** Expect 1 in 10 to answer, 1 in 30 to pay.
  Volume matters; follow-up matters more.
- **The CVE expiry cuts both ways.** Once agencies patch, urgency collapses and
  you are selling hygiene, which nobody budgets for.
- **They will ask "are you certified?"** You are not. Answer with evidence - the
  report, the method, the false-positive story - then buy the cert from first
  earnings, in that order.
- **Do not overclaim.** `AC:H` means exposure, not proven exploitability. Say
  "vulnerable build", never "you can be hacked". The first competent officer who
  checks will catch it.

