# Safe PHP2Shell laboratory on WordPress

This laboratory shows the effective web runtime and the `status → OOM → status`
cycle. The OOM is triggered after WordPress has bootstrapped, using a fixed
maximum of 24 blocks of 1 MiB and a temporary limit 8 MiB above the initial
consumption.

It does **not** implement a PHP2Shell chain: it sends no anomalous multipart
bodies, does not interrupt `unserialize()`, does not groom the heap, does not
consume stale pointers, does not read memory and does not execute commands. An
isolated OOM or HTTP 500 does not prove the CVE; the result only demonstrates
fatal-error handling and worker reuse.

## Laboratory protections

- Compose publishes Apache only on `127.0.0.1:8080`.
- The endpoint requires `PHP2SHELL_LAB_ENABLED=1` and a header token.
- The client rejects any destination that resolves outside loopback and does
  not follow redirects.
- The OOM request accepts no sizes or functions supplied over HTTP and is sent
  once.
- Verbose output hides the token.

The bundled token is a disposable laboratory credential. Do not reuse it and
remove the endpoint when finished.

## Startup

From `lab/wordpress`:

```sh
docker compose config --quiet
docker compose up -d --force-recreate wordpress
docker compose exec -T wordpress php -l /var/www/html/php2shell-lab.php
```

Check only version, SAPI and configuration:

```sh
# historical: the original safe_probe.py was removed in the workspace cleanup
# python3 ../php2shell_safe_probe.py
```

Run a single OOM test and observe recovery:

```sh
# python3 ../php2shell_safe_probe.py --trigger-oom  (script removed in cleanup)
```

Correlate request identifiers and PIDs with the log:

```sh
docker compose logs --no-color --since 2m wordpress | rg 'PHP2SHELL_LAB|Allowed memory size|Out of memory'
```

The endpoint logs `oom_start` before allocating memory and `oom_shutdown` when
it finishes. WordPress has its recovery screen disabled only inside this Compose
file so the fatal error is more deterministic.

## Interpretation

| Result | Correct interpretation |
| --- | --- |
| `STATUS_ONLY` | The real web runtime was obtained. Version classification does not detect vendor backports. |
| `RECOVERED_SAME_WORKER` | The same observed process served another request after a benign OOM. It neither proves nor disproves PHP2Shell. |
| `WORKER_REPLACED_OR_NOT_RESAMPLED` | Another worker answered or the initial one did not appear in the samples; with several workers this is inconclusive. |
| `FAILED` | The endpoint did not respond or WordPress did not recover within the observation window. Check logs and container limits. |

The image observed at the time used PHP 8.3.33. That version string is inside the
affected upstream range and the first fixed upstream release of the branch is
8.3.36. A vendor could have applied a backport while keeping the number, so the
version is evidence of exposure, not proof of exploitation.

## Result observed in this environment

The run of 21 October 2026 obtained:

- WordPress 7.1.1 on PHP 8.3.33, SAPI `apache2handler` and `mod_php` loaded.
- `memory_limit=128M`, `post_max_size=8M`, OPcache and session upload progress
  enabled.
- The deliberate request `lab-3ad3359907664f2a` installed a temporary 12 MiB
  limit on PID 22.
- The log recorded the start, the memory fatal when requesting 1,052,672 bytes
  and the correlated shutdown.
- A later request was again served by PID 22.
- Docker reported `running=true`, `OOMKilled=false`, `Restarting=false` and did
  not recreate the container.

The HTTP status of the OOM request was 200 because the header and the first JSON
block had already been sent when the fatal error occurred. The client therefore
correlates the event with the logs instead of treating the HTTP status as proof.

During the first validation, WordPress removed a generic global variable from
the endpoint and a `status` query accidentally triggered the OOM. It was fixed
by storing the action and identifier in constants before bootstrap; the later
validation separated both actions correctly. The logs keep that earlier trial
(`lab-36f4c77843a742f7`) so the history is explicit.

The verified result is **recovery of the same worker after a benign OOM**. It
does not prove the use-after-free, a memory leak or RCE.

To compare vulnerable/fixed, keep WordPress, extensions and configuration,
change only the runtime and use the same harness. The specific evidence for the
fix remains the version or accredited backport, the patch PHPTs and, if an
instrumented laboratory is compiled, the absence of native errors in those
tests.

## Teardown

When finished, delete `lab/wordpress/wp/php2shell-lab.php` and the `PHP2SHELL_LAB_*` variables
from Compose, remove `WP_DISABLE_FATAL_ERROR_HANDLER` and recreate the service.
The laboratory file allows a deliberate denial of service to anyone who knows
the token, even though the port is bound to loopback.

> Historical note: this document describes the first, deliberately harmless
> laboratory. The current RCE work and the profile factory are documented in
> `exploit-report.md`, `rce-guide.md` and the `tools/` directory.
