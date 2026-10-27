# Growing the exploitation inventory

## What is inventoried now

| Layer | Coverage |
| --- | --- |
| Offset inventory | 12 builds: 7.4.33, 8.0.30, 8.1.34, 8.2.0, 8.2.34, 8.3.0, 8.3.35, 8.4.25, 8.4.26, 8.5.0, 8.5.10, 8.5.11 |
| Heap profiles | 8.3.33, 8.3.35 (leaks); 8.4.25, 8.4.26, 8.5.10, 8.5.11 aarch64/amd64 (RCE); 7.4/8.0/8.1/8.2 (offsets only) |
| Verified RCE | 8.4.25 aarch64, 8.4.26 amd64, 8.5.10 aarch64, 8.5.11 aarch64, 8.5.11 amd64 |
| Labs | `:8100`-`:8106`, one per build |
| Catalog | all vulnerable branches 5.4 → 8.5, plus 8.6 RC |

Each offset entry carries the `libphp.so` **sha256**, so two builds with the same
version number (a vendor backport, a different distro, an ASAN build) are
distinguishable.

## Axes to expand

1. **Version/tag** — every patch release in a vulnerable branch.
2. **Distro** — Debian bookworm, Ubuntu, Alpine, Fedora, vendor packages.
3. **Arch** — aarch64 and x86_64; offsets and heap layout differ.
4. **Build hash** — `libphp.so` sha256; the real identity of a build.
5. **SAPI** — mod_php prefork, PHP-FPM, CLI (the chain is mod_php-specific).
6. **Configuration** — `memory_limit`, `display_errors`, worker count,
   `post_max_size`, session settings.
7. **Chain/precondition** — zero-prereq OOM chain, `var_destroy` gadget chain,
   session-file + LFI, handler mismatch.

## Lanes

### Offset lane (fast, no target run)

```sh
python3 tools/php2shell_offsets.py --images php:8.4.25-apache php:8.5.10-apache
```

Creates a container, copies `libphp.so`, parses the ELF symbol table, writes
`profiles/offsets/<version>-<arch>.json` and rewrites `docs/offset-inventory.md`.
No PHP request is made, so it scales to dozens of tags.

### Calibration lane (heap + RCE proof)

```sh
python3 tools/php2shell_matrix.py --only 8.4.26 --repo-dir /tmp/php2shell-rce
```

Stages 1-2 are discovered automatically; stage 3 is tried with the known
layouts and a profile is marked `rce=true` only after a real command proof.
Builds that only leak are stored with `rce=false`.

### Configuration lane

- `memory_limit`: 8M and 128M verified on 8.4.26; the dispatcher probes it.
- `display_errors=Off`: not implemented; a separate leak path is required.
- multi-worker prefork: supported with `--pin-workers N` (keep-alive pinning);
  verified on 2 and 4 workers.
- PHP-FPM: different lifecycle; the mod_php chain does not transfer directly.

### Remote lane

`tools/php2shell_assess.py` fingerprints exposure. A remote build cannot be
hashed without reading its `libphp.so`; profiles are selected by
version + distro, and the operator supplies offsets for an unknown build.

## Automation

A CI job can, for each tag in a list:

1. run the offset lane and store the sha256-keyed JSON;
2. start a disposable lab and run the calibrator;
3. run the RCE proof and record the result;
4. publish `docs/offset-inventory.md` / `docs/profile-inventory.md` and a
   regression table.

The entry point is `tools/php2shell_matrix.py`; the offset lane is
`tools/php2shell_offsets.py`; the dispatcher only runs `rce=true` profiles.

## Priorities

1. **8.4.x / 8.5.x adjacent patches** (8.4.25, 8.5.10, 8.5.0): they likely
   share the 8.4/8.5 heap layout, so a quick calibrate may add RCE profiles.
2. **x86_64 variants** of the verified images: same version, different offsets.
3. **Configuration variants**: 128M (done), `display_errors=Off`, multi-worker.
4. **FPM** port and **older branches** (research).
5. **Other chains** for app-specific preconditions, clearly separated from the
   zero-prereq chain.
