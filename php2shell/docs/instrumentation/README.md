# Runtime instrumentation

Read-only `/proc/<pid>/mem` inspection of the local laboratories. No gdb and no
agent inside the target: a sidecar container shares the PID namespace and reads
the Apache worker's memory.

## ps_globals offsets

Extracted from each image's `libphp.so` with `nm -D`:

| PHP | `ps_globals` |
| --- | --- |
| 7.4.33 | 0x0d15738 (`libphp7.so`) |
| 8.0.30 | 0x0e37d50 |
| 8.1.34 | 0x0ecc350 |
| 8.2.34 | 0x0f0c998 |
| 8.3.35 | 0x101ca90 |
| 8.4.26 | 0x1316820 |
| 8.5.11 | 0x1751f50 |

The 7.4 image ships `libphp7.so`; the oracle now matches any `libphp*` mapping.

## Usage

```sh
docker run --rm --pid=container:p2s-lab-8335 --cap-add=SYS_PTRACE \
  -v "$PWD/docs/instrumentation/mem_dump.php:/m.php:ro" \
  php:8.2-fpm php /m.php 0x101ca90
```

`mem_dump.php` prints `PS(http_session_vars)` (R0), the reference at R0 and the
session array at `val.value` (R1). `id_dump.php` prints `PS(id)`.

## Findings

### 8.3.35 — the reference and array are alive

After the stage-3 "A" request:

```text
R0+0x00  02000000 1a000000   refcount=2, type=0x1a (IS_REFERENCE|flags)
R0+0x08  e087c584 ffff0000   val.value = chunk+0x587e0
R0+0x10  07030000 00000000   val.type  = 0x307 (IS_ARRAY)

R1+0x00  01000000 07000000   refcount=1, type=7 (IS_ARRAY)
R1+0x08  00000000 f0ffffff   flags=0, nTableMask=-16
R1+0x10  805bc684 ffff0000   arData = chunk+0x65b80
R1+0x30  c0fc1287 ffff0000   pDestructor = libphp+...
```

Both objects are valid and referenced. `zval_ptr_dtor` on the session zval only
decrements the reference (2 -> 1); it does not destroy it. The 8.4/8.5 stage-3
carrier assumes it can overwrite or destroy the reference; on 8.3 the object is
alive and cannot be reclaimed by heap reuse. This is the concrete blocker.

### 8.2.34 — dangling id, leak shape does not transfer

`PS(id)` is non-NULL after A (`0xffff984a7000`), so the stale pointer exists.
B requests with values of 16, 24, 32, 40, 48, 56, 64, 80, 96, 112 and 128 bytes
never reclaim it: at 56/64/80 the response carries a new 32-character id, at the
other sizes no cookie is emitted.

### 8.4.26 — oracle adjustment

The working 8.4.26 image is amd64 under emulation and its Zend MM chunk is not
exposed as a 2 MB `rw-p` mapping, so `mem_dump.php` finds no chunk. The leak
still reports `chunk=0x7ffffc400000`; the oracle needs to accept that mapping
shape before the differential comparison can be completed.

## Next experiments

1. Adapt the oracle to the 8.4.26 mapping and dump the same fields; if its
   reference is freed/dangling, that is the condition 8.3 lacks.
2. For 8.3, target the live array at `chunk+0x587e0` instead of R0, or force the
   OOM inside `php_session_initialize` so the reference is left half-built.
3. For 8.2 and the EOL branches, repeat the id/value-size sweep and inspect the
   B session lifecycle before the cookie is built.
