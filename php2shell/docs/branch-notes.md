# Branch calibration notes

Status of the branches that do not yet reach RCE, with the measurements made on
the local laboratories.

## PHP 8.3.33 / 8.3.35 — leaks work, stage 3 blocked

- Stage 1 (heap leak) and stage 2 (libphp leak) reproduce.
- After the stage-3 "A" request, `PS(http_session_vars)` sits at `chunk+0x56180`
  (bookworm pads) or `chunk+0x56440` (lab pads).
- 55-byte reference buffers land at `chunk+0x5d068 + n*0xa0`; 32-byte buffers
  walk upward from `chunk+0x571d8`. None lands on `PS(http_session_vars)`.
- Varying the pad value size (7..511) moves R0 only between 0x56180 and 0x56300.
- Adding pre-OOM fields moves R0 by 128 bytes per field up to K=24
  (`0x56d80`), then jumps to `0x75080` at K=30. The ref landing at `0x5d068`
  is skipped.
- The reference at R0 is **alive**, not dangling. Dump after A on 8.3.35:

  ```text
  R0+0x00  02000000 1a000000   refcount=2, type=0x1a (IS_REFERENCE|flags)
  R0+0x08  e087c584 ffff0000   val.value = chunk+0x587e0
  R0+0x10  07030000 00000000   val.type  = 0x307 (IS_ARRAY)
  ```

  `zval_ptr_dtor(PS(http_session_vars))` therefore decrements 2 -> 1 instead of
  destroying the reference; the 8.4/8.5 carrier assumes it can overwrite or
  destroy it. This is the concrete reason stage 3 does not fire on 8.3.
- Conclusion: the fake reference is not being placed, and the live reference
  cannot be overwritten by heap reuse. The next step is to instrument the
  reference/array lifetime (ASAN or watchpoint) or to target the `val.value`
  array at `chunk+0x587e0` instead of R0.

## PHP 8.2.34 — UAF exists, leak shape does not

- After the stage-1 "A" request, the worker still has a non-NULL `PS(id)`
  (`0xffff984a7000`), so the stale pointer exists.
- B requests with values of 16, 24, 32, 40, 48, 56, 64, 80, 96, 112 and 128
  bytes never reclaim it: at 56/64/80 the response carries a new 32-character
  session id; at the other sizes no cookie is emitted.
- The 8.4/8.5 leak shape does not transfer. The next step is to instrument the
  B session lifecycle (`php_session_rfc1867_cleanup` / `reset_id`) to see
  whether `PS(id)` is cleared before the cookie is built.

## PHP 7.4.33 / 8.0.30 / 8.1.34 — UAF exists, leak shape does not

- After the stage-1 "A" request, the worker keeps a non-NULL `PS(id)`:

  ```text
  7.4.33  0xffff80aa9000
  8.0.30  0xffffb36a9000
  8.1.34  0xffff8f8a8000
  ```

- B requests with values of 16, 24, 32, 40, 48, 56, 64, 80, 96, 112 and 128
  bytes never reclaim it: at 56/64/80/112/128 the response carries a new
  32-character session id; at the other sizes no cookie is emitted.
- The same failure as 8.2: the `Set-Cookie` leak shape that works on 8.3+ does
  not transfer to the EOL branches. The pre-RINIT UAF exists, but the cleanup
  path builds a new id instead of reusing `PS(id)`.

- `zif_system` / `zval_ptr_dtor` extracted; no heap calibration yet.
- These EOL branches need the same first diagnostic as 8.2: confirm whether the
  pre-RINIT OOM leaves `PS(id)` dangling and whether a controlled buffer can
  reclaim it.

## Working branches

- PHP 8.4.26: RCE verified (`uid=33`), at 8M and 128M.
- PHP 8.5.11: RCE verified (`uid=33`), after applying the profile's
  `forge_len=63` and widening the pointer filters for `0xffff...` addresses.
