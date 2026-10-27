# gdb instrumentation

A sidecar with `gdb` and `SYS_PTRACE` attaches to the lab's Apache worker. No
debugger runs inside the target image.

```sh
docker run -d --name p2s-gdb --pid=container:p2s-lab-8335 \
  --cap-add=SYS_PTRACE debian:bookworm-slim sleep infinity
docker exec p2s-gdb sh -c 'apt-get update -qq && apt-get install -y -qq gdb'

# gdb must resolve target paths locally:
docker cp p2s-lab-8335:/usr/lib/apache2/modules/libphp.so /tmp/libphp.so
cat /tmp/libphp.so | docker exec -i p2s-gdb sh -c 'mkdir -p /usr/lib/apache2/modules && cat > /usr/lib/apache2/modules/libphp.so'
docker cp p2s-lab-8335:/usr/sbin/apache2 /tmp/apache2
cat /tmp/apache2 | docker exec -i p2s-gdb sh -c 'cat > /usr/sbin/apache2 && chmod 755 /usr/sbin/apache2'
```

The key gdb setting is `set sysroot /`; without it gdb tries
`target:/usr/lib/...` and gets `Operation not permitted`.

## Trace on 8.3.35

Breakpoints on `php_session_track_init`, `zend_mm_safe_error` and
`zend_out_of_memory`; send the stage-3 "A" request:

```text
TRACK_INIT
#0  php_session_track_init
#1  php_session_initialize
#2  php_session_rfc1867_update
#3  php_session_rfc1867_callback

MM_SAFE_ERROR
#0  zend_mm_safe_error
#1  zend_mm_alloc_huge
#2  zend_mm_realloc_slow
#3  rfc1867_post_handler
#4  sapi_handle_post
#5  php_default_treat_data
#6  php_auto_globals_create_post
#7  zend_activate_auto_globals
#8  php_hash_environment
#9  php_request_startup
```

The session reference/array are fully built by `php_session_track_init`, and
the OOM happens later in the POST parser (`rfc1867_post_handler`). The bailout
therefore skips cleanup of *fully initialised* state; it does not leave a
half-built or freed reference. This matches the memory dump (`refcount=2`,
`val.type=IS_ARRAY`).

Trying to move the OOM into session serialization with a large
`PHP_SESSION_UPLOAD_PROGRESS` key also ends in `rfc1867_post_handler`: the
parser buffers the key before the session update can serialise it.

## Implication

For 8.3, the stage-3 technique from 8.4/8.5 cannot work with these triggers: the
reference is alive and fully initialised. The next experiment would have to make
`php_session_initialize` itself fail (e.g., a persisted session file read with
`session.upload_progress.cleanup=Off`), or target the live array instead of R0.
