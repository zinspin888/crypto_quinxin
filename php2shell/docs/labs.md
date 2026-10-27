# Local laboratories

`tools/php2shell_labs.py` starts one disposable container per build, using the
official images, a single prefork worker, `display_errors=On`,
`memory_limit=8M`, `post_max_size=64M` and a per-lab `/out` mount.

```sh
python3 tools/php2shell_labs.py up
python3 tools/php2shell_labs.py status
python3 tools/php2shell_labs.py test
python3 tools/php2shell_labs.py down
```

| Version | Image | URL | Profile | Test result |
| --- | --- | --- | --- | --- |
| 7.4.33 | `php:7.4-apache` | http://127.0.0.1:8100/ | offsets only | no RCE |
| 8.0.30 | `php:8.0-apache` | http://127.0.0.1:8101/ | offsets only | no RCE |
| 8.1.34 | `php:8.1-apache` | http://127.0.0.1:8102/ | offsets only | no RCE |
| 8.2.34 | `php:8.2.34-apache` | http://127.0.0.1:8103/ | calibration failed | no RCE |
| 8.3.35 | `php:8.3.35-apache` | http://127.0.0.1:8104/ | leaks only | no RCE |
| 8.4.26 | `php:8.4.26-apache` | http://127.0.0.1:8105/ | RCE verified | **uid=33(www-data)** |
| 8.5.11 | `php:8.5.11-apache` | http://127.0.0.1:8106/ | RCE verified | **uid=33(www-data)** |

The 8.4.26 image is amd64-only and runs under emulation on Apple Silicon; the
others use the native arm64 image. `test` runs
`tools/php2shell_auto.py --memory-limit-mb 8` against each lab and writes the
proof to `lab/rce/out/<version>/p1`.

Builds without a verified RCE profile are refused by the dispatcher; they do
not send the chain. Extending coverage means calibrating that build with
`tools/php2shell_calibrate.py` and committing the resulting profile.
