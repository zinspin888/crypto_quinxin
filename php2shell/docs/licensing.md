# Licensing

## This repository

The original code, profiles, laboratories, tests and documentation in this
repository are released under the MIT license (see [LICENSE](../LICENSE)).

## The upstream exploit

The chain is based on the public research by **9bie**:

- <https://github.com/9bie/php2shell-bypass-aslr-exp>

That repository has no explicit license file. For that reason:

- its source is **not vendored** here;
- no patch file containing its code is redistributed;
- `tools/bootstrap_upstream.py` only clones the pinned commit;
- `tools/php2shell_upstream.py` applies the documented runtime changes in place
  (see [upstream-changes.md](upstream-changes.md)).

The upstream's own terms apply to that checkout. If you need a clear license for
it, contact its author.

## CVE and third-party material

CVE identifiers and the referenced public analyses belong to their respective
authors. The credits are in the README.

## Authorization

The MIT license grants copyright permissions only. It does **not** authorize
testing any system. See [ACCEPTABLE_USE.md](../ACCEPTABLE_USE.md).
