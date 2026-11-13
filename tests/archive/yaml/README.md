# Historical YAML configuration evidence

These are the M2 YAML decoder and full mihomo-loader comparison fixtures. They
are excluded from CMake, CI gates, fuzz corpora, installation and the native
Solaris Conf compiler. The 176-case record describes the historical scope only.

To reproduce the old configuration comparison, use an isolated checkout of
`7a05406128254ed31e6a53fc814c2acfe74188e9` and its own build instructions. This
folder preserves the reference sources, test inputs, Go locks, checked overlays
and original dependency metadata; it is not a maintained import adapter.
The obsolete C YAML parser and libyaml build shim are available in Git history.

Current contracts are in `tests/contracts/config/`, `tests/support/config/`
and `tests/fuzz/config-seeds/`, and use Solaris Conf v1 exclusively.
