# Full configuration reference

`config_full_differential_contract` compares Solaris's owned configuration image
with the original `UnmarshalRawConfig` and `ParseRawConfig` from the exact mihomo
fork revision in `overlay/manifest.json`. The older `config_differential_contract`
continues to check the independent raw YAML decoder fixtures.

Build with CMake and run:

```sh
cmake --build build --target solaris_config_dump_tests solaris_full_config_reference
ctest --test-dir build -R '^config_full_differential_contract$' --output-on-failure
```

The report is `build/config-full-differential.json`. It contains each synthetic
fixture, both actual results, pre-projection representation details, intentional
differences with reasons, the reference provenance, and whether the OS network
sandbox was active. These are offline configuration and matcher checks, not
listener, peer interoperability, operating-system, or performance evidence.

`build.py` verifies the exact module version, module checksum, go.mod checksum,
available origin revision, all cached module contents with `go mod verify`, and
the pinned source-file hashes. Go prohibits overlays inside its module cache, so
the verified source is copied to the build directory and selected using a private
modfile. The source repository and module cache remain unchanged.

The observation overlay adds only four bridges:

- The real listener `genAddr`/`portIsZero` helpers produce addresses and disabled
  states without opening a socket.
- The real ordered `tunnel.match` receives the loaded rules/proxies and controlled
  metadata/DNS answers. The in-memory update functions do not apply configuration.
- The real SOCKS/CONNECT metadata decoder handles the encoded destination before
  matching, including reference FQDN trimming. Both input and effective hosts are
  retained; this is a codec/matcher check without a network listener.
- The AnyTLS routine wrapper records the effective duration passed to the original
  `StartRoutine`; normalization and scheduling stay unchanged. Read-only reflection
  also observes the actual session timeout and pool minimum.

The helper passes the original decoded object unchanged to the full loader. Its
resource guard refuses providers, Geo/RULE-SET resources, external certificates,
plugins, active groups, DNS, NTP, TUN, and other unreviewed fields. It uses an empty
temporary home and rejects unexpected created files. It never calls `ApplyConfig`,
listener `Listen`, proxy dial methods, provider initialization, or health checks.
On macOS both reference and Solaris processes run with `deny network*`; other OSes
use the same input guard and record the absence of this OS sandbox in the report.

Projection normalizes public protocol aliases, UUID byte spelling, wildcard
listener spelling, masked CIDR networks, and the effective non-resolving nature
of source CIDR. It retains original representations and lists these rules.
Behavioral differences are checked individually: strict input validation, the
documented M2 protocol subset, flat/generated groups, explicit UDP gates, numeric
IPv6 binding, Vision suffix preservation, and established ASCII domain
normalization. A new or disappearing difference fails the test.
