# Third-Party Notices

## BLAKE3 C implementation

`third_party/blake3/` vendors the official BLAKE3 C implementation, its
x86-64 SIMD assembly, x86 SIMD intrinsics, and ARM NEON backend from upstream commit
`8aa5145039b972ba30e98e788752d37d14568824`:

https://github.com/BLAKE3-team/BLAKE3

License: Apache-2.0 OR CC0-1.0

The upstream license texts are kept in:

- `third_party/blake3/LICENSE_A2`
- `third_party/blake3/LICENSE_CC0`

## Linked libraries

The SDK links to libuv (MIT). Enabling the TLS module also links BoringSSL
(ISC-style and other permissive licenses). Source revisions and archive
checksums are fixed in `dependencies/lock.json`; their license files are
installed with the SDK. BoringSSL is statically linked with a private symbol
prefix, including a build-time rename of its SSL_SESSION struct tag to cover
an upstream prefix-table omission. BoringSSL is pinned to snapshot tag
`0.20261020.0`, exact commit `d3bf4795ad5b79d646cddf2fec687da5b9b502db`.
The ordered, checksum-verified Solaris patches live in
`third_party/boringssl/patches/`; they preserve the upstream license and expose
private, opt-in TLS seams. Protocol authentication is not enabled by ordinary TLS.
The Shadowsocks and VLESS encryption modules also link the portable BLAKE3 C backend as a private,
prefixed static library; SIMD source files remain vendored but are not compiled.

The prior implementation also used BoringSSL (ISC-style and other permissive
licenses), lwIP (BSD-3-Clause), PCRE2 (BSD-3-Clause), nghttp2 (MIT), and llhttp
(MIT). These sources remain attributable through implementation baseline
`f9ca89ac3cf13808463beac9b4130d6639ffb1c7`; future modules must carry forward
the applicable notices when reusing them. Additional parser selections for
subsequent stages are recorded in the dependency lock.

## hev-socks5-tunnel

Parts of the prior Linux TUN device setup (`src/inbound/tun.c` at baseline
`f9ca89ac3cf13808463beac9b4130d6639ffb1c7`) were adapted from
`heiher/hev-socks5-tunnel`:

https://github.com/heiher/hev-socks5-tunnel

License: MIT

Copyright (c) 2022 hev

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Independent TLS protocol test peers

`tests/support/transport/tls_profiles_peer/` pins MetaCubeX jls-tls and
restls-client-go, SagerNet sing-shadowtls, and XTLS REALITY as independent
loopback test servers. Their exact module versions and checksums are in
`go.mod`, `go.sum`, and `dependencies/lock.json`. These Go libraries and test
binaries are not linked into or installed with the Solaris SDK. The native
protocol test clients consume BoringSSL and the already attributed BLAKE3
implementation; protocol references are listed in `docs/development/TLS_BACKEND.md`.

## lwIP TCP stack and platform reference

Enabling `SOLARIS_ENABLE_TUN_LWIP` links lwIP 2.2.1, commit
`77dcd25a72509eb83f72b033d219b1d40cd8eb95`, under its BSD-3-Clause license.
The archive checksum is locked in `dependencies/lock.json`. Solaris compiles
selected raw TCP/IP sources with private symbols and a custom allocator;
the upstream `COPYING` file is installed in `share/Solaris/licenses/lwip/`.

https://github.com/lwip-tcpip/lwip

SagerNet sing-tun v0.9.6, commit
`ddaa4ca25e3bcb776d6ce81f4477b3becb5426de`, was consulted as the system TCP NAT,
Apple TUN and Wintun behavior reference. Its source is GPL-3.0-or-later;
it is not linked into or distributed with the Solaris SDK.

https://github.com/SagerNet/sing-tun

## llhttp HTTP parser

Enabling `SOLARIS_ENABLE_PROXY_INBOUND` links llhttp 9.4.3, commit
`0e815792b167a9bd8ace259b95b7da953776c288`, under its MIT license.
The archive checksum is locked in `dependencies/lock.json`. All generated C
identifiers are privately prefixed; upstream sources are fetched without edits.
The upstream `LICENSE-MIT` is installed in `share/Solaris/licenses/llhttp/`.
The build verifies the pinned header hash and removes its unconditional Windows
`dllexport` annotation from a private build copy, so parser symbols do not enter
the Solaris DLL ABI. Parser behavior and the downloaded upstream sources are unchanged.

https://github.com/nodejs/llhttp

## libyaml YAML parser

The offline configuration compiler links libyaml 0.2.5, commit
`2c891fc7a770e8ba2fec34fc6b545c672beb37e6`, under its MIT license.
The archive checksum is locked in `dependencies/lock.json`. Solaris uses
private symbol prefixes and a per-compilation bounded allocator through
forced include headers; upstream sources are fetched without edits.
The upstream `License` is installed in `share/Solaris/licenses/libyaml/`.

https://github.com/yaml/libyaml

The independent decoder fixtures in `tests/support/config/reference/` pin
`go.yaml.in/yaml/v3 v3.0.5`, the YAML dependency of the fixed mihomo reference.
Its upstream source uses MIT and Apache licenses; the module checksums remain
in `go.sum`. This helper is test-only and is not linked into or installed with
the Solaris SDK.

The full configuration oracle in `tests/support/config/reference/full/` uses
the GPLv3-licensed fixed mihomo revision recorded in `dependencies/lock.json`.
Its module checksums and original source hashes are verified before making a
private build copy. Test bridges expose existing address/metadata/rule helpers
and observe the effective AnyTLS timer argument without changing loader or
matching behavior. The build emits hashes for these bridges and the resulting
observation overlay. This reference executable is not linked into or installed
with the Solaris SDK.
