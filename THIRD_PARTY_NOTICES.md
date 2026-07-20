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

The project links to libuv (MIT), BoringSSL (ISC-style and other permissive
licenses), lwIP (BSD-3-Clause), PCRE2 (BSD-3-Clause), nghttp2 (MIT), and llhttp
(MIT). Host builds may use libraries supplied by the build environment; mobile
build scripts fetch pinned source revisions into ignored build directories.
These libraries are not vendored in this repository.

## hev-socks5-tunnel

Parts of the Linux TUN device setup in `src/inbound/tun.c` are adapted from
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
