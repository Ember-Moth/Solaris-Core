# 2026-11-03 文档归档

本次将原实现文档与本轮讨论形成的草案合并归档，当前有效文档见 [开发文档索引](../../README.md)。

## 文档清单

| 原路径 | 归档文件 | 性质 |
| --- | --- | --- |
| `README.md` | [PROJECT_README.md](PROJECT_README.md) | 原实现的项目与构建说明 |
| `docs/EMBEDDING.md` | [EMBEDDING.md](EMBEDDING.md) | 原 schema/ABI 的宿主调用说明 |
| `docs/MIHOMO_LIBRARY_DESIGN.md` | [MIHOMO_LIBRARY_DESIGN.md](MIHOMO_LIBRARY_DESIGN.md) | 总体设计讨论草案 |
| `docs/FRAMEWORK_ARCHITECTURE.md` | [FRAMEWORK_ARCHITECTURE.md](FRAMEWORK_ARCHITECTURE.md) | 框架扩展契约草案 |
| `docs/UDP_NAT_DESIGN.md` | [UDP_NAT_DESIGN.md](UDP_NAT_DESIGN.md) | mihomo/原实现核对与 UDP 方案 |
| `docs/RUNTIME_CONCURRENCY_DESIGN.md` | [RUNTIME_CONCURRENCY_DESIGN.md](RUNTIME_CONCURRENCY_DESIGN.md) | libuv、多 worker 与栈边界方案 |

正文保留归档时状态，仅增加归档提示并调整 Markdown 链接。指向原代码的链接已固定到检查基线 `f9ca89ac3cf13808463beac9b4130d6639ffb1c7`，避免之后的源码重建改变参考内容。

原 README 中的 `../docs/PROJECT_STATUS.md` 在归档前已经不存在，已在原文位置标明，不补造历史文件。

## 调查证据

- [UDP 探针源码](evidence/udp_nat_probe.c)：针对原实现的本地测试工具，使用原项目类型名，不属于新 SDK。
- [UDP 探针结果](evidence/udp_nat_probe.json)：同源 A/B/A 目标、回复端口、空包和 IPv6 的本地观察。
- [归档清单与 SHA-256](manifest.json)：记录原路径、原内容 hash、归档 hash 和链接调整。

探针使用 macOS arm64 上原构建的静态库，并显式补链 libuv；未使用真实系统 VPN，也不是公网 NAT 或多核性能测试。源码及 JSON 按字节保存，未归档编译产物。
