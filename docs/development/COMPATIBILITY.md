# 配置、协议与平台兼容矩阵

日期：2026-11-06。固定参考见 [依赖与参考 lock](../../dependencies/lock.json)。状态只反映当前实现，目标阶段不表示已经可用。

| 能力 | 当前状态 | 任务/验收 |
| --- | --- | --- |
| Solaris C 生命周期、操作事件、状态 snapshot、flush/destroy | 已实现；macOS arm64 本机验证 | M0-03 / G-LIFE |
| 共享/静态安装包与 `Solaris::core` | 已实现；macOS arm64 独立 C/C++ 消费验证 | M0-04 / G-BUILD |
| 多个 engine 内 I/O workers | 已实现 1–32 配置，双 worker 本机验证 | M1-01 / G-WORKER |
| stream/datagram、buffer/scope、Direct/Block | 内部接口已实现，双栈受控对端验证 | M1-02/M1-04 / G-LIFE |
| 模块 registry/配置工厂 | 内部接口已实现；别名/依赖检查、类型化配置、双 worker 工厂、静态裁剪本机验证；无 YAML 入口 | M1-03 / G-MODULE 子项 |
| 单 datagram 多目的复用、空包/真实 source | Direct socket 路径已验证 | M1-02/M1-04 / G-UDP 子项 |
| UDP association、目的映射/reply endpoint 服务 | 已实现；命名空间隔离、固定 worker/plan、双栈/域名、deadline/关闭本机验证；映射模式可查询 | M1-05 / G-UDP 基础子集 |
| DNAT/Fake-IP 回复恢复、公网 NAT/设备行为 | 尚未实现/验证，不从本地端口复用推导 | M3 / G-UDP/G-DEVICE |
| 中立 TLS、裸 VLESS TCP/plain 或 TLS | 内部配置工厂已接入；固定 sing-box v1.12.12 双 worker/双栈/域名互通；显式 CA 与 identity 校验；encryption/flow 组合分别见下表，尚无 YAML 入口 | M1-06a/b / G-INTEROP 子项 |
| VLESS encryption | 已接入 `mlkem768x25519plus`，native/xorpub/random、1-RTT/0-RTT、X25519/ML-KEM 密钥及 relay 链；固定 Xray 的 TCP/XUDP/association 与独立 crypto fixture 本机通过 | M1-06c / G-INTEROP |
| VLESS `xtls-rprx-vision` | 已接入 padding、内层 TLS 1.3 识别和双向 raw 切换；固定 Xray 的 TLS 1.3、三种 encryption 外观及 encryption-over-TLS 组合通过；基础 flow 拒绝 UDP 443，后缀 `-udp443` 放行 | M1-06d / G-INTEROP |
| VLESS XUDP | Single XUDP 已接入 plain/TLS、共享 datagram backend 与 association；固定 sing-box/Xray 和独立线格式对端已验证；无跨连接 global-ID 恢复 | M1-06e / G-UDP U06/G-INTEROP |
| SS AEAD/2022 TCP/native UDP | 三种 AEAD 与两种 2022 AES 方法已接入；固定独立对端、重放/鉴权边界本机验证；无插件/2022 EIH | M1-06f / G-INTEROP 子项 |
| SS UoT | 已接入：`udp-over-tcp: true` 使用共享 UoT v2；五种 cipher、双 worker、双栈/域名与关闭本机互通；无 v1/connect 模式 | M1-06g / G-UDP U06/G-INTEROP |
| AnyTLS/session/UoT | AnyTLS v2 已接入 TLS、padding 更新、session 复用与共享 UoT；本机双 worker/双栈/域名互通；不支持半关闭或 v1 peer | M1-06g/h / G-INTEROP |
| SOCKS5 outbound 扩展试验 | 已实现 CONNECT/UDP ASSOCIATE、无认证或用户名密码、双栈/domain、控制连接生命周期、select/测速/观测；无 BIND、UDP 分片或 TLS 配置入口 | M1-08 / G-MODULE/G-INTEROP |
| mihomo YAML：公共语法/proxies/rules/mode/select | 不支持；尚无公开配置 API | M2-01–M2-03 / G-CONFIG |
| SOCKS5/HTTP/mixed 入站与控制 SDK | 尚未实现 | M2-04–M2-05 |
| prepare/commit/retire 配置事务 | 尚未实现 | M2-06 / G-RELOAD |
| 最小系统域名解析 | TCP 与 UDP association 使用 getaddrinfo；底层 Direct UDP send 仍只接收数值地址 | M1-04/M1-05 |
| DNS policy/DoH/DoT/Fake-IP、双栈 TUN | 尚未实现 | M3-01–M3-04 / G-UDP |
| Android/Apple 系统 VPN 与薄绑定 | 尚未实现/真机未验证 | M3-05–M3-06 / G-DEVICE |
| Provider、健康策略、Geo/RULE-SET、持久化 | 尚未实现 | M4 / G-CONFIG/G-RELOAD |
| 内部 select/固定 plan | 共享选择修订、worker 实例、存量 plan 固定；健康状态独立；无 YAML/公开业务 SDK 入口 | M1-07 / G-WORKER |
| 连接追踪与流量 | 单 flow/association 记录、有限关闭历史、跨线程关闭；USER/PROBE 分桶与物理 socket payload 计数 | M1-07 / G-LIFE |
| HTTP(S) 单次测速 | 固定 plan 的 HEAD 请求，完整响应头与写入完成才成功；显式 HTTPS 信任、整体 deadline、取消和迟到结果处理 | M1-07 / G-INTEROP |
| REALITY/ShadowTLS/Restls/JLS/ECH/XHTTP/指纹等额外组合 | 生产出站/配置尚未接入；[五个 TLS 库补丁](TLS_BACKEND.md) 已实现，四种认证握手经独立对端验证；Vision 已在 M1-06d 验证 | M2-03/M5-02 / G-INTEROP |
| Windows/Linux/OpenHarmony | M0 Windows/Linux CI 已通过；M1 远端 CI 尚未验收，平台接入未实现 | M0-05/M5-03 / G-BUILD/G-DEVICE |
| QUIC/Hysteria2/TUIC/DoQ/HTTP3 | 尚未实现 | M6-01 / G-INTEROP |
| 多核吞吐、尾延迟、能耗改善 | 未测量 | M6-03–M6-04 / G-PERF |

当前实现不接受或模拟原 schema，也不提供 mihomo HTTP 控制器。原协议代码/探针保存在 Git 历史和文档归档中，其通过记录不计为新实现的支持状态。

有意的配置行为差异（库模式不执行 external-controller、明确的 UDP idle timeout 与 NAT capability 等）目前是设计决策，必须在对应实现阶段补样本和差分记录后才可标为已实现。
