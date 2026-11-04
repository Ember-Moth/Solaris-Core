# 配置、协议与平台兼容矩阵

日期：2026-11-03。固定参考见 [依赖与参考 lock](../../dependencies/lock.json)。状态只反映当前实现，目标阶段不表示已经可用。

| 能力 | 当前状态 | 任务/验收 |
| --- | --- | --- |
| Solaris C 生命周期、操作事件、状态 snapshot、flush/destroy | 已实现；macOS arm64 本机验证 | M0-03 / G-LIFE |
| 共享/静态安装包与 `Solaris::core` | 已实现；macOS arm64 独立 C/C++ 消费验证 | M0-04 / G-BUILD |
| 两个以上 engine 内 I/O workers | 不支持，返回 ENOTSUP | M1-01 / G-WORKER |
| stream/datagram、Direct/Block、模块 registry | 尚未实现 | M1-02–M1-04 / G-MODULE |
| UDP association/NAT、多目的复用、reply endpoint | 尚未实现 | M1-05 / G-UDP |
| SS AEAD/2022、AnyTLS、VLESS 基础协议 | 尚未接入新框架 | M1-06 / G-INTEROP |
| SOCKS5 outbound 扩展试验 | 尚未实现 | M1-08 / G-MODULE/G-INTEROP |
| mihomo YAML：公共语法/proxies/rules/mode/select | 不支持；尚无公开配置 API | M2-01–M2-03 / G-CONFIG |
| SOCKS5/HTTP/mixed 入站与控制 SDK | 尚未实现 | M2-04–M2-05 |
| prepare/commit/retire 配置事务 | 尚未实现 | M2-06 / G-RELOAD |
| DNS/DoH/DoT/Fake-IP、双栈 TUN | 尚未实现 | M3-01–M3-04 / G-UDP |
| Android/Apple 系统 VPN 与薄绑定 | 尚未实现/真机未验证 | M3-05–M3-06 / G-DEVICE |
| Provider、健康策略、Geo/RULE-SET、持久化 | 尚未实现 | M4 / G-CONFIG/G-RELOAD |
| REALITY/Vision/ECH/XHTTP/指纹等具体组合 | 新框架未验证，不从历史实现推导支持 | M2-03/M5-02 / G-INTEROP |
| Windows/Linux/OpenHarmony | 已配置 CI 构建目标，但当前未运行；平台接入未实现 | M0-05/M5-03 / G-BUILD/G-DEVICE |
| QUIC/Hysteria2/TUIC/DoQ/HTTP3 | 尚未实现 | M6-01 / G-INTEROP |
| 多核吞吐、尾延迟、能耗改善 | 未测量 | M6-03–M6-04 / G-PERF |

M0 不接受或模拟原 schema，也不提供 mihomo HTTP 控制器。原协议代码/探针保存在 Git 历史和文档归档中，其通过记录不计为新实现的支持状态。

有意的配置行为差异（库模式不执行 external-controller、明确的 UDP idle timeout 与 NAT capability 等）目前是设计决策，必须在对应实现阶段补样本和差分记录后才可标为已实现。
