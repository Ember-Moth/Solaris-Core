# Solaris Core 开发文档

基线日期：2026-11-03，最近更新：2026-11-06。M1 与 M2 的实现及本机功能验收已完成。完整配置差分、14 组 M2 验收的证据和非阻塞已知问题见 [M2 验收矩阵](development/DEVELOPMENT_PLAN.md#511-完整配置差分与-m2-07-验收矩阵)。

## 阅读顺序与职责

| 顺序 | 文档 | 负责定义 |
| --- | --- | --- |
| 1 | [架构与模块契约](development/ARCHITECTURE.md) | 项目目标、命名、目录、模块边界与扩展方式 |
| 2 | [配置与宿主 SDK](development/CONFIGURATION_AND_SDK.md) | 配置语义、宿主 API、平台边界和事务式更新 |
| 3 | [运行时与多核](development/RUNTIME.md) | executor、worker、对象所有权、跨线程通信 |
| 4 | [UDP 与 NAT](development/UDP_NAT.md) | UDP 关联身份、映射、固定选路和回复路径 |
| 5 | [测试与验收](development/TESTING.md) | 各类验收条件、参考实现与证据要求 |
| 6 | [开发计划](development/DEVELOPMENT_PLAN.md) | 任务顺序、依赖、完成状态和下一批工作 |

实施配套：[M0 工程决策](development/M0_DECISIONS.md)、[已实现 SDK 用法](development/SDK.md)、[配置/协议/平台兼容矩阵](development/COMPATIBILITY.md)。目标规范不等于当前已支持能力。

当前实现说明：[M1 模块工厂、UDP association 与统一 I/O](development/M1_DATA_PATH.md)。
代理入站：[HTTP/SOCKS5/mixed、认证与 TCP/UDP 生命周期](development/PROXY_INBOUND.md)。

TUN 接入：[lwIP/system、宿主 packet I/O 与平台设备层](development/TUN.md)。
TLS 依赖和协议扩展：[BoringSSL 固定基线、补丁与认证边界](development/TLS_BACKEND.md)。

## 文档使用规则

这些文件共同构成当前开发依据；每项事实在表中指定的责任文档中维护，其他文件引用它。实现状态只在开发计划中登记，技术规范里的目标不表示该功能已经实现。

更改会话语义、线程所有权、公共模块契约或配置行为时，先同步对应规范和验收条件，再提交实现。跨文档存在冲突时应消除冲突，不能任选一条执行。

当前要求：

1. 全新开发；不保留原项目的命名兼容壳、私有配置转换层或 ABI 桥接。
2. mihomo YAML 是公开配置目标；libclash 作为嵌入功能参考，不复刻其二进制接口。
3. 模块化扩展和至少两 worker 的正确性属于早期框架验收。
4. 源码检查、本地探针、协议互通、真实设备和性能测试是不同级别的证据。
5. 未确定的实现选型必须在开发计划中安排决策任务；不以“后续再优化”掩盖影响架构的缺口。
6. 源码与测试按组件职责组合到子目录；共享能力从协议目录抽出，目录与引用规则见 [架构规范](development/ARCHITECTURE.md#7-目录与对象生命周期)。

## 历史归档

[归档索引](archive/README.md) 保存原实现文档、讨论草案及调查证据。其旧路径、API、构建命令和阶段描述均只代表归档时状态，不能覆盖本目录的开发规范。
