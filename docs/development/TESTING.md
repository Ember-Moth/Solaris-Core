# 测试与验收规范

状态：独立内核验收定义，2026-11-13 按 Solaris Conf 方向调整；不表示新测试已经运行。各阶段状态只在 [开发计划](DEVELOPMENT_PLAN.md) 维护。
迁移期间现有 YAML/参考测试的注册保持原状，CFG-04 在原生替代覆盖完成后调整默认门禁；本次仅修改规范。

## 1. 证据分类

| 证据 | 可以说明 | 不能代替 |
| --- | --- | --- |
| 源码检查 | 入口、调用关系、明确的限制与待验证推断 | 运行行为、吞吐、真机结果 |
| 单元/契约测试 | 模块契约、边界、状态机和失败处理 | 独立协议互通 |
| 本地受控集成 | 数据路径、异步交互、地址与队列行为 | 系统 VPN、真实网络变化 |
| 原生规范样本 | Solaris Conf 的词法、字段语义和统一模型 | 协议互通、平台行为或未实现功能 |
| 第三方对照 | 指定版本与样本下的行为差异及设计参考 | Solaris 原生行为的唯一标准、完整第三方配置兼容 |
| 独立实现互通 | 指定协议组合在对端上的实际通信 | 所有平台上的 VPN 行为 |
| 真机测试 | 对应设备、OS、签名与宿主环境下的结果 | 其他平台或发布包自动成立 |
| 性能测量 | 指定条件下的吞吐、延迟、CPU、内存和能耗 | 未测场景的性能承诺 |

归档的原实现 smoke/UDP 探针只属于历史证据，不计入新工程完成度。

## 2. 公共验收门槛

| ID | 验收门槛 | 关键证据 |
| --- | --- | --- |
| G-BUILD | 可构建与消费 | 仅安装产物和公开头文件的独立 C 消费者；正常依赖链接；自有导出/命名检查 |
| G-MODULE | 模块边界成立 | SOCKS5 新出站仅改模块、清单、测试/文档；通用层无协议特判 |
| G-LIFE | 生命周期/所有权 | 接受恰好一次完成、取消、关闭屏障、失败清理、buffer 引用与旧代退休 |
| G-WORKER | 多 owner 正确性 | 至少两个 I/O workers；同一对象固定 owner；跨线程消息有界且无丢唤醒 |
| G-CONFIG | 原生配置行为 | Conf v1 规范样本、字段/单位/默认值、源位置、引用/能力与实际路由；文件入口与内部类型模型一致 |
| G-UDP | UDP/NAT 行为 | association、端口复用、真实源地址、DNAT、空包、双栈、超时和封装 |
| G-RELOAD | 更新一致性 | 候选失败保留现状，提交影响新对象，旧引用安全退休，Provider 独立更新 |
| G-INTEROP | 协议互通 | 每项声明支持的组合有独立对端、TCP/UDP 与错误路径证据 |
| G-DEVICE | 平台行为 | 宿主 TUN/protect/packet callback、网络变化、停止清理、平台限制 |
| G-PERF | 性能证据 | 同条件 1/2/4 workers 与普通/批量路径对照，不以构建或单个计数代替测量 |

某阶段只通过门槛的子集时，报告具体测试 ID 与覆盖范围；不能将整个门槛标为全功能通过。

## 3. 运行时与 adapter 契约

所有 adapter 复用同一契约套件，覆盖：

- open 成功、拒绝、异步失败、超时、取消与迟到完成，避免重复回调和资源悬挂。
- stream 的有序写入、暂停/恢复、writable 通知、半关闭、整体关闭与缓冲释放。
- datagram 原子消息、零长度 payload、长度限制、批量 accepted 前缀与队列满行为。
- 重复 close、stop 中 DNS/protect/握手完成、对象引用归零和旧 generation 退休。
- 所选成员和实际 open 的 plan 一致，组/Provider 更新不让已有对象悄悄换出站。
- session 共享、部分子流结束、底层连接失败传播、预算耗尽和引擎停止。
- 至少两 worker 下，连接/association/session 不被并发操作；所有完成回到正确 owner。

使用可控时钟、注入失败、mock dialer 和受控对端确定重现步骤。并发检测与断言在适用平台启用；不能仅靠一次压力测试未崩溃认定线程安全。

## 4. UDP 必需样本

| 测试 ID | 场景与期望 | 最早完整覆盖阶段 |
| --- | --- | --- |
| U01 | 同源 A/B/A：同族 Direct 复用本地端口，各目的收发正确 | M1 |
| U02 | 不同 engine/inbound 相同源地址：表、回复和策略完全隔离 | M1 |
| U03 | 首次建关联多包并发：只 open 一次，队列受限，完成一次 | M1 |
| U04 | association 固定 worker；目标改变不漂移，N 改变不直接重哈希存量 | M1 |
| U05 | 首包 Direct/次包本应 Proxy 及反向顺序：遵循首次选路固定 | M2 |
| U06 | native UDP、SS/AnyTLS UoT、VLESS XUDP：同一 association/公共层不增加封装特判 | M1 内部全部路径；M2 YAML/入站接入 |
| U07 | Fake-IP、hosts、多域名同 IP/端口：租约稳定、歧义隔离、正确恢复 | M3 |
| U08 | 备用远端 IP/端口回复：真实 peer 保留，映射与过滤分别检查 | M1，平台验证在 M3 |
| U09 | 空 payload、IPv4/IPv6 校验和、MTU、超长/分片策略 | datagram 在 M1，TUN codec 在 M3 |
| U10 | idle/open/DNS deadline、生效配置、队列满与迟到回调 | 基础 M1，配置与 DNS M2/M3 |
| U11 | SOCKS5 控制连接结束、宿主回复通道替换、网络绑定失效 | outbound 控制连接 M1；入站 M2，TUN M3 |
| U12 | 批量与普通路径：目的、顺序、统计、accepted 与内存回收一致 | M1/M3 |

公网 STUN/ICE 观察是额外测试，需记录服务器、网络与代理端条件；本地 socket 复用不能被写成公网 NAT 类型保证。

## 5. 原生配置与辅助对照

Solaris Conf v1 的预期由 [原生配置规范](CONFIGURATION_AND_SDK.md) 定义，覆盖：

- UTF-8/BOM、LF/CRLF、段/键、版本、引号/转义、逗号/等号、注释及完整输入消费；错误精确定位且不泄漏凭据。
- 必需/缺省/空值/显式零、十进制与单位、重复项、名称/引用、规则顺序与 FINAL、能力裁剪和宿主覆盖。
- 输入/行长/token/条目/引用深度/诊断预算、逐点分配失败、调用者释放输入后的 image 寿命，以及纯编译无 I/O。
- 等价显式样本产生相同 owned 模型；C SDK 和运行时沿用同一校验，不因文本入口不同改变取消、更新或旧流语义。
- 安装后的 `.conf` 宿主完成真实代理、控制/观测与失败/成功更新；DNS/TUN/平台新段按其实际实现单独验收。

原生 parser 加独立 fuzz 入口和人工构造的边界语料；预期不能全由待测实现自己生成。迁移可使用显式等价的旧 YAML 样本检查已有模型回归，
但不要求复制 YAML 隐式类型、mihomo 默认值或 Surge 的管理指令。新格式错误不能触发隐式旧格式回退。

mihomo、Surge 或其他实现的对照仅在需要研究或核验差异时使用，并固定版本、输入和观察点。
已有 mihomo 完整加载器与 YAML 差分结果保留为 M2 历史证据；CFG-04 完成后移出原生默认门禁，不能改标签冒充 `.conf` 验收。
协议线格式、独立对端互通、资源与生命周期测试继续保留；外部格式导入器若将来单独交付，则维护自身明确子集的兼容测试。

## 6. 协议与解析器

协议矩阵分别列出协议、传输、安全、encryption、flow、Mux、UDP 封装、地址族和对端版本。例如裸 VLESS/plain、裸 VLESS/TLS、VLESS encryption、Vision/TLS、Vision/encryption 需要分别登记；REALITY/XHTTP 等额外组合不从这些结果推导。编译有源码不等于每个入口可用。

M1-06 必须分别取得以下证据，完成状态由 [开发计划](DEVELOPMENT_PLAN.md#m1-06-协议范围与退出条件) 记录：

- VLESS encryption：固定支持该层的 Xray 对端，记录参数与版本；验证错误凭据、密文篡改/截断、重放、握手 deadline、取消与开启的会话恢复模式。普通 TLS 互通不覆盖协议加密。
- `xtls-rprx-vision`：固定支持该 flow 的独立对端；验证 padding/内层 TLS 识别、raw 切换前后顺序和缓冲交接、暂停/背压/关闭及 UDP 443 策略。允许的 TLS/encryption 承载组合逐项验证，禁止直接强转后端私有对象。
- VLESS XUDP：经 registry/factory 和公共 association 验证多目的 A/B/A、IPv4/IPv6/domain、真实 peer、空包、拆粘包/截断、会话标识隔离、取消和底层断流后的完成回调排空。不能以传统单目的 UDP 或 UoT 冒充 XUDP。
- 共享 UoT v2：独立 codec fixture 与对端分别验证地址/长度、空包、拆粘包/截断、有界排队及异常关闭；SS 每种受支持 cipher 的加密 stream、AnyTLS session 子流分别运行互通和 lifecycle 测试。SS 原生 UDP 成功、或只有 AnyTLS UoT 成功，均不覆盖 SS UoT；配置选择失败不得静默回退。

裸 VLESS、encryption、flow 和 UDP 方案的配置有效性、未知值、缺少所需 carrier 能力都必须经过模块工厂验证。至少两个 worker 上运行受支持组合，且保持实例/配置退休后活动通道的独立寿命。

对拆包/粘包、截断、畸形长度、错误认证、重复报文、乱序、超长输入、背压和异常关闭建立回归。解析器/framing 使用 fuzz，生命周期使用 ASan/UBSan；线程检测按平台能力执行。密码运算调用既有密码库，测试协议调用与状态使用的正确性。

## 7. 平台与性能

各平台独立检查产物消费、符号/头文件、所需架构、依赖打包；Android 包括页对齐，Apple 包括真机/模拟器切片与 Extension 集成。设备验收覆盖实际 TUN/protect、DNS/网络变化、反复启停、前后台、失败回滚及宿主资源释放。

性能采用同一设备、网络、流量与电源条件的 1/2/4 workers 对照，分别测单流、多流、多/单 UDP association、共享 Mux session、TUN TCP/UDP、配置更新叠加转发。

记录每线程 CPU、吞吐/包率、p50/p95/p99 延迟、loop lag、mailbox 深度、丢包原因、RSS/峰值内存和能耗。区分单核热点、栈 owner、入口分派、输出写入和队列开销；不承诺线性扩展，不以增加线程数作为通过标准。

## 8. 结果记录

每次验收至少保存：代码提交、参考/依赖版本、平台/工具链、精确命令或脚本、测试 ID、通过/失败/未执行、日志/产物位置与剩余限制。失败修复后针对相关行为复测；没有新变化或疑点不重复扩大测试。

只有对应交付物和验收证据完整时，才能在开发计划中标完成。构建通过、接口 smoke、模拟包和真机结果分开填写。

## 9. Parser fuzz 复现

使用带 libFuzzer runtime 的原生 Clang/Clang++。fuzzer 使用独立 core；下列专用构建还为 BoringSSL C++ 后端开启 coverage/ASan/UBSan，以覆盖私有 session 字段解析。普通 SDK 构建不采用这些参数。

```sh
cmake -S . -B build-fuzz -G Ninja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DSOLARIS_BUILD_FUZZERS=ON -DSOLARIS_BUILD_EXAMPLES=OFF -DSOLARIS_SANITIZER=address "-DCMAKE_CXX_FLAGS=-fsanitize=fuzzer-no-link,address,undefined"
cmake --build build-fuzz --parallel --target solaris_parser_fuzz solaris_vless_encryption_tests solaris_ss_control_peer solaris_encryption_control_peer solaris_tls_profiles_tests solaris_tls_profiles_peer
python3 tests/fuzz/seeds.py build-fuzz/seeds --ss-control build-fuzz/reference-tools/ss-control --encryption-control build-fuzz/reference-tools/encryption-control --encryption-client build-fuzz/solaris_vless_encryption_tests --tls-client build-fuzz/solaris_tls_profiles_tests --tls-peer build-fuzz/reference-tools/tls-profiles-peer
mkdir -p build-fuzz/corpus build-fuzz/artifacts
build-fuzz/solaris_parser_fuzz build-fuzz/corpus build-fuzz/seeds -dict=tests/fuzz/protocols.dict -max_total_time=60 -max_len=196608 -timeout=5 -rss_limit_mb=2048 -print_final_stats=1 -artifact_prefix=build-fuzz/artifacts/
```

入口覆盖地址、UoT/XUDP、VLESS/Vision、SS TCP/UDP、SOCKS5 握手/UDP、AnyTLS padding/session、VLESS encryption 配置/记录/握手、HTTP URL/响应、模块配置和 TLS session 序列化。输入包含 parser/variant/分配失败索引，逐次核对预算归零；没有网络或 executor 活动。保留失败 artifact 和命令，修复后以原 artifact 回放，再恢复变异运行。机制见 [LLVM libFuzzer 文档](https://llvm.org/docs/LibFuzzer.html)。有限时长运行不代表所有输入或平台已被穷尽。


TLS 基线和补丁有独立的 `tls_patch_contract`、`tls_recipe_contract`，范围见 [TLS 后端](TLS_BACKEND.md)。
`tls_contract` 包含确定性的停止边界：底层 open 已通知 TLS、握手 pump 已排队，此时先关闭 admission，
确认 scope 取消先于 pump 推进，accepted open 返回 ECANCELLED 且实际回调/资源全部排空。

Xray 的 UDP 测试目标使用 `tests/support/loopback.py` 在 IPv4/IPv6 同时预留端口，防止 macOS
双栈临时端口与单族回显 socket 重合。回显检测到源端口等于目标端口即停止并报错，不允许形成自回环洪泛。
Shadowsocks 的 A/B/A 源端口复用按同一测试中的活动通道核对；不同测试关闭后的端口重复分配不计为协议错误。
固定参考端的长重复检查仍可能受本机网络环境影响，必须保留同对端独立控制结果，不能以客户端重试掩盖。
