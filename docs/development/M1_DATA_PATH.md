# M1：模块工厂、UDP association 与统一 I/O

日期：2026-11-05。本文描述 M1-01–M1-05 及已接入的 TLS/VLESS/SS 边界；阶段状态以 [开发计划](DEVELOPMENT_PLAN.md) 为准。

## 协议目录与待交付组合

当前 Shadowsocks 的源码集中在 `src/adapters/outbound/shadowsocks/`：`module.c` 管理配置/工厂，`crypto.c` 处理密钥与密码调用，`stream.c` 处理 TCP 记录，`packet.c` 与 `native_udp.c` 分别处理原生 UDP 报文与通道。VLESS 集中在 `src/adapters/outbound/vless/`，`module.c` 管理配置/工厂，`stream.c` 实现基础请求/响应，`encryption/` 分开管理配置、密码原语和握手/记录状态。

VLESS 家族的目标包含裸 VLESS、VLESS encryption、`xtls-rprx-vision` 和 XUDP；当前基础 TCP/XUDP、plain/TLS 和 VLESS encryption 已实现，Vision 已接入下述经过验证的组合。encryption、flow、carrier 是独立的组合维度，UDP 通过 XUDP 接入 datagram/association。Shadowsocks 已实现原生 UDP 和可选 UoT v2；共享 UoT 已接入 SS 加密 stream 和 AnyTLS 子流。

未知或未支持的组合继续拒绝；准确职责见 [架构规范](ARCHITECTURE.md#协议家族与组合)，退出条件见 [M1-06 子项](DEVELOPMENT_PLAN.md#m1-06-协议范围与退出条件)。

## 模块注册与配置工厂

[模块契约](../../src/contracts/module/module.h) 定义冻结 registry、不可变配置与 owner 实例。`modules/builtin.json` 同时枚举源码、依赖、构建开关和 descriptor；CMake 从该清单生成显式 descriptor 引用，不使用 constructor 自注册。`SOLARIS_ENABLE_DIRECT`、`SOLARIS_ENABLE_BLOCK` 默认开启，可分别关闭；禁用模块不进入 archive 或 registry。

registry 发布前检查规范名/别名冲突、缺失依赖和依赖环。descriptor 及其字符串具有进程寿命，registry 复制模块指针数组。配置编译按名称或别名查找模块，未知或已禁用类型返回 ENOTSUP；`reject` 是 Block 的别名。

[配置视图](../../src/contracts/module/config.h) 是借用的类型化 map/string/integer 等数据，不依赖 YAML 库。模块编译复制需要保留的数据，检查重复/未知字段、类型和范围，诊断保留字段名与行列。外层配置编译器将来负责节点名称、type 和引用图；当前模块视图只包含模块配置，不代表已经支持 YAML。

Direct 通过共享 helper 编译 `bind-address`、`bind-port`、`open-timeout-ms`、`pending-bytes`、`pending-requests`、`read-chunk-size`。绑定地址必须是数值地址；端口需与地址一起提供。未配置的字段继承注入 dialer 设置，socket preparation/context 保留在宿主服务中，不能由配置覆盖。

配置可以跨 worker retain/release。工厂只在 owner 上创建实例，不联网；实例 scope 在显式 retire 或 engine stop 时关闭 admission，排空实例资源后销毁。部分编译/构造失败会回收已分配内容，拒绝构造不会触发用户 on_close。已返回通道有独立寿命；模块如需让通道使用配置，必须为通道持有相应引用。

固定 plan 可在 owner 上调用 `solaris_module_retain/release` 持有实例，防止 engine stop 先销毁实例、再收到 association 的释放。持有引用只延长对象寿命，retire 仍会关闭新 I/O admission；正常配置退休应等固定 plan 释放后再 retire 实例。

`module_contract` 验证自定义 descriptor、别名与依赖错误、输入修改/registry 销毁后的配置寿命、双 worker 构造、异步资源退休、重复 retire、失败分配和预算归零。静态 archive 与最终测试可执行文件分别检查 descriptor 的存在/裁剪，Direct/Block 对端测试全部经过 registry 工厂。

## 执行与停止

engine 管理一个控制线程及 1–32 个 I/O worker，每个 worker 独立 libuv loop。创建时停放，start 激活新 generation，stop 关闭全部普通任务入口并等待资源和回调排空；线程保留供再次 start，destroy 才终止线程。

普通任务使用有界 mailbox，已接受操作的完成节点由操作预留，使用独立完成队列。数据队列满或 admission 关闭不会阻断释放。分派、deadline 与取消每轮都有工作预算。

scope 管理基础引用及 native handle/request 引用。取消停止新 I/O，原生回调保留引用直到实际结束，归零后才在 owner 上执行 deferred done。done 和内存释放返回前不会发布 worker 排空屏障。

deadline 使用逐 executor 的逻辑时钟，由一个 libuv timer 驱动。测试可推进注入时钟并唤醒 worker。宿主 flush 的等待期限继续使用 OS 单调时钟。control 或本 engine 的 I/O 回调调用 flush/destroy 返回 EDEADLOCK。

## 统一 I/O

内部契约位于 [contracts/io/channel.h](../../src/contracts/io/channel.h)。stream/datagram 通过 vtable 操作，普通方法要求在 owner 执行，错误线程返回 ETHREAD。

- 接受 write/send 时保留 immutable buffer 引用，完成后释放；拒绝不产生完成回调且不保留引用。
- batch 接受有序前缀并返回准确 accepted 数量。目前是可移植的多次提交后备实现，不宣称一次原生 batch syscall。
- buffer 引用计数和预算支持跨 worker；发布后不能通过可写接口修改。预算包含 I/O buffer、通道和请求元数据，不等于 RSS。
- 接收 buffer/source address 借用到回调返回；buffer 可以 retain，source address 需要按值复制。
- 通道由 scope 拥有，on_close 返回后句柄失效。open、取消和 timeout 的已确定结果不重复交付。
- stream 支持读暂停/恢复、字节和请求数背压、writable 提示及半关闭；远端 EOF 后仍可本端写入。

## Direct 与 Block

[Direct](../../src/adapters/outbound/direct/module.c) 通过统一 socket/dialer 服务建立通道；[Block](../../src/adapters/outbound/block/module.c) 明确拒绝且不创建 socket。engine 和通用 I/O 没有协议类型分支。

内部模块与测试通过 registry/配置 factory 构造。adapter 私有 typed initializer 仅用于模块内部；YAML 与公开业务入口尚未交付。

outbound retire 关闭新 admission，已返回通道保留独立 scope。engine stop 取消所有通道，也可以在 owner 上单独 close。策略/业务回调的外部 context 必须保持到对应通道关闭，库不能自动复制任意 void 指针的所有权。

## Direct TCP

已实现 IPv4/IPv6、异步系统域名解析、有界地址候选尝试、端到端 open deadline、连接前 socket 策略、本地地址绑定、读写背压和双向半关闭。

失败候选的 socket 先关闭再尝试下一个，每个新 socket 都重新应用准备策略；策略拒绝不作为普通网络失败绕过。连接/解析完成也核对绝对 deadline，避免超时回调排队时误报迟到成功。

getaddrinfo 的 OS 工作不一定可立即取消。请求可先交付取消/超时结果，但 scope 保留底层请求直到真实结束；stop 不会提前释放相关内存。

## Direct UDP

已实现 IPv4/IPv6 unconnected socket、同族多目标发送、真实回包 source、零长度报文、长度校验、背压、部分 batch 和关闭屏障。一个通道发送 A/B/A 复用同一本地绑定。

IPv4/IPv6 使用独立 lane，底层通道对错误地址族与域名目标明确返回 ENOTSUP。上层 association 负责域名到数值端点映射；规则选路、DNAT 与 Fake-IP 尚未实现。

发送队列满返回 EAGAIN，不关闭通道；单包过大返回 EMSGSIZE。截断接收丢弃并计数。接收 buffer 分配失败作为终端资源错误关闭通道，避免忙循环；更细的接收内存压力恢复尚未实现。

## UDP association

[association 服务](../../src/contracts/flow/udp.h) 允许任意线程提交，使用每 engine 独立的有界表。key 包含入站 ID/代际、客户端身份与规范化源地址；不使用结构体 padding 或 IPv4 的无效尾部字节。首包在分派前登记，后续并发报文合并排队；整个关联只选择一次 plan，目标改变不重选。worker 集合更新只影响新关联，存量保留原 owner。

首次任务通过普通 executor admission 入队，保证尚未建立 scope 的首包也包含在 engine stop 屏障中。后续队列使用预留完成节点与 scheduler 引用，在数据队列满和 admission 关闭时仍能排空。请求计数涵盖排队和已提交未完成的包；batch 返回准确有序前缀。snapshot 分别记录 accepted/sent/failed、待处理包/字节、队列拒绝、接收与回复丢弃。

默认上限为 1024 个关联、每关联 32 个目的映射、64 个未完成报文和 256 KiB payload；内部 options 可降低或调整。内存分配仍受 budget 限制。目的映射不在活跃期间自动替换，达到上限明确拒绝新目的。domain-capable adapter 可保留域名；否则按首部顺序调用 resolver，合并同一目的的待完成解析。最小系统路径优先 IPv4、回退 IPv6；完整 DNS 策略/cache/Fake-IP 在后续阶段。

具有 multi-destination 能力的 adapter 按地址族复用通道；单目的 adapter 按目的隔离通道。snapshot 报告 `ASSOCIATION_LANES` 或 `DESTINATION_LANES`；只有共享通道且 backend 可查询时才报告单一本地端口，不把目的专用通道写成稳定 NAT 映射。

回复端点以线程安全引用持有，send 在关联 owner 执行，回调期间借用 peer/buffer。真实 peer 按值规范化后交付，不替换成首包目的地；跨入站 owner 的转发由端点自身的有界消息桥完成。相同 key 更换 endpoint/context/generation 返回 EBUSY，关闭后可新建；在线替换与 SOCKS 控制连接接入属于 M2。

open、DNS 和 idle 分别使用 deadline，open/解析结果还检查绝对时间以拒绝迟到成功。默认 idle 为 300 秒，合法发送/成功回复刷新；队列满、失败发送及被回复端点拒绝的包不刷新。初次解析失败且没有可用通道/后续报文时回收关联。取消先拒绝 admission，再排空包、通道、resolver 和 timer；迟到完成保留引用到实际回调，旧 ID 不能关闭同 key 的新关联。宿主需在销毁借用的 executors 前 close/destroy dispatcher；destroy 在全部回调/引用排空前返回 EBUSY。

`udp_association_contract` 用独立 Python UDP 对端验证 U01–U04、U08 的真实备用源端口、U09 的 datagram 子集与 U12；`udp_lifecycle_contract` 注入时钟/迟到完成、单目的 backend、资源与分配失败验证 U10。备用源 IP 的原样传递通过受控通道回调验证；没有公网 NAT 或平台接口切换证据。

## Carrier、TLS 与记录过滤器

`contracts/io/carrier.h` 的 carrier factory 只建立 stream，不依赖具体代理协议。工厂在 open 返回前复制或 retain 后续所需配置；模块可注入其他 carrier，物理连接仍经统一 dialer/socket policy。

`transport/tls/tls.h` 的不可变信任上下文可跨 worker 共享，必须提供非空 PEM CA；证书链及 DNS/IP identity 校验不可跳过，最低 TLS 1.2。M1 尚无系统信任库桥接、客户端证书、指纹、ALPN 配置或 REALITY。每端 BIO 为 32 KiB，单次 wire write 最多 16 KiB，证书链上限 256 KiB。原生 BoringSSL 内部分配不计入 Solaris buffer budget，不能把该预算当作完整 RSS 上限。

`transport/stream/filter.h` 将记录编解码与 stream 的队列、deadline、scope、暂停和关闭分开。codec 不创建网络对象；接收区由 codec 声明上限，输入不足暂停解码并等待下一片，错误或未完成记录的 EOF 明确失败。write 的成功完成在下层实际 write 完成之后，取消排空所有已接纳回调。

VLESS 配置字段为 `server`、`port`、`uuid`、公共 dialer 字段，以及可选 `tls`/`servername`/`ca-pem`、`encryption`。目前支持基础 TCP 与 Single XUDP，均可用 plain、普通 TLS 或 encryption、十六进制 UUID；支持下述 Vision 组合；REALITY 未接入。open 成功表示 carrier 和请求 preface 已写出，基础 VLESS 本身没有独立的鉴权确认，不能把它当作远端目标已连通。后续数据和单次测速才能检验往返路径。

线格式参考 [Project X VLESS 协议](https://xtls.github.io/development/protocols/vless.html)，独立对端固定为 [sing-box v1.12.12](https://github.com/SagerNet/sing-box/tree/v1.12.12)。依赖和对端版本集中记录在 `dependencies/lock.json`。

## VLESS encryption

`encryption` 缺省或 `none` 关闭此层；启用格式与 [固定 Xray 的定义](https://github.com/XTLS/Xray-core/tree/a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/vless/encryption) 对齐：`mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.[padding.delay.padding...].<server-public-key>[.<relay-key>...]`。支持 X25519 和 ML-KEM-768 服务端认证密钥，最多 8 个密钥；拒绝无效、低阶 X25519 与非规范 base64url。padding 最多 31 个交替块、总长度至多 65,553 字节、总 delay 上限 60 秒，仍受整个 open deadline 限制。未指定 padding 时使用协议默认范围。

完整握手组合临时 ML-KEM-768 与 X25519，并校验服务端 NFS AEAD、票据和全部 padding 后才放行 VLESS 请求。使用硬件可用性选择 AES-256-GCM 或 ChaCha20-Poly1305；两种原语均有独立 Go 样本。nonce 按大端递增，回绕记录使用旧密钥认证后派生新密钥，random 模式单独维护 header CTR。分片输入、分配失败和认证失败不会提前提交接收 nonce/header 状态。

`0rtt` 先完成一次完整握手，再使用各 worker 客户端内的票据。有效期使用单调时钟；恢复时使用新的 NFS 密钥，可立即写入，首个响应记录才确认该次恢复。未确认的恢复关闭、失败或取消会保守清除同一代票据，旧连接不能抹掉较新的票据。后续新连接可重新完整握手，已接受的业务数据不自动重放。客户端状态由通道持有，不随模块提前 retire 释放。

中立 record filter 提供可选 ready gate 和分段 preface/delay，不让 codec 拥有 socket、线程或 timer。等待认证期间继续处理握手输入；业务读暂停仍生效，on_open 前不交付业务数据。deadline、delay 与迟到写回调均计入 scope 的关闭屏障。

固定 Xray v26.10.31 的所有 appearance、X25519/ML-KEM/混合 relay、plain/TLS、双 worker、双栈/域名、重复连接和 XUDP/association 已在本机互通。独立 Go fixture 保留真实服务器状态，确认实际 0-RTT 恢复、重复恢复请求拒绝、握手/记录篡改、截断、重复/乱序、nonce 回绕、分配失败回滚、票据过期和旧代失败。Vision 组合另见下节；没有远端 CI、设备或性能验收结论。

## Vision 与 raw 切换

VLESS `flow` 接受空值、`xtls-rprx-vision` 和 `xtls-rprx-vision-udp443`。基础 flow 在 XUDP 编码前拒绝 UDP 443；后缀允许该端口。无 encryption 时必须配置 TLS，且实际协商最低 TLS 1.3；有 encryption 时只穿透 encryption 层，下层 TLS/其他承载继续维持其语义。REALITY、TCP Mux 和内核 splice 不在此实现中。

`vision/` 负责 flow addons、首帧 UUID、padding continue/end/direct、TLS record/ServerHello 识别。记录头与握手均可跨输入片段，ServerHello 捕获上限 65,792 字节；校验扩展长度、supported_versions、cipher 与 HelloRetryRequest，CCM_8 不进入 raw。写方向在完整内层 application record 边界发出 direct 标记，再等承载写屏障完成；未知命令、缺少 UUID、过早 direct 与截断帧拒绝。

中立 stream raw 契约提供同步读切换和有序异步写屏障。TLS 每次只向 BoringSSL 提供一条记录；读切换先排空 `SSL_pending` 明文，再交付尚未喂入的底层字节，不访问后端私有结构。写屏障等待已有密文实际完成，切换后不插入外层 close_notify。encryption 的 random 模式继续处理内层 TLS 记录头 CTR，原语层支持拆分 header/body；其他两种 appearance 直接转发。

`tls_raw_contract` 通过独立 Python TLS 1.2/1.3 对端验证同一次 TCP 写入中的 TLS/raw 拼接、剩余明文、暂停、写屏障、关闭与取消。Vision 的固定 Xray 对端验证真实内层 TLS 的双向切换、plain 应用数据、三种 encryption appearance、encryption-over-TLS 1.2、双 worker、重复连接、XUDP/association。独立 codec fixture 覆盖最大扩展、HRR、错误标记、半帧、错误 cipher/版本/扩展、分配失败和 UDP 443 策略。

## Shadowsocks

`shadowsocks`（别名 `ss`）配置采用 `server`、`port`、`cipher`、`password`、可选布尔字段 `udp-over-tcp` 和公共 dialer 字段。当前支持三种 AEAD 2017 方法（AES-128/256-GCM、ChaCha20-IETF-Poly1305）及 SS 2022 必选的两种 BLAKE3/AES-GCM 方法。2022 password 必须是精确 16/32 字节的 base64 PSK，不对超长密钥做哈希兼容；不接受 EIH、多用户密钥链、插件或 TLS。SS 2022 可选 ChaCha 方法未实现。

TCP 复用 record filter。2022 preface 将 salt、固定头、含非零随机 padding 的可变头合并为一次下层写入；响应校验 type、30 秒时间差和请求 salt。AEAD 2017 单记录上限 16,383，2022 为 65,535；空 payload 的鉴权记录也会被消费，未完整的 header/record EOF 明确失败。与 VLESS 一样，open 只说明请求已写出，不能替代往返连通性验证。

原生 UDP 包 codec 与 socket 生命周期分离。通道通过统一 dialer 建立数值服务端的 UDP socket；域名服务端异步解析，受绝对 open deadline 和 scope 约束。收包先核对物理服务端 endpoint，再解析经过认证的源地址。多目标通道保留同一外层 socket；IPv4/IPv6 lane 由 association 层决定。无效鉴权/地址/重放包丢弃计数，资源分配失败关闭通道并排空已接纳发送。协议 payload 上限 65,000 字节，实际可发送尺寸还受 OS/socket/path MTU 限制，异步失败如实回调。

AEAD 2017 没有时间戳，因此实例工厂要求注入跨 worker、跨配置共享的 persistent exact replay store，TCP/UDP 与两个方向使用同一 key/salt 命名空间。该有界集合不自动过期、不淘汰存活项；满表拒绝新 salt。宿主服务管理其容量和寿命，不可通过配置退休重置来规避重放保护。M1 的内部集成调用方显式提供该服务，公开 engine SDK 尚未暴露协议工厂。

SS 2022 TCP 响应绑定请求 salt；UDP 使用独立客户端 session、递增 packet ID 和两个服务端 session 的 1,024 包滑动窗口。每个服务端 session 至少保留 60 秒；所有鉴权、时间、客户端绑定、padding 和地址检查通过后才更新窗口。第三个服务端 session 在没有过期槽位时拒绝。时间戳使用 Unix 时钟，保留期使用单调时钟，两者都可注入测试。默认熵来自 BoringSSL CSPRNG；熵失败不会发送未加密或复用 nonce 的数据。

协议依据为 [Shadowsocks AEAD](https://shadowsocks.org/doc/aead.html) 与 [SIP022](https://shadowsocks.org/doc/sip022.html)。独立 Go 加密 fixture 验证篡改、截断、salt/time/session 绑定、重放、乱序、窗口和内存失败。真实网络对端固定 sing-box v1.12.12；本机观察到同一远端映射由 IPv4 切换到 IPv6/域名的对端限制，独立客户端对照也复现，因此真实互通分别覆盖 IPv4 A/B/A、IPv6 lane 和域名首包。未推导公网 NAT 或设备验证。

## 共享流式 datagram 与 UoT

[流式 datagram backend](../../src/transport/datagram/stream.h) 接受任意 stream factory 与独立 packet codec，统一管理 scope/deadline、消息队列、接收重组、暂停/背压和关闭屏障。接受的消息保留 immutable buffer，成功完成发生在下层 write 完成之后；失败/取消排空所有回调，迟到的下层完成继续持有引用。batch 维持有序前缀语义。接收空间受 codec frame limit 与最多 64 KiB 的单次 carrier delivery 限制，不能把消息拆成无界队列。

[UoT v2 codec](../../src/codec/uot/codec.c) 使用 non-connect 模式，每包携带目的地址。`udp-over-tcp: true` 使 SS 通过加密 stream 请求 `sp.v2.udp-over-tcp.arpa:0`，首次 send 将实际首包目的地的请求头与报文一起编码；后续包仍可改变目标。普通目标的零端口校验保持严格，magic peer 仅是协议元数据，不交给物理 resolver。默认 `false` 继续使用原生 UDP，失败不会自动切换方案。AnyTLS 使用相同 backend 与 codec；v1 与 connect 模式尚未交付。

UoT payload 协议上限为 65,535 字节，队列配置仍可限制单次接纳；实际 UDP 转发尺寸受对端 OS/path MTU 限制。local-address 返回 ENOTSUP，不将承载 stream 的 TCP 端口当成远端 UDP NAT 端口。open 只表示 carrier 与其必要前缀已就绪，不能证明后续 UDP 目标可达。线格式见 [SagerNet UoT 文档](https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/)。

独立 Python fixture 验证地址类型、首包请求/后续帧、空包、255 字节域名、65,535 字节 payload、部分输入和失败分配。受控 stream 验证 EOF 截断、错误地址、读暂停、部分 batch、背压、绝对 deadline、取消后迟到回调及 stop 等待。SS 的固定独立对端对五种 cipher 分别运行 native UDP/UoT，实例与配置提前退休后通道仍正常收尾；AnyTLS 的 TCP/UoT 另有独立对端测试。SS native UDP/UoT、AnyTLS UoT 和 VLESS XUDP 均通过公共 association 的双 worker/三 family lane、固定 plan、批量、配置释放与停止组合测试。

## VLESS XUDP

[独立 XUDP codec](../../src/codec/xudp/codec.c) 实现 Single XUDP：VLESS 外层发送 CommandMux 3，不发送目标地址；首个 datagram 发送 New/session ID 0，后续 Keep，每包都携带目标地址。地址编码使用共享 port-first helper。每个 datagram channel 拥有独立承载流；不实现跨连接 global-ID 复用、自动重放或 TCP Mux。payload 上限 65,535，实际 UDP 转发尺寸由对端 OS/path 决定。

接收端严格校验 metadata 长度、session ID、UDP network、地址与选项。无地址 Keep 使用首个目的地址；带地址的包保留对端提供的 peer，包括备用回复端口。KeepAlive 数据只消耗不交付；End 可交付最后一包后以 ECLOSED 结束通道；错误标记、未知命令和截断关闭通道。通用 backend 负责有界重组、背压与关闭屏障，association 不辨识 XUDP/UoT。

线格式依据 [Project X Mux.Cool](https://xtls.github.io/en/development/protocols/muxcool.html)。固定 sing-box v1.12.12 和 Xray v26.10.31 对端、独立 sing-vmess v0.2.7 对照和 Python TLS/UDP 对端分别提供互通、对端限制与完整空包/异常帧证据。固定外部对端均丢弃空 XUDP；sing-box 的同连接 IPv4→IPv6 切换也不支持。Solaris 不据此改写地址或将空包转为非空，支持的语义由独立 fixture 和可处理空包的真实 UDP 对端验证。

## Session 与 AnyTLS

[共享 session pool](../../src/transport/session/pool.h) 管理 carrier、子流、队列、deadline、空闲回收和故障传播，codec 只负责帧和输出分包。每个 pool 属于一个 worker；默认会话队列至少 1 MiB/64 请求，配置更大子流限制时相应提高，子流仍受自己的 pending 限制。接收区由 frame limit 加最多 64 KiB carrier delivery 限定，不另建无界子流接收队列。暂停的子流可在下一 DATA 帧阻塞整个 session；共享层可配置多子流复用，AnyTLS 按协议选择最新空闲 session，每个 session 同时承载一个子流。

子流取消后，尚未开始的 DATA 从队列移除；已开始的分包必须完成当前帧，再发送全关闭标记。已接纳 write 恰好完成一次，scope 保留到 carrier 的迟到完成。session 故障关闭所有子流，不自动重放数据。模块退休停止新 admission、立即回收空闲 session，活动子流排空后再关闭 carrier；engine stop 则取消全部 scope。空闲截止时间在选择 session 时也检查，避免 timer 尚未执行时复用已过期连接。

`anytls` 配置要求 `server`、`port`、`password`、`tls: true`、`ca-pem` 和 identity，支持公共 dialer 字段及 `idle-session-timeout-ms`（默认 60,000，范围 1–3,600,000）和 `session-limit`（默认 64，范围 1–1,024）。只支持协议 v2；TLS 信任与身份校验沿用共用 transport。当前子流单次 write 最大 512 KiB，再按 65,535 字节的 PSH 帧分段；队列限制可以进一步降低接纳上限。

TCP open 等待请求写入和成功 SYNACK，SYNACK 错误关闭该子流。UoT 的目的地址还在应用 preface 内，对端读取该 preface 后才可能确认，所以其 carrier open 只等待请求写入，后续错误仍传播到 datagram。AnyTLS FIN 是整个子流关闭，不发布 HALF_CLOSE 能力，shutdown_write 返回 ENOTSUP；不能把它伪装成 TCP 半关闭。

认证采用密码 SHA-256 和 padding0。首个 session 包组合 Settings、SYN 和目的地址 PSH；padding 保留每次 carrier write 的边界。服务端更新的策略仅影响该 worker/client 后续新 session，活动 session 保持快照。策略最多 4 KiB、32 个包编号、每包 16 项，每项长度不超过 65,535；无效或超限策略明确关闭，不静默忽略。随机范围使用拒绝采样，熵提供者异常不会形成无限循环。Alert 拒绝 session，并经可选 `module_services.diagnostic` sink 交付最多 1 KiB 的对端文本；文本是借用的不可信字节，宿主负责安全显示，库不直接写 stderr。

线格式依据 [AnyTLS 协议文档](https://github.com/anytls/anytls-go/blob/main/docs/protocol.md)。固定 sing-box v1.12.12/sing-anytls v0.0.11 对端验证双 worker、双栈/域名、TCP/UoT、空包、背压、错误凭据和取消。独立 Python TLS 对端确认每个 worker 在同一 TLS session 上依次完成三个子流，并验证拆包、padding 更新、错误版本/命令、截断和 SYNACK 拒绝；Python binary fixture 单独验证认证、帧、padding 与失败回滚。共享 session 受控测试覆盖多子流、最新 session 选择、空闲超时、故障传播、部分帧取消、迟到 write 的 stop 屏障及分配失败。

## 平台与公开 API 边界

当前 socket preparation 是 nonblocking 同步回调，在 TCP connect/首次 UDP send 前执行；本地 bind 也经统一服务。回调不能私自关闭借用的 native handle，且需考虑不同 worker 并发调用。

异步 Android protect、系统接口自动选择、宿主 DNS 接管与 TUN 尚未实现。最小 resolver 使用系统 getaddrinfo，不宣称控制了 OS 内部 DNS socket 的 protect 策略。

公开安装 SDK 仍是 engine 生命周期/控制入口。Direct、I/O、executor、resolver 均是内部模块接口，不是已发布的宿主网络连接 API。

## 验证

- [executor 测试](../../tests/contracts/runtime/executor.c)：双 worker 独立线程、阻塞隔离、满队列取消、迟到完成释放、generation 重启、逻辑 deadline、资源上限、跨线程 buffer、部分 worker 创建失败回收、192 个 scope 分批停止。
- [I/O 测试](../../tests/contracts/io/channel.c) 与 [Python 对端](../../tests/support/io/peers.py)：TCP 双栈/localhost、背压、暂停、两个方向的半关闭、取消、写后关闭和时钟注入超时；UDP 多目的同端口、备用源端口、空包、IPv6、部分 batch、关闭排空；Block/policy 拒绝。
- 测试结果使用 [mutex/condition 事件](../../tests/support/runtime/event.h) 交接，保证未插桩 libuv 的 Mach semaphore 路径之外也有 TSan 可见的发布关系；没有 race 忽略规则。

这些验证使用本地受控对端，不等于公网 NAT、系统 VPN、完整协议互通或性能验收。

## 固定 plan、选择与观测

`contracts/flow/plan.h` 定义一个 owner 上的唯一 lease，包含固定 outbound、节点 ID 和选择修订。释放会先清空调用方的 plan，再释放引用；UDP association 对全部后续 family lane 使用同一个 plan。

`policy/select/` 的 control 在所有 worker 间共享一份选择状态；成员 ID/名称不可变，worker group 绑定自己的模块实例。最小组是平面成员列表，YAML 与嵌套组在后续阶段。切组只影响新 plan，retire group 不退休仍被其他组/plan 使用的成员。健康 PASS/FAIL/UNKNOWN 与选中成员独立，较早开始的检查不能覆盖较新的结果，取消不把节点标为故障。

`observe/connections/` 在 flow 边界包裹固定 plan，一个 UDP association 的多个通道共用一条记录。tracker 有全局活跃上限和有限关闭历史；线程安全快照保留节点/选择修订、owner/generation、首目标、最后目的与真实回复地址、逻辑字节/包、队列和错误。跨线程关闭使用预留完成节点，数据 mailbox 满时仍能关闭；先拒绝新操作，再等待实际已接受回调。旧 ID 不关闭新的记录，destroy 在 plan/通道/回调排空前返回 EBUSY。

逻辑计数只在该包装边界更新，禁止重复包裹同一 plan；USER 与 PROBE 分桶，计数按 worker 聚合。live 总量是跨 worker 的观测快照，owner fence 后可精确核对。`runtime/metrics/traffic.c` 则在物理 TCP/UDP callback 处计数一次，包含协议/TLS framing，排除 IP/TCP/UDP 头部和 OS getaddrinfo 的内部流量；共享 session 的物理量不虚构为每个子流独占。计数对象可跨线程引用/查询，原生通道持有引用；宿主仍需保留 factories 使用的计数对象。数值达到 uint64 上限时饱和并标记。

## 单次 HTTP/HTTPS 测速

`observe/probe/` 消费一个固定 plan，发送一个 HEAD 请求；请求写完成且收到完整 2xx/3xx 响应头才成功。URL 上限 2,048 字节，支持 ASCII 域名、IPv4、带方括号的 IPv6、端口、路径和 query；fragment 不上网，userinfo/control 字符和无效端口拒绝。响应头最多 16 KiB、最多 4 个 informational response，不跟随跳转，不重试或重放应用数据。

HTTPS 使用 URL identity 和显式 CA，TLS 模块关闭时拒绝 HTTPS、保留 HTTP。整体 deadline 在 open、数据和最终结果处检查，迟到成功不会改成健康；取消和完成均等待 stream、write 与 timer 回调排空。结果耗时记录决定结果的时间，OS 取消排空较慢可能推迟结果交付。通过 tracker 的流量归 PROBE；健康发布使用独立 token，不切换选择状态。本项衡量响应头往返，不是吞吐测试。

现有所有出站均经过相同的观测包装与独立 HTTP(S) 对端测试。SOCKS5 扩展复用了这些入口，通用统计、选择及 probe 未增加协议判断。


## SOCKS5 outbound

`adapters/outbound/socks5/` 独立持有配置、握手 codec、TCP wrapper 与 UDP ASSOCIATE 生命周期。
配置为 `server`、`port`、公共 dialer 字段及成对提供的 `username`/`password`（每项 1–255 字节）。
无凭据时只提供 no-auth，有凭据时只提供用户名密码认证，拒绝服务端降级到其他 method。
支持 CONNECT/UDP ASSOCIATE、IPv4/IPv6/domain；不支持 BIND、UDP FRAG、TLS 配置或认证方法扩展。

TCP 依次完成 method、可选认证及 CONNECT 回复；open 等待最后一次握手写入完成，保留回复后的
预读应用数据。接收可以分片或与数据/EOF 合并；队列、暂停、半关闭、绝对 deadline 和取消仍遵守公共 stream 契约。

UDP 独占一条存活的 TCP 控制连接；成功回复后建立 relay 通道，wildcard BND 地址使用控制连接选中的实际服务器地址，
domain BND 经异步解析。保留 UDP 包内真实源地址/端口，丢弃错误 relay 来源、保留位、FRAG 或畸形报文。
控制连接 EOF、异常数据或关闭会关闭整个 association，等待已接纳 send、DNS、timer 和实际底层 close 回调排空。
控制连接与 relay 共用一个整体 open deadline；候选 TCP 仅在尚未连通时允许尝试下一个地址，握手失败不重试认证。

固定 sing-box、独立 Python 线格式/UDP 对端，以及受控 TCP carrier 加真实 UDP socket 分别验证互通和生命周期。
select/固定 plan、HTTP(S) probe、连接追踪、逻辑与物理计数均复用通用层。仅 SOCKS5 的静态构建可以关闭 TLS/crypto。
