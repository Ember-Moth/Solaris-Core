# HTTP、SOCKS5 与 mixed 入站

三个入口共用内部 owner/scope、固定 dial plan、TCP relay 和 UDP association。启用
`SOLARIS_ENABLE_PROXY_INBOUND`（默认开启）会构建全部三个入口并链接固定版本 llhttp；设为
`OFF` 后这些源码和 llhttp 依赖均移除。它不依赖 SOCKS5 出站、TLS 或 TUN 模块。

内部入口位于 `src/contracts/inbound/proxy.h`，供内核集成使用。宿主通过公开 YAML 编译和 prepare/commit
激活、更新监听，见 [SDK 用法](SDK.md)。HTTP 代理监听本身是明文 TCP；HTTPS 目标通过 CONNECT 隧道访问。

## 能力与边界

| 入口 | 已实现 | 明确边界 |
| --- | --- | --- |
| HTTP | HTTP/1.0、HTTP/1.1 CONNECT；普通 absolute-form / origin-form 请求；Basic 认证；Content-Length、chunked、Expect/100-continue 和受限 trailer；WebSocket Upgrade | 普通转发每条客户端连接只处理一个请求，重写 `Connection: close`；不支持普通 HTTP 连接复用、非 WebSocket Upgrade、HTTP/2 或 HTTPS absolute-form |
| SOCKS5 | CONNECT、UDP ASSOCIATE；无认证或用户名密码认证；IPv4/IPv6/domain 目标；分片或合并到达的握手 | 不支持 BIND、UDP FRAG；UDP ASSOCIATE 的客户端地址必须为数字地址或全零地址 |
| mixed | 同一端口按首字节识别 SOCKS5 或 HTTP，共用认证策略 | `select` 收到识别后的 HTTP/SOCKS5 类型，不是 mixed 类型 |

CONNECT 成功回复只在出站真正打开后发送。HTTP 连接失败返回 502，连接超时返回 504；SOCKS5
拒绝、失败和超时使用相应失败回复。握手未完成或流空闲超时会关闭连接。成功回复前收到的隧道数据
保留到握手回复写完后再转发。普通 HTTP 不把 pipeline 中第二条请求发送给目标。

SOCKS5 CONNECT 的 BND.ADDR/BND.PORT 当前为 `0.0.0.0:0`：统一 stream 契约不暴露出站本地地址。
UDP ASSOCIATE 则返回实际绑定的 UDP 地址和端口。

## 宿主接入

所有 API 和回调在指定 executor owner 上调用。一个 owner 可以同时创建多个监听器；不同 owner
也可分别创建。`listen` 必须是数字 IPv4/IPv6 地址，端口 0 请求系统分配临时端口，实际地址由
`snapshot.bound` 返回。默认只监听 `127.0.0.1`。

```c
solaris_proxy_inbound_options_t options;
solaris_proxy_inbound_options_init(&options);
options.owner = owner;
options.protocol = SOLARIS_INBOUND_MIXED;
solaris_address_parse("127.0.0.1", 7890, &options.listen);
options.inbound_id = inbound_id;
options.context = host;
options.select = select_plan;
options.authenticate = authenticate; /* NULL 表示允许无认证 */
options.on_close = inbound_closed;
solaris_status_t rc = solaris_proxy_inbound_create(&options, &inbound);
```

`authenticate` 同步接收用户名和密码字节及其长度；返回 `SOLARIS_OK` 才允许。配置该回调后必须
使用 HTTP Basic / SOCKS5 用户名密码认证，不能降级为无认证。借用的凭据仅在回调期间有效；
宿主不要阻塞 owner。HTTP 返回 407 时带 Basic challenge，代理认证头不会发送到目标服务器。

`select` 接收 source、destination、实际入站协议、TCP/UDP、inbound_id、connection_id 和已认证
用户名。返回一个拥有独立 lease 的 `solaris_dial_plan_t`，例如通过 `solaris_module_plan_acquire`；
框架负责释放。TCP 在连接开始时选择一次，UDP 在 association 建立时选择一次，后续目标映射保持
同一个 plan；选择回调不执行网络 I/O。返回失败时也不得遗留未交回的资源。

运行时 bundle 使用异步 `route` 接口：TCP 接纳即持有对应代际，完成握手后启动 route job；等待 DNS 期间
暂停读取并保留有界首包。UDP 首条有效包在登记关联时固定配置视图，排队处理不重新读取 active；后续包复用同一关联。
route job 取消、超时、连接关闭或 stop 后排空 resolver 回调，不能迟到拨号。旧同步 `select` 仍供固定 plan 的内部宿主使用。

`detached_create/accept` 将不可变入站代际与物理监听分开，配置管理器以同一 active publication 派发新连接。
`retire` 只关闭新接纳，存量连接继续；`close` 取消全部连接和关联。候选失败使用 parent scope 等待完整析构，
包括工厂拒绝后仍在进行的 native close。

认证和选择回调可以关闭自己的监听器。`create` 拒绝时输出为 NULL，不产生宿主关闭回调；接受后
`on_close` 等待监听器、TCP/UDP、关联、已接受 I/O 和延后回调全部排空。对象在该回调返回后失效。
engine stop 同样触发排空。`snapshot` 提供活跃连接数、接受/拒绝、认证/协议失败和 UDP 丢弃计数；
它不是完整流量或连接列表 SDK。

## HTTP 报文与预算

llhttp 9.4.3 以严格模式解析，Solaris 额外拒绝重复 Host/Content-Length、TE+CL、Host 与目标不一致、
错误 authority、非 WebSocket Upgrade，以及用 Connection/Proxy-Connection 指名关键 framing 字段的请求。
普通请求改为 origin-form 并生成目标 Host；移除 Proxy-Authorization、Proxy-Connection、Connection、
Keep-Alive、TE 以及 Connection/Proxy-Connection 指名的字段。原始请求中的 origin Authorization 保留。

正文流式校验并背压；chunked trailer 在完整验证前不向后转发。认证、路由、framing、内容处理和
连接控制相关字段不允许作为 trailer。流式转发期间遇到无效正文会关闭连接，已经发送的正文无法撤回。

默认头部上限 32 KiB，允许配置 1 KiB–1 MiB；最多 256 个头字段，trailer 字段名最多 256 字节。
trailer 的缓冲预算为头部上限加一个 8 KiB 读块。客户端握手缓冲也受该界限约束。
默认每监听器 1024 条连接，单流/association 待处理字节 256 KiB、UDP 待处理包 64 个、目标映射 64 个；
握手超时 10 秒，空闲超时 300 秒。`pending_byte_limit` 至少为 `header_limit + 8192`；
所有内存仍受 engine 预算约束。资源拒绝不会返回伪造的成功握手。

## WebSocket

HTTP/mixed 入站支持两种路径：直接 `GET http://host/path`（也接受 `ws://` absolute-form）携带
`Upgrade: websocket`，或先建立 CONNECT 隧道再发送 WS/WSS。WSS 的证书验证和 TLS 握手由客户端与
目标服务器完成，代理透明转发加密字节。

直接 Upgrade 要求 HTTP/1.1 GET、Connection 的 Upgrade token、版本 13 和有效格式的 16 字节
Sec-WebSocket-Key；无请求正文，可携带 Content-Length: 0。转发时规范化 Connection/Upgrade，保留
Origin、Cookie、目标 Authorization、子协议与压缩扩展字段，仍剥离代理凭据和其他 hop-by-hop 字段。

上游响应头按严格 HTTP 规则解析。允许最多 16 个 informational 响应，整个响应头序列共用
`header_limit`，并沿用从客户端接入开始的握手 deadline。有效的 101 必须携带匹配的 WebSocket
Upgrade/Connection token，以及格式正确且唯一的 Sec-WebSocket-Accept，且没有消息正文长度字段。
客户端仍负责校验 Accept 与自己 Key 的对应关系、协商的子协议和扩展。

101 及与其合并到达的首批服务器帧排空后才开放双向透传；提前到达的客户端帧保留在有界缓冲中。
非 101 响应继续按 HTTP 的 Content-Length/chunked/EOF 正文边界发送并关闭，不切换协议，不发送提前
到达的客户端帧。无效上游响应和握手 EOF 返回 502，等待响应超时返回 504。

切换后不解析、解压、重新分片或改写 WebSocket 帧，因此 Ping/Pong、Close、分片、二进制载荷和
permessage-deflate 均由两端处理。连接沿用 `idle_timeout_ms`（默认 300 秒）；任一方向实际流量都会
刷新计时，心跳同样有效。需要更长静默期的宿主应提高该值；代理不主动生成 WebSocket 心跳。

## UDP 控制与来源约束

每条 TCP 控制连接有自己的 UDP socket。UDP 源 IP 必须与 TCP peer 一致；请求提供非零端口时从第一包
起固定该端口，端口为 0 时由第一条有效 SOCKS5 UDP 包绑定，后续不允许换端口。全零客户端地址按
TCP peer 解释；错误 RSV、FRAG、地址或目标端口的包不能抢占绑定。

TCP 控制连接 EOF、异常关闭、收到额外控制数据、入站关闭或 engine stop 都会关闭 association 和
UDP socket。回复保留实际目标地址；空 UDP payload 有效。超大包和预算不足显式丢弃并计数。
关闭后的旧 endpoint 不会投递到新连接。

association 空闲回收不关闭 SOCKS5 控制 TCP；控制连接仍受每入站连接数上限约束。后续有效包可重新创建关联。
配置更新时，旧控制连接按逻辑入口 ID 查询当前配置，不以旧物理端口定位；认证策略变化、入口删除或禁用 UDP
会拒绝新关联。已经建立的关联保留旧 plan，包括提交后新建目标映射或地址族 lane。

## 验证入口

- `http_proxy_codec_contract`：严格 framing、认证编码、逐字节拆分正文/trailer、pipeline 隔离、截断和字段数限制。
- `proxy_inbound_contract`：独立回环 TCP/UDP 对端，三入口和两种认证策略、IPv4/IPv6/domain、并发、多监听器、
  来源端口限制、真实连接失败、受控连接超时、关闭重入、分配失败与 engine stop。
- 系统有 curl/openssl 时，同一测试额外验证 curl HTTP/SOCKS5 认证及验证证书后的 HTTPS 隧道；缺少工具会明确输出跳过。
- `websocket_inbound_contract`：独立 RFC 6455 客户端/服务端，WS Upgrade、CONNECT WS/WSS、认证、拆分与合并握手、
  首帧边界、压缩扩展、分片交错控制帧、拒绝/超时、长响应头、分配失败与关闭排空；需要 openssl 生成测试证书。
  `python3 tests/support/inbound/proxy/websocket.py build/solaris_proxy_inbound_tests --duration 310` 可追加 16 条并发连接的持续心跳验证。
- `tcp_relay_contract`：成功/失败/取消的 `on_connect` 恰好一次，含回调内关闭和写入排空。
- `routed_inbound_contract`：detached 接纳/退休、异步首包固定视图、一次本地解析、空闲重建、认证更新、队列满和迟到 DNS 取消。
- `runtime_proxy_contract`、`runtime_protocol_contract`：从 YAML 经公开 SDK 激活、事务回滚/更新、双 worker 与固定独立协议对端。
- `llhttp_private_symbols`、`installed_consumer`、模块裁剪检查：私有符号、依赖安装与独立静态/共享消费。
- `solaris_parser_fuzz` 的 parser id 21：HTTP 请求头、正文和 trailer，parser id 22 覆盖 Upgrade 响应及拒绝正文，均含分配失败；llhttp 本体也参与覆盖率与 ASan/UBSan 插桩。

规范参考：[RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html)、[RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html)、
[RFC 1929](https://www.rfc-editor.org/rfc/rfc1929.html)、
[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html)、
[RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html)。
