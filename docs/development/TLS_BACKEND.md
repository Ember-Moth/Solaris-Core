# TLS 后端与补丁边界

## 固定基线与构建

TLS/crypto 统一使用 BoringSSL 周期快照 **0.20261020.0**，对应提交
`d3bf4795ad5b79d646cddf2fec687da5b9b502db`。`dependencies/lock.json`
同时锁定版本、提交、归档 SHA-256、原始源码树 SHA-256，以及按顺序应用的补丁及其哈希。
上游快照没有稳定 ABI 或 LTS 承诺；更新必须重新完成本文件的验收，不跟随分支 HEAD。

构建先由 FetchContent 下载并核验归档，再由 `scripts/dependencies/boringssl.py`
验证完整原始树、复制到当前构建目录的 `_deps/solaris_bssl-patched`，逐个执行严格的
`git apply --check` 和 `git apply`。原始源码不修改；每次配置还会核验生成树，拒绝手工改动、
旧版本 source override、错误补丁哈希和不可应用补丁。补丁集变化从原始树重新生成，
不会在已修改的树上反复打补丁。交叉编译使用宿主 Python 3.9+ 和 Git。

可用 `FETCHCONTENT_SOURCE_DIR_SOLARIS_BSSL` 复用**同一锁定版本的原始树**，不能指向已打补丁的源码。
修改锁文件和补丁会触发 CMake 重新配置。BoringSSL 静态链接、使用 `solaris_bssl` 私有符号前缀，
不安装它的头文件，不在 Solaris 公共 SDK 暴露 `SSL *`。新增导出必须进入 BoringSSL 的两种
prefix table 并通过归档符号审计。旧的单体 `boringssl-reality.patch` 已由新设计替代。

## 分层与状态

协议认证在各自适配层；BoringSSL 补丁只提供无法用公开 API 安全表达的握手/记录能力。
Solaris TLS backend 继续拥有 SSL/BIO、有限输入队列、deadline、背压、取消和关闭屏障。
同一个连接只能选择一个认证 profile；Vision 是上层流处理，可以与经过验收的承载组合。
不得通过 BIO 输出后的任意字节修改来改变 Hello，也不得把认证失败转换为代理连接成功。

| 能力 | 补丁/接口决策 | 当前实现范围 |
| --- | --- | --- |
| ClientHello 固定字段认证 | `0001-client-hello-auth.patch` | 已实现，TLS 1.3 ClientHello random/session ID 和受限 X25519 派生 |
| Restls 首条加密记录试探与 Finished 交接 | 下文的记录事务接口设计 | 待随 Restls adapter 和独立对端一起实现；没有旁路开关 |
| JLS ServerHello 认证与证书签名替代 | 下文的认证状态接口设计 | 待随 JLS adapter 和独立对端一起实现；没有跳过 CertificateVerify 的通用开关 |
| REALITY/ShadowTLS/Restls/JLS 完整协议 | 独立 profile、认证、记录封装和配置工厂 | 尚未接入；底层 hook 的通过不等于这些协议已支持 |
| Vision raw | 已有 stream 的分方向 raw 接口 | 使用公开 TLS API 和有限单记录 feeder；不需要新增 BoringSSL patch |

完整协议仍按开发计划的安全/传输扩展任务验收。本次固定基线和补丁设计不改变 M1 的协议范围，
也不提前暴露尚无互通证据的配置字段。

## ClientHello 认证接口

`SSL_set_solaris_client_hello_callback` 只能在第一次握手前配置到单个 SSL，不能继承为进程全局策略。
调用方声明可替换 `random`、`session_id` 或二者；输出是两个定长 32 字节数组，没有任意扩展写指针。
回调同步执行，不允许重入 SSL，输入和输出指针只在回调内有效，context 由 backend 持有至 SSL 释放。

调用顺序：

1. BoringSSL 生成 random、session ID、key shares、扩展及完整四字节头的 ClientHello。
2. 如有 PSK，清零 binder 内容但保留原有长度前缀，将这份完整消息交给认证回调。
3. 回调计算协议字段；库只提交声明的字段，并同步 `client_random` 和内部 `session_id`。
4. 用上游 `tls13_psk_binder` 对最终 ClientHello 重新计算 binder，然后进入原有发送和 transcript 路径。

回调返回失败则不发送 ClientHello。未知 field、空回调、server 角色和握手中重配置会被拒绝。
启用此扩展时必须把最低/最高版本都设为 TLS 1.3；ECH、DTLS、QUIC、early data、重协商和
HelloRetryRequest 均明确失败。普通 TLS 没有这些额外限制。恢复模式可重新计算 binder，
但上层仍须对 ticket 的协议、身份、服务端和配置 generation 做隔离。

`SSL_solaris_client_hello_x25519` 仅在回调内可用，使用实际发出的独立 X25519 key share
与指定服务端公钥计算 shared secret。它拒绝不存在的 share、低阶公钥和回调外访问，
失败时清零输出；临时私钥在库内清理，调用方必须清理派生出的密钥。当前不从 hybrid share
拆取私钥，也不把任意 TLS 私钥导出给适配层。REALITY profile 需显式配置独立 X25519 share；
增加 hybrid/fingerprint 支持时要作为独立组合验证。

## 四种协议的接入设计

### REALITY

profile 用回调内的 X25519 结果、ClientHello random 前 20 字节和 `REALITY` info 派生认证密钥。
构造包含版本、保留位、时间及 short ID 的 16 字节明文，将 ClientHello 的 session ID 清零作为 AAD，
以 random 后 12 字节作为 nonce 生成 32 字节认证 session ID。协议版本和时间由 profile 提供，
不能把旧补丁中的固定版本字节留在 TLS 库中。

临时证书认证通过 BoringSSL 已有 custom verify API 实现：验证证书结构、Ed25519 公钥的认证值，
以及配置要求的附加签名；保留 TLS CertificateVerify 和 Finished 校验。
正常证书验证成功只表示连到了伪装站点，不能表示 REALITY 认证成功。未认证不得转发代理负载；
如实现伪装站点回退，必须有独立状态、限额及关闭路径。首个接入禁用 ticket/0-RTT；恢复、ML-DSA
和不同 key-share/fingerprint 组合各自增加验收，不能由普通 TLS 或 Vision 测试推导。

### ShadowTLS v3

profile 保留 28 字节随机 session ID，最后 4 字节暂时清零，计算完整 ClientHello 的 HMAC 后填入。
session ID 必须在 transcript 前同步。ServerHello/random 的读取可以用已有消息回调；
ShadowTLS 的 HMAC/XOR 记录封装位于 TLS 下方的有界 record wrapper，恢复给 TLS 的记录必须先通过
协议认证。完成真正的 TLS 握手后，按原有 raw 屏障交接，保留在途写、预读记录和未消费明文的顺序。

严格模式要求 TLS 1.3。伪装服务器的 TLS 证书验证与 ShadowTLS 服务端认证分别记录；认证不成立时
禁止打开代理通道。v1/v2、非严格 TLS 1.2 和用户数据记录 HMAC 不是 ClientHello hook 自带的功能。

### Restls

TLS 1.3 session ID 认证以 key-share 的 group/data 及 PSK identities 为输入，可由同一 Hello 回调完成。
Restls 的 keyed BLAKE3、记录脚本、方向计数、长度掩码及 HMAC 均在 adapter；不塞进 BoringSSL。
参考实现还依赖以下两个能力，需要作为第二个补丁单独实现和验收：

- **首条受保护记录的事务试探**：在 read cipher 已安装、序号尚未推进时，提供有界密文副本给 profile
  做 XOR 还原。候选记录必须经过原有 AEAD 验证。仅候选成功才能推进序号和标记认证；候选失败要丢弃
  试探明文及其错误栈，不污染原始密文或 cipher 状态。若继续验证原始 TLS 记录，只能进入未认证回退状态。
  接口不得允许 callback 直接声称解密成功或提供未经 AEAD 验证的明文。首版限 TLS 1.3 AEAD；CBC/SSLv3 不适用。
- **Client Finished 的精确 wire 交接**：在握手消息封装为记录时标记覆盖 Finished 的所有输出记录，
  将有界副本交给 profile，并在实际 carrier 写完成后确认屏障。不能假定一次 BIO write 恰好是一条 Finished，
  不能把明文 Finished 当成协议所需的密文记录，也不能重发已经提交的记录。

完成认证和 Finished 写屏障后，Restls 自己接管应用记录；普通 TLS NewSessionTicket、alert 与伪装站点
数据的分流仍需按协议处理。TLS 1.2 不是修改 min-version 就能支持：它还要求提前生成并保留客户端 ECDHE
key，按 group/public key 和 ticket 构造认证 session ID，并处理显式 GCM nonce 与恢复握手顺序。
这部分要设计独立 eager-key 接口并与 TLS 1.2 对端验证，不能复用只有 TLS 1.3 证据的 hook 宣称可用。

### JLS v3

profile 将 ClientHello random 和 PSK binders 清零后构造认证输入，按 username/password 派生的
key/nonce 生成 FakeRandom；禁止产生协议保留的 downgrade/HRR 后缀。第一层补丁保证最终 binder
与替换后的 random 一致。ServerHello 认证使用原始消息且只清零 random，禁止 HRR。

JLS 的伪装证书机制还需要第三个补丁：在 ServerHello 解析完成、转入证书处理之前执行同步认证回调，
建立只属于本次握手的 `unauthenticated → authenticated` 状态。只有认证成功的 JLS profile 才能采用
其证书链/CertificateVerify 替代规则；消息结构、signature 字段边界、transcript 和 Finished 验证仍保留。
失败不降级成“忽略证书错误”，也不能在 SSL_CTX、复用 SSL 或其他连接间继承认证状态。
该状态由完整协议认证产生，不提供随意设置 `authenticated=true` 或全局 `skip_verify` 的公开 API。

ticket 必须绑定 JLS 身份、服务端、协议版本及配置 generation，并在接收时记录已认证来源；
普通 TLS ticket、其他用户 ticket、过期或旧配置 ticket 都不能提升为 JLS 会话。
导出/恢复时也必须保留这个约束，无法证明绑定则丢弃恢复。首个 adapter 可以拒绝恢复模式；
启用恢复必须另测 binder、两端身份认证和 ticket 隔离。

## 验收与升级

已经存在的底座测试：`tls_recipe_contract` 检验干净应用、重复配置、原始树/补丁/结果树篡改、
版本切换重建和应用失败保护；`tls_patch_contract` 检验真实 TLS transcript、TLS 1.3 ticket 恢复与
零 binder 输入、实际 key-share 一致性、低阶公钥、拒绝回调、错误证书/hostname、HRR、版本和时序限制。
后者使用内存 BIO 的 BoringSSL 两端，不把它作为四种协议的独立互通证据。

每次升级版本或修改补丁还必须运行：普通 TLS 1.2/1.3 独立对端、Vision raw/缓冲交接、现有协议全套、
私有符号与安装消费、ASan/UBSan/TSan、静态裁剪。新增协议再增加固定版本的独立服务端及同对端控制，
覆盖错误密码/short ID、时钟边界、篡改、重放、分片/粘包、PSK/HRR/ECH 拒绝、取消与真实写完成屏障。
Restls 记录试探必须证明失败不改变序号或消耗原记录；JLS 必须证明未认证、旧 ticket 和错误身份不能触发签名替代。
未通过这些门槛的补丁不进入默认 series，未验证的协议不进入支持矩阵。

固定参考：

- [BoringSSL 上游集成约定](https://github.com/google/boringssl/blob/d3bf4795ad5b79d646cddf2fec687da5b9b502db/INCORPORATING.md)
- [Xray REALITY 客户端](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/transport/internet/reality/reality.go)
- [ShadowTLS v3](https://github.com/ihciah/shadow-tls/blob/02dd0bc7bae8a2011729f95021690e694fd8e43e/docs/protocol-v3-en.md)
- [Restls Hello](https://github.com/MetaCubeX/restls-client-go/blob/6566c5f8a24420fbaeb27bc74deea2597a30f4a7/handshake_client.go)、[记录层](https://github.com/MetaCubeX/restls-client-go/blob/6566c5f8a24420fbaeb27bc74deea2597a30f4a7/conn.go)
- [JLS 认证](https://github.com/MetaCubeX/jls-tls/blob/67adc0e2f79630fcf80f0b65278d4d1a094b812b/jls.go)、[TLS 1.3 证书路径](https://github.com/MetaCubeX/jls-tls/blob/67adc0e2f79630fcf80f0b65278d4d1a094b812b/handshake_client_tls13.go)
