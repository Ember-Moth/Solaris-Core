# TLS 后端与补丁边界

更新日期：2026-11-06。本文描述已实现的私有 TLS 库能力及其调用约束；生产出站/配置接入仍由对应协议模块完成。

## 固定基线与构建

统一使用 BoringSSL 周期快照 **0.20261020.0**，提交
`d3bf4795ad5b79d646cddf2fec687da5b9b502db`。`dependencies/lock.json`
锁定版本、提交、归档和原始源码树 SHA-256、补丁顺序与各补丁哈希，当前 patch ABI 为 5。
上游快照没有稳定 ABI 或 LTS 承诺；更新后要重新完成下述验证。

FetchContent 校验归档，`scripts/dependencies/boringssl.py` 再验证原始树，复制到当前构建目录的
`_deps/solaris_bssl-patched`，执行严格的 `git apply --check` 和 `git apply`。
每次配置校验生成树，拒绝源码/补丁/结果树篡改；补丁变更从干净基线重新生成。
`FETCHCONTENT_SOURCE_DIR_SOLARIS_BSSL` 只能指向同一版本的原始树。
宿主需要 Python 3.9+ 和 Git，交叉编译也在宿主完成这些步骤。

BoringSSL 静态链接并使用 `solaris_bssl` 符号前缀，不安装其头文件，也不在 Solaris 公共 SDK 暴露 `SSL *`。
新增接口在两套 prefix table 中登记，归档符号和安装消费测试继续检查隔离。

## 已实现的补丁

| 顺序 | 文件 | 能力 |
| --- | --- | --- |
| 1 | `0001-client-hello-auth.patch` | ClientHello random/session ID 定长认证回调；内部状态、wire、transcript 和 PSK binder 同步 |
| 2 | `0002-record-auth-and-finished.patch` | 首条受保护记录的 AEAD 事务试探、原记录回退、精确 Client Finished 密文记录捕获 |
| 3 | `0003-peer-auth-and-session-binding.patch` | ServerHello 认证后的证书认证替代；绑定身份、SNI 和配置代际的可序列化恢复票据 |
| 4 | `0004-eager-and-hybrid-key-shares.patch` | TLS 1.2 提前生成并复用 X25519/P-256/P-384；TLS 1.3 hybrid 中的 X25519 派生 |
| 5 | `0005-disable-client-resumption.patch` | 按连接禁止 TLS 1.2/1.3 恢复、ticket/PSK 广告和缓存回调 |

所有设置只作用于单个 SSL，必须在第一次握手前完成；普通 TLS 不启用这些扩展。
回调同步执行，输入和借用输出仅在约定期间有效，不得重入握手/I/O 或释放 SSL。
调用方持有 callback context 至 SSL 释放。认证状态属于当前连接，不在 SSL_CTX 或不同连接间继承。
带 ClientHello 认证回调的连接重建使用新的 SSL；`SSL_clear` 会清除认证结果，旧 Hello 回调不能在同一对象重跑。

密码、认证消息和数据封装留在协议层。补丁没有新增 registry 类型、YAML 字段或占位成功路径。
本次测试中的协议客户端位于 `tests/support/transport/tls_profiles/`，不进入发布库。
Vision 继续使用已实现的分方向 raw 接口，不需要额外修改 BoringSSL。

## ClientHello 与 key share

`SSL_set_solaris_client_hello_callback` 接收完整 ClientHello（含四字节握手头），仅允许替换声明的
32 字节 random/session ID。库更新内部 `client_random`/`session_id` 后再进入 transcript。
有 PSK 时，回调输入的 binders 先清零但保留长度前缀，提交字段后使用上游 binder 算法重新计算。
失败不发送 ClientHello；未知 flags、空回调、握手中重配置均拒绝。

TLS 1.3 要求固定 min/max 为 1.3；TLS 1.2 必须同时启用 eager key share 且固定版本为 1.2。
ECH、DTLS、QUIC、early data、重协商和 HelloRetryRequest 不与 Hello 认证组合。

- `SSL_solaris_client_hello_x25519` 使用独立 X25519 share，保持原接口语义。
- `SSL_solaris_client_hello_x25519_for_group` 显式选择独立 X25519 或 X25519MLKEM768 的 X25519 部分。
  派生在拥有私钥的 key-share 对象内完成，不导出或消耗私钥；低阶点、缺失 share 和回调外调用失败并清零输出。
- `SSL_set1_solaris_eager_key_shares` 配置最多三个不重复的 X25519/P-256/P-384，在 TLS 1.2 Hello 前生成。
  `SSL_get0_solaris_eager_key_share` 仅在 Hello 回调内借用编码后的公钥。
  ClientKeyExchange 使用选中组的同一密钥；未准备的组、静态 RSA/PSK 套件拒绝，不能重新生成另一把密钥。
  仅 session ID 的 TLS 1.2 恢复被丢弃并重新完整握手；ticket 恢复仍可用。

## 记录认证与 Finished

`SSL_set_solaris_record_auth_callback` 只处理第一条完整受保护的服务端记录。
支持 TLS 1.2/1.3 的 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305；CBC 不进入试探。

1. 保留原始 header、密文、cipher 和 sequence，给回调一份有界密文 body 副本。
2. 回调只能改副本，不能改变 header、长度或序号，也不能直接提交明文或宣称 AEAD 成功。
3. 使用当前 AEAD 验证候选。成功才把明文放回库自己的输入缓冲，并按原路径推进一次序号。
4. 候选失败清理临时明文和本次试探的错误。默认终止；显式 `SSL_SOLARIS_RECORD_ALLOW_FALLBACK`
   才会验证未修改的原记录，回退成功仍是未认证状态。

`SSL_get_solaris_record_auth_result` 在回调中和握手未完成时返回 PENDING；候选失败返回 REJECTED；
仅在候选验证和完整 TLS 握手均成功后返回 OK。证书链、身份、CertificateVerify 和 Finished 校验仍保留。

`SSL_enable_solaris_client_finished_capture` 把 Client Finished 隔离成自己的完整 TLS 记录，保存准确密文，
总量上限 4096 字节；BIO 分片或 WANT_WRITE 重试不会重复捕获。
`SSL_get0_solaris_client_finished` 在完整握手成功且 flight 已提交到 BIO 后提供借用视图。
使用内存 BIO 时，调用方还必须等真实 carrier write 完成，才能发送协议后续数据或进行 raw 切换。
Solaris 现有 TLS/stream 屏障在后续协议接线中仍须保持。

## ServerHello 认证与恢复隔离

`SSL_set_solaris_peer_auth_callback` 用于 JLS 一类替代证书认证的 TLS 1.3 profile，必须同时配置 RANDOM Hello 回调。
它接收已完成结构解析的原始 ServerHello；回调必须对本次消息做密码认证。
只有返回成功的当前握手才能采用替代链认证和 CertificateVerify 签名验证路径。
签名消息的结构、非空签名、允许的算法及公钥类型检查保留，transcript 和 Finished 验证始终保留。
认证失败直接终止，不以普通证书成功作为协议成功。

`SSL_get_solaris_peer_auth_result` 仅在认证和完整握手完成后返回 OK。
替代认证下 `SSL_get_verify_result` 保留 `X509_V_ERR_APPLICATION_VERIFICATION`，不伪装为 PKIX 验证通过。
record auth 与 peer auth 互斥；peer auth 不与 eager TLS 1.2、ECH、DTLS、QUIC、early data、PAKE 或重协商组合。

设置时传入 32 字节 `identity_context`，代表协议、用户、逻辑服务端和配置 generation，不放入密码材料。
库还自动绑定本次 SNI。收到 ticket 后，用该 ticket 的 PSK 为上下文生成标记，保存为私有 ASN.1 `[100]` 字段。
序列化和 session 复制保留标记，握手配置释放后仍能正确签发标记；字段长度、版本、客户端角色和 QUIC 标记严格校验。

普通 TLS ticket 不升级为替代认证 ticket，替代认证 ticket 不进入普通 TLS 恢复。
身份/generation/SNI 不一致或标记改变时不发送 PSK，仍以已选 profile 完成新的完整认证握手。
恢复时也重新认证 ServerHello。session 对象的可信存储由调用方负责。

## 禁用恢复

`SSL_disable_solaris_resumption` 丢弃提供的 session，不发送 TLS 1.2 session-ticket、TLS 1.3
pre_shared_key/psk_key_exchange_modes 扩展，不向调用方交付可缓存的新 ticket/session。
收到的 TLS 1.3 ticket 仍按正常消息语法处理，但不触发缓存回调；配置释放后策略仍有效。
外部 PSK、PAKE、early data、DTLS、QUIC 和重协商组合明确拒绝。
普通连接及其他 SSL 对象的恢复行为不受影响。

这是 REALITY/ShadowTLS profile 的必要设置。上游 `SSL_OP_NO_TICKET` 只控制 RFC 5077，不能代替 TLS 1.3 策略。
对完整 Hello 认证的协议不能在回调后再引入会改变认证输入的 PSK binder。

## 协议映射与验证范围

| 协议 | 使用的能力与约束 | 已验证的 TLS 层范围 |
| --- | --- | --- |
| REALITY | Hello SID、显式组 ECDH、已有 custom certificate verify、禁用恢复；显式允许 Ed25519，保留真实 CertificateVerify | 当前 Xray 引用的 REALITY 服务端；hybrid-only 与 hybrid+X25519；错误 key/short ID/时间和签名算法拒绝 |
| ShadowTLS v3 | Hello SID HMAC、禁用恢复；TLS 下方的 HMAC/XOR wrapper 和握手后的独立数据 HMAC | 严格 TLS 1.3、真实证书/身份校验、双向数据、错误密码和身份拒绝 |
| Restls | Hello SID、record probe、Finished；TLS 1.2 使用 eager public keys | TLS 1.3 完整/恢复，TLS 1.2 X25519/P-256/P-384 完整/恢复，双向数据；错误密码/身份、未认证回退拒绝转发 |
| JLS v3 | Hello random、peer auth、PSK binder 和身份标记 | 完整/恢复/序列化/复制/配置释放；不同用户/SNI/generation 隔离，错误凭据、SH、空签名、未知算法和错误 Finished 拒绝 |

Restls 的 XOR 只修改指定位置起的前 16 字节；TLS 1.2 GCM 的显式 nonce 处理由 profile 决定。
Client Finished 参与首个应用记录认证的情形是 TLS 1.3 和 TLS 1.2 恢复；TLS 1.2 完整握手不加入该项。
当前 REALITY 引用要求先提供 X25519MLKEM768，可再提供 X25519；测试 profile 明确选择服务端使用的认证 share。

以上证明补丁可以承载相应握手和数据交接。生产协议 outbounds、YAML 配置、浏览器指纹、REALITY 附加 ML-DSA 策略、
ShadowTLS 非严格/旧版本等功能仍按对应适配任务单独交付，不从这些 TLS 测试推导。

## 验证入口

- `tls_patch_contract`：Hello/transcript、PSK binder、身份/版本/HRR 与 callback 生命周期。
- `tls_record_patch_contract`：三种 AEAD 的 TLS 1.2/1.3 候选成功、原记录回滚、篡改/回调失败、CBC 拒绝；7 字节 BIO 写、3 字节输入和精确 Finished。
- `tls_key_patch_contract`：提前生成的公钥与实际 ClientKeyExchange 一致、TLS 1.2 ticket 与 session-ID 行为、缺失组及 hybrid 派生。
- `tls_resumption_patch_contract`：线上的扩展、输入 session 丢弃、缓存抑制、普通连接不受影响与 early-data 拒绝。
- `tls_policy_patch_contract`：参数/输出归零、DTLS/QUIC/ECH、认证模式冲突和外部 PSK 拒绝，失败前不输出 Hello。
- `tls_profiles_interop_contract`：固定独立 Go 服务端的 53 个场景；包括由真实流量密钥重新生成合法 AEAD 标签的错误 Finished/签名算法。
- `tls_recipe_contract`、`crypto_symbols`、`installed_consumer`：补丁完整性、隔离和 SDK 消费。
- parser fuzz 的 session 入口使用独立握手生成的 ticket，检查扩展后的 session 解析和序列化往返；运行方式见 [测试规范](TESTING.md)。

升级或修改补丁还需运行普通 TLS、Vision raw、现有协议、共享/静态安装消费、ASan/UBSan、TSan 和裁剪检查。
实际结果见 [开发计划](DEVELOPMENT_PLAN.md)。

固定参考：

- [BoringSSL 集成约定](https://github.com/google/boringssl/blob/d3bf4795ad5b79d646cddf2fec687da5b9b502db/INCORPORATING.md)
- [Xray REALITY 客户端](https://github.com/XTLS/Xray-core/blob/a4a3dff5b20c2faae567b742c172c7b95e75c083/transport/internet/reality/reality.go)
- [ShadowTLS v3 规范](https://github.com/ihciah/shadow-tls/blob/02dd0bc7bae8a2011729f95021690e694fd8e43e/docs/protocol-v3-en.md)
- [Restls 握手](https://github.com/MetaCubeX/restls-client-go/blob/6566c5f8a24420fbaeb27bc74deea2597a30f4a7/handshake_client.go)、[记录与服务端](https://github.com/MetaCubeX/restls-client-go/blob/6566c5f8a24420fbaeb27bc74deea2597a30f4a7/restls_server.go)
- [JLS 认证](https://github.com/MetaCubeX/jls-tls/blob/67adc0e2f79630fcf80f0b65278d4d1a094b812b/jls.go)

实际对端的 Go module 版本和 checksum 固定在 `tests/support/transport/tls_profiles_peer/go.mod`、`go.sum` 与依赖 lock。
