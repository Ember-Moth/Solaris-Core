# TUN 内部接入

入口是 `src/contracts/inbound/tun.h`。当前接口供内核模块集成，尚未进入 `include/solaris/` 和公开 SDK 导出；没有 YAML TUN 配置入口。完整系统 VPN 还需要宿主负责权限、接口配置、出站保护和平台生命周期。

## 选择协议栈

| backend | TCP 路径 | 使用条件 |
| --- | --- | --- |
| `SOLARIS_TUN_STACK_LWIP` | lwIP 2.2.1 raw TCP 状态机，独立处理握手、窗口、重传和 FIN | 每进程同时一个实例，所有调用固定同一 owner；第二个实例返回 EBUSY，前一个 on_close 后可重建 |
| `SOLARIS_TUN_STACK_SYSTEM` | 改写 IP/端口到本机 TCP listener，再从接受的 socket 恢复原始目标 | 宿主必须先配置接口地址和不同的 peer 地址，以及到 peer 的回注路由；禁止 `include_all_networks`，明确返回 ENOTSUP |

system 的映射仅由合法初始 SYN 建立，绑定源/目标四元组，接受连接时校验 peer 和映射代际；回包恢复原始地址并重算校验和。正常双向关闭后仍保留映射 120 秒，供内核尾部数据/FIN 重传及迟到 ACK 使用；期间拒绝同 tuple 的新 SYN，普通 idle 不提前回收，也不通过收到报文延长保留期。RST 的序号有效性由系统 TCP 校验，NAT 层不会仅凭 RST 标志关闭流。映射释放后端口再隔离 120 秒，防止旧 TCP 包落入新连接。lwIP 的正常双向关闭保留 TCP 排空及 TIME_WAIT 所需映射；两种栈关闭后保留的槽位均计入 flow_limit，显式关闭入站或 engine stop 会立即回收，不等待 TIME_WAIT。

两种 backend 共用 TCP relay 与 UDP association。选路 callback 为每个 TCP flow/UDP association 返回一个持有引用的 `solaris_dial_plan_t`，目标变化不重新选择既有 UDP association 的 plan。relay 使用有界队列、读暂停和 ordered write，等待通道及已接纳回调排空后释放 plan。出站自身没有 HALF_CLOSE 能力时，TUN 不能创造该能力。

## 宿主 packet I/O

在目标 owner 上初始化 options，调用 `solaris_tun_options_init`，填写：

- `owner`、`context`、`select` 和 `on_close`。
- 至少一个 `address4` / `address6`；不启用的地址族保持 family=0。system 还需要 `peer4` / `peer6`。
- `device.kind=0` 与 `emit`，使用裸 IP 包收发；lwIP 的 MTU 至少 1280；system 的 IPv4 可低至 576，启用 IPv6 时至少 1280。

宿主把输入拷贝或保留到 owner 执行时，再调用 `solaris_tun_input`。输入和 emit 的 packet 指针只借用到函数返回；异步写入必须自行复制。emit 返回 EAGAIN 表示有界输出拥塞，TCP 由栈重传；UDP 不自动重放。input/emit 内同步重入 input 返回 EBUSY，新的包应排队到 owner；emit/select 内允许关闭。

关闭前停止生产者并排空或撤销宿主排队的输入。排队任务执行时检查宿主保存的 live handle 和 generation，不能捕获裸指针并跨过 on_close 使用。`solaris_tun_close` 开始排空；`on_close` 是内部 device、stack、TCP、UDP 和已接纳 I/O 的最后屏障，返回后句柄失效。宿主自行排队的任务不属于这个屏障。engine stop 使用相同取消路径。

默认上限：512 个 TCP 槽位、512 个 UDP association、每关联 64 个目标映射、256 KiB 待处理字节及 64 个待处理包，idle 60 秒、open 10 秒。lwIP 内部分配也计入 owner budget；预算不等于整个进程 RSS。

## 平台设备

设备公共契约在 `src/contracts/inbound/tun_device.h`。只有显式调用设备 open 才可能创建设备；库不修改系统 MTU、地址、路由、DNS 或代理设置。

| 平台/来源 | options 与行为 |
| --- | --- |
| 已有 POSIX packet fd | `SOLARIS_TUN_DEVICE_FD`；必须已 nonblocking，core dup 并仅关闭副本，宿主保留原 fd；普通文件拒绝 |
| macOS native utun | `SOLARIS_TUN_DEVICE_NATIVE`；使用 PF_SYSTEM/SYSPROTO_CONTROL，读取实际 utun 名；收发处理 4 字节网络序 AF 前缀 |
| iOS / NetworkExtension | native 创建返回 ENOTSUP；使用公开 NEPacketTunnelFlow 的 read/write 包回调接裸 IP 接口。也可接受宿主合法持有的 packet fd，不使用私有 KVC 查找 fd |
| Linux native TUN | `SOLARIS_TUN_DEVICE_NATIVE`；打开 `/dev/net/tun`，设置 `IFF_TUN|IFF_NO_PI`，权限由宿主提供 |
| Windows Wintun | `SOLARIS_TUN_DEVICE_WINTUN`；宿主提供匹配架构的可信 DLL 绝对路径；有界 ring 队列和等待线程，关闭先退出/join 等待线程再结束 session/释放 adapter |

FD 的 `SOLARIS_TUN_FRAMING_IP` 表示裸 IP；Apple utun fd 使用 `SOLARIS_TUN_FRAMING_DARWIN`。NEPacketTunnelFlow 交付的包已经是裸 IP，不加 AF 前缀。Wintun DLL 不随 Solaris 分发；打开已有 adapter 时只释放句柄，库新建的 adapter 随关闭移除。

lwIP 可在入站 options 中直接指定 native 设备，成功后通过 `solaris_tun_name` 获取实际名称，宿主再配置网络。system 的 listener 必须绑定已配置地址，因此单阶段 `native/Wintun + system` 明确返回 ENOTSUP。接入 system 的顺序是：宿主先通过设备 API 打开接口、取得设备名称并配置地址/peer/路由，再用预配置 FD 或 packet I/O 创建入站。packet I/O 模式的 emit 转发到设备 write；设备 on_packet 在入站就绪后才调用 input。设备关闭与宿主配置回滚由宿主协调。

出站 socket 的保护/路由绕行使用已有 dialer preparation 服务；否则可能把代理服务器连接重新送入 TUN。iOS `includeAllNetworks` 使用 lwIP，不悄悄切换到不兼容的 system backend。

## 报文范围

IPv4/IPv6 TCP、UDP 校验总长度、校验和及支持的扩展头。IPv4 source-route、IPv6 routing/fragment/AH/ESP、输入 IP 分片明确拒绝，不声称重组。UDP 支持空包与多目标固定 association；超过 MTU 的 UDP 回复分片输出，部分输出失败视为丢包，不重放已输出片段。ICMP echo 只回复配置的接口地址，不伪造远端可达性；ICMP 错误转译、PMTU discovery、sniff、DNS/Fake-IP 尚未实现。

## 构建与验证

`SOLARIS_ENABLE_TUN`、`SOLARIS_ENABLE_TUN_LWIP`、`SOLARIS_ENABLE_TUN_SYSTEM` 默认开启。关闭 TUN 会同时裁剪两种栈；关闭 lwIP 后不链接其依赖。lwIP revision、archive SHA256 与 sing-tun v0.9.6 参考 revision 固定在 `dependencies/lock.json`。lwIP 使用私有符号前缀，BSD 许可证随 SDK 安装；sing-tun 是平台行为与 system NAT 的参考，不链接其 Go runtime。

本机测试入口：`ip_packet_contract`、`tcp_relay_contract`、`tun_inbound_contract`、`tun_lwip_contract`、`tun_system_contract`、`tun_fd_contract`、`tun_wintun_contract`。它们分别覆盖独立包校验/改写、背压和迟到回调、真实 TCP/UDP 回环转发、raw TCP 重传/FIN、system NAT/假冒 accept、FD framing 和模拟 Wintun ring。测试不创建设备、不更改主机网络。

已执行本机 Debug、相关 ASan/UBSan 和 TSan、Apple/Windows 的可用编译检查；这些不能替代真实 utun、NetworkExtension、Linux TUN、Wintun 驱动及 VPN 路由验证。公开绑定、真机前后台/网络切换和持续性能验收仍属于后续工作。
