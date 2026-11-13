# 当前 C SDK：配置、控制、观测与生命周期

本页保留现有 SDK 与 YAML 宿主的使用说明。项目已选择独立内核与 Solaris Conf `.conf`，但原生入口尚未切换，不能将下方 YAML 样例直接改扩展名后使用。
迁移任务见 [CFG 计划](DEVELOPMENT_PLAN.md#21-原生配置迁移与近期优先级)，原生目标规范见 [配置与宿主 SDK](CONFIGURATION_AND_SDK.md)；实现状态以开发计划为准。

## 构建与使用

需要 CMake 3.24+、C11 编译器；测试还需要 Python 3.9+ 和 C++11 编译器。首次配置下载 lock 指定的 libuv、libyaml 及启用模块的依赖，之后同一构建目录可复用依赖。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --config Debug --parallel
ctest --test-dir build --build-config Debug --output-on-failure
cmake --install build --config Debug --prefix "$PWD/build/install"
```

默认共享库；静态构建增加 `-DBUILD_SHARED_LIBS=OFF`。测试/示例可分别通过 `SOLARIS_BUILD_TESTS`、`SOLARIS_BUILD_EXAMPLES` 关闭。Sanitizer 配置使用独立构建目录和 `-DSOLARIS_SANITIZER=address`（ASan/UBSan）或 `thread`，需要支持的 Clang/GCC 工具链。

原生共享库按平台命名为 macOS `libsolaris.dylib`、Linux `libsolaris.so` 或 Windows `solaris.dll`。Apple XCFramework 与移动平台打包不属于当前最小 SDK，按后续平台阶段交付。

安装后：

```cmake
find_package(Solaris CONFIG REQUIRED)
target_link_libraries(my_host PRIVATE Solaris::core)
```

包含 `<solaris/core.h>`，或按需包含 config/control/observe/probe/log/engine/error/version 头文件。静态安装的私有依赖归档需要一并保留，链接由导出目标完成；共享包包含其私有实现，不向宿主暴露 libuv/libyaml API。

## 安装后的 C 配置宿主

安装包的 `share/Solaris/examples/config-host` 包含纯 C11 宿主、两份 loopback YAML 和独立 CMake 工程。
可将该目录复制到任意位置，用安装前缀构建；源码仅包含公开的 `<solaris/core.h>`：

```sh
cmake -S /path/to/config-host -B host-build -DCMAKE_PREFIX_PATH=/path/to/solaris-sdk
cmake --build host-build
./host-build/solaris_config_host /path/to/config-host/config_host.yaml --ephemeral
```

`--ephemeral` 将已启用的监听显式覆盖为临时端口，输出 configured/requested/actual；不改变 YAML 端口 0 的禁用语义。
`--trust CA.pem` 提供 TLS/HTTPS 的显式信任。命令支持 `nodes`、`mode`、`select`、`probe`、`connections`、`traffic`、
`logs`、`close`、`load`、`stop` 和 `start`；失败 load 保留旧配置，EOF/quit 排空并销毁。
完整语法见 [样例说明](../../examples/config_host/README.md)。`installed_consumer` 会从搬迁后的包复制、独立构建并运行此样例。

## 已实现入口

| 函数 | 行为 |
| --- | --- |
| `solaris_engine_options_init` | 填充 worker、队列、资源和预算默认值 |
| `solaris_engine_create` | 同步创建，复制 options/host；失败输出 NULL |
| `solaris_engine_start` | 异步激活 I/O workers，进入新 generation |
| `solaris_engine_stop` | 关闭 I/O admission 并等待资源/回调排空；重复 stop 仍完成一次操作 |
| `solaris_engine_get_snapshot` | 拷贝状态、控制操作计数、generation、worker 数与 I/O 预算统计 |
| `solaris_engine_cancel` | 请求取消尚未完成的非生命周期操作；已确定结果返回 ECLOSED，start/stop 不支持取消 |
| `solaris_engine_flush` | 等待入口时已接受操作及其回调完成 |
| `solaris_engine_destroy` | 关闭新操作，取消排队操作，等待回调/线程退出并释放 |
| `solaris_status_string` | 返回静态状态说明 |
| `solaris_version_string` | 返回产品版本字符串 |

公开 SDK 通过离线 YAML 编译、prepare、commit 激活 HTTP/SOCKS5/mixed 代理；下文说明资源和事务边界。
模式与节点选择、连接查询与关闭、流量、单次测速及日志通过下述公开接口访问；TUN 的宿主业务 API 继续后续工作包。
内部 Direct 与系统 resolver 的边界见 [M1 实现说明](M1_DATA_PATH.md)。

## 离线 YAML 编译

`solaris_config_compile_bytes` 编译有界内存中的 YAML，`solaris_config_compile_file` 读取一份有界文件再编译。
这两个入口是同步操作，应在宿主工作线程调用；不解析域名、建立 TLS、拨号或绑定监听端口。
成功只表示产生不可变配置 image。编译失败时 config 为 NULL，诊断对象仍可能存在，必须释放。

```c
#include <solaris/core.h>
#include <stdio.h>

int inspect_config(const char *path) {
    solaris_config_options_t options;
    solaris_config_options_init(&options);
    solaris_config_t *config = NULL;
    solaris_diagnostics_t *diagnostics = NULL;
    solaris_error_t error;
    solaris_status_t status = solaris_config_compile_file(
        path, &options, &config, &diagnostics, &error);
    for (size_t i = 0; i < solaris_diagnostics_count(diagnostics); ++i) {
        solaris_config_diagnostic_t item;
        if (solaris_diagnostics_get(diagnostics, i, &item) == SOLARIS_OK)
            fprintf(stderr, "%s:%u:%u %s: %s\n", item.source,
                item.line, item.column, item.path, item.message);
    }
    solaris_diagnostics_release(diagnostics);
    if (status != SOLARIS_OK) return 1;
    solaris_config_snapshot_t snapshot;
    status = solaris_config_get_snapshot(config, &snapshot);
    solaris_config_release(config);
    return status == SOLARIS_OK ? 0 : 1;
}
```

输入 bytes、options 字符串和 parser 生命周期均不被 image 借用。config/diagnostics 的 retain/release 可跨线程使用；
`get_snapshot`、`get_node`、`diagnostics_get` 返回调用者持有的纯值拷贝，公开节点信息不含密码。
`fingerprint` 是不包含凭据的非加密结构摘要，不能用于判断完整配置相等、跳过认证更新或安全校验。
`source_name` 用于诊断，`base_directory` 用于资源引用；file 入口默认使用 YAML 所在目录。
编译不读取证书或客户端密钥。TLS 的宿主 trust 在 prepare 中注入，不能把 mihomo 的客户端 `certificate/private-key` 当作 CA。

输入字节、总分配预算、单字符串、递归深度、节点、alias 展开和诊断条数分别有上限，使用 options 初始化函数取得默认值。
多文档、循环 alias、重复 key、未知转发功能与未编入模块明确报错；支持的范围和刻意差异见[兼容矩阵](COMPATIBILITY.md)。

## 代理配置的准备与提交

| 函数 | 行为 |
| --- | --- |
| `solaris_engine_prepare_config` | 接纳后持有 image、复制 PEM 和监听覆盖参数，在所有 worker 创建模块及候选监听；成功回调交出 owned prepared handle |
| `solaris_engine_commit_config` | 以 prepared 的 base revision 做 CAS，原子发布全部入口与选路配置；返回 applied revision |
| `solaris_prepared_config_get_snapshot/get_listener` | 拷贝候选状态、运行 generation、base/applied revision 与真实监听地址 |
| `solaris_prepared_config_retain/release` | 跨线程管理候选元数据；释放最后一个未提交引用会异步放弃候选资源 |
| `solaris_engine_get_config_snapshot/get_bound_listener` | 读取当前配置和实际监听，读取列表时携带 active revision 防止跨版本拼接 |
| `solaris_config_get_listener` | 获取离线监听 ID、名称和编译地址；尚未分配 worker，`worker_id=UINT32_MAX` |

接入顺序：

1. 在宿主工作线程离线 compile，并处理诊断。
2. start engine，等待 start 的结果；仅有 RUNNING 不能说明代理就绪，首次提交前 `active_revision=0`。
3. 初始化 `solaris_config_prepare_options_t`，调用 prepare。API 接纳后可立即释放调用方的 image、PEM 和覆盖参数。
4. prepare 成功回调取得一个 owned handle，检查实际绑定地址，再调用 commit。commit 接纳会额外持有 handle，调用方可立即 release。
5. commit 成功的 revision 才表示新业务配置生效。prepare 失败或未发布的 commit 失败保持原 active 配置。

prepare 必须在已启动的 runtime 上执行。它可提前绑定并 listen，但候选端口不接纳代理协议业务；外部 TCP 握手可能成功后被关闭。
每个物理监听由固定 worker 接纳；多个监听可分布到多个 worker。每个 worker 都有完整模块实例，单端口尚无跨 worker 接纳分发。
`udp: false` 同时过滤选路能力并拒绝实际 datagram open。

普通 TLS 节点要求 `trust_pem/trust_length` 提供显式 CA PEM，最多 256 KiB；缺失、无效或身份不匹配均失败。
库不自动读取系统根证书，不关闭验证。YAML 外部证书资源、客户端证书以及额外 TLS 组合仍按兼容矩阵逐项接入。

宿主可用 `bindings` 按已存在的 listener ID 覆盖数字地址和端口。地址 NULL 保留编译地址，端口 0 明确请求临时端口；
这与顶层 YAML 端口 0 表示禁用不同。公开监听快照同时提供 configured、requested 和实际地址/端口，以及 `binding_overridden`。
固定端口相同的物理监听可以复用，逻辑入口交换端口和认证变更在 commit 一次切换；通配地址与具体地址的重叠变更返回 ENOTSUP，需 stop/start。

同一 engine 同时只执行一项 prepare；另一项开始执行时若已有 prepare，会以 EBUSY 完成。可以依次准备并持有多个候选。
base revision 在 prepare 开始执行时固定，后台工作期间发生的提交不会改变它；先成功提交的候选推进 revision，其余旧 base 候选 commit 返回 EAGAIN 并撤销。
commit 开始前取消不会消耗 handle；开始后候选为一次性。取消与发布共享线性化边界，发布后不能被报告为未应用的取消。
typed callback 在控制 owner 执行，先于通用操作事件；失败 error 借用到回调返回。prepare 必须提供 callback，commit callback 可省略。
失败回调等待候选资源排空，避免失败后端口仍被本次候选占用。

旧 TCP 在接纳时固定配置，包括尚未完成握手的连接。旧 UDP association 固定 plan，可以继续创建新的目标映射或地址族通道；
提交后先释放旧物理监听引用，再等待存量连接和 plan 排空后退休模块。现存 SOCKS5 UDP 控制连接在新建 association 时按逻辑入口 ID 查询新配置；
入口删除、禁用 UDP 或认证策略变化会拒绝新关联，已存在的关联保持原配置。UDP association 空闲回收与控制 TCP 生命周期分开。

stop 清空 active、关闭全部业务资源并使未提交候选失效；重启需要重新 prepare/commit。候选 handle 只保留可读元数据，
不会阻止 stop/destroy，销毁 engine 后仍可读取并释放已持有的 handle。`publication_revision` 保留并推进，未激活时 `active_revision=0`。
成功提交的 handle 保持历史 COMMITTED 状态与 applied revision，不代表该配置仍 active；当前状态以 engine 快照为准。
从 prepare 回调提交 commit 时，之前已进入的 flush 不会自动等待这个后续操作；等待对应 commit 事件，或在提交后再建立屏障。

## 模式与节点选择

`solaris_engine_get_control_snapshot` 返回 owned 不可变副本。通过 `get_info/get_node/get_group/get_group_member` 读取同一 config/selection revision 的模式、节点、平面组及成员，再用 `solaris_control_snapshot_release` 释放。
这些元数据没有凭据，不保活运行时资源，engine 销毁后仍可读；需要跨持有者共享时使用 retain。

`solaris_engine_set_mode` 和 `solaris_engine_select` 均是异步操作，必须提供快照中的非零 `config_revision`。
执行时配置已变化则返回 EAGAIN；错误的组/成员或模式返回 EINVAL。成功结果提供 config/selection revision；
模式或选择没有变化时保持 selection revision。手动选择不会被健康探测自动覆盖。
模式/选择变化不推进 config revision，因此不会使只因控制变更而准备的候选失效。

TCP 在接纳时固定控制视图，包含仍在协议握手或 DNS 阶段的连接；UDP 在首条有效包登记 association 时固定。
后续切换只影响新的接纳；旧连接保持原 plan。reload 在提交点迁移当前模式和仍存在于新组的选中成员，
不会用 prepare 开始时的值覆盖准备期间的选择。成员失效时使用新组配置的默认成员，组快照提供 previous_selected_id、
selection_reason 和 reason_revision，区分初始选择、用户选择、保留、成员移除和新增组。

## 连接与流量

`solaris_engine_get_connections` 返回 owned 列表，可选择包含有界关闭历史；列表用 retain/release 管理，
`count/get` 读取纯值。单条查询使用 `solaris_engine_get_connection` 和完整 `{generation,id}`，不得仅按 id 跨代操作。
记录覆盖 TCP 接纳、握手和等待路由的阶段，以及 UDP association；尚未选路时 node/目标可能尚未确定。
SOCKS5 UDP 控制 TCP 保留自身零业务字节记录，UDP association 单独计数，以便关闭全部也能撤销空闲控制连接。

记录包含配置/选择 revision、实际叶节点、规则索引、owner、源/原目标/拨号目标、状态、字节包数及待处理队列。
`rule_index=UINT64_MAX` 表示模式选择或默认 DIRECT，没有匹配规则；未完成路由的字段不能解释为已选路证据。
公开信息不包含认证密码或用户名。

`solaris_engine_close_connection` 与 `solaris_engine_close_connections` 是异步操作。
后者在线性化点捕获当前已接纳连接，不关闭 admission，后来建立的连接仍可用。
完成回调给出捕获数量，并等待这些连接、待定路由与通道排空。
开始关闭后取消不会重新打开连接，取消结果同样等待清理完成，并保留已捕获的 matched 数量。
单条关闭的 generation 不匹配返回 EAGAIN；不存在或已关闭的 ID 返回 ECLOSED。要停止整个 engine，使用 stop。

`solaris_engine_get_traffic` 返回 USER/PROBE 两个逻辑计数桶和 engine 物理 socket 汇总。
逻辑字节在代理协议转换之前、同一应用数据只计一次；物理计数位于 TLS/协议/共享 session 下方，
只包含出站 socket payload，不含 IP/TCP/UDP 包头。共享 AnyTLS session 等场景无法准确按 USER/PROBE 拆分物理字节，
因此物理计数只提供总体，不能把它与逻辑字节相加。
这些是运行中的多 worker 观测汇总，并非所有 owner 同时刻的全局屏障。

## 单次测速与日志

初始化 `solaris_probe_options_t`，提供节点或平面组 target_id、HTTP(S) URL，并调用 `solaris_engine_probe`。
config_revision 为 0 时在操作开始捕获当前配置；非零时检查该 revision，过期返回 EAGAIN。
URL 最多 2048 字节、PEM 最多 256 KiB，接纳前复制，宿主可在调用返回后释放输入。
HTTPS 要求显式 trust PEM 并验证证书链及目标身份；TLS 被裁剪时 HTTPS 返回 ENOTSUP。

测速只发送一次 HEAD，完整 2xx/3xx 响应头与请求写入完成才成功；不跟随重定向、不重试、不测正文吞吐。
默认超时 5000 ms。用通用 `solaris_engine_cancel` 取消；typed 结果在资源排空后交付一次，并含实际配置/选择 revision、
节点、逻辑连接 ID、HTTP 状态、时延与字节数。时延记录结果决定时刻，资源清理或 OS 取消延迟不计入时延。
probe 的通用 event.config_revision 为 0，因为它没有发布配置；读取 typed 结果获取观察到的配置。
stop/destroy 等待已接纳的 probe 完成取消和回调。

`solaris_engine_get_logs(engine, after_sequence, max_records, ...)` 从固定容量环取得 owned 快照。
记录按 sequence 递增；下一次使用返回的 cursor，max_records 为 0 取环容量。
`overwritten/dropped` 是累计覆盖/丢弃数，`missed` 表示当前 cursor 已落后于保留窗口。
日志只公开安全 component、事件类别、status 和标识元数据，不复制 peer 原始文本、URL 或凭据。
该接口为轮询拷贝，不在 I/O worker 调用宿主回调；快照可在 engine 销毁后读取和释放。

## Worker 与预算

| options 字段 | 默认值与范围 |
| --- | --- |
| `io_workers` | 默认 1，支持 1–32；另有一个控制线程 |
| `command_capacity` | 控制队列默认 32，范围 1–1024 |
| `io_queue_capacity` | 每 worker 普通队列默认 128，上限 65536 |
| `io_resource_limit` | 每 worker scope 默认上限 1024，可设到 65536；包括内部 deadline/request scopes |
| `buffer_limit_bytes` | engine 共享 I/O 分配预算，默认 16 MiB；包含缓冲、通道与请求元数据，不等于 RSS |

以上零值取默认。创建时 worker 停放，start 激活，stop 排空并停放，destroy 才释放线程。worker 数在 engine 生命周期内固定。

## 调用和事件契约

start/stop 成功时写入非零 operation ID，失败时写零且不触发事件。ID 在单个 engine 内严格递增；多个调用线程按接纳顺序排列。队列满返回 EBUSY，重复 start（已运行或已有运行请求）也返回 EBUSY，拒绝不会改变请求状态。

事件在控制 owner 线程执行，不会在提交调用栈内直接调用，但可能在另一线程的 start/stop 返回前到达。宿主必须在提交前准备好回调上下文，不能假设“API 返回后事件才可能出现”。event 指针借用到回调返回，拷贝整个结构体即可独立保存。

回调允许提交下一操作与读取 snapshot；`flush`、`destroy` 会等待 owner，因此从本 engine 的控制回调或 I/O 回调内调用返回 EDEADLOCK，并保持对象有效。不要让回调等待其宿主线程中的 flush/destroy，否则宿主自行造成循环等待。

回调可选；未安装时仍记录完成状态，flush/snapshot 可用于无事件宿主。snapshot 只保留最近完成结果，若需要每个操作结果应安装事件回调。

内部异步操作允许乱序完成，`completed_operations` 是完成数量，`last_operation_id` 是最近完成的 ID，不保证递增。
有界窗口为 `command_capacity + 1`，乱序结果也占用窗口直到之前的操作完成；即使普通命令队列有空位，也可能返回 EBUSY。
完成屏障使用连续完成水位，且覆盖结果回调、通用事件和 owned context 的清理。
`cancel` 成功表示已请求取消；若操作已发布配置，最终事件仍携带实际 `config_revision`，不能将取消当作回滚。

## 完成屏障与销毁

`flush(engine, timeout_ms, ...)` 等待调用入口时已接受的控制命令及这些命令的回调全部返回。后续提交的操作不属于该屏障，需要再 flush；成功只是完成屏障，不代替具体操作状态。零超时为轮询，`SOLARIS_TIMEOUT_INFINITE` 无限等待，超时不取消操作。

destroy 是独占的宿主生命周期操作：宿主先停止其他 API 调用，再销毁。已经执行的回调允许完成；仍在队列中的操作收到 ECANCELLED，各自恰好一次。成功返回后不得再使用 engine，宿主此时才可释放回调上下文；NULL destroy 成功。

## 示例

```c
#include <solaris/core.h>
#include <stddef.h>

int use_core(void) {
    solaris_engine_t *engine = NULL;
    solaris_error_t error;
    uint64_t operation;
    solaris_status_t rc = solaris_engine_create(NULL, NULL, &engine, &error);
    if (rc != SOLARIS_OK) return 1;
    rc = solaris_engine_start(engine, &operation, &error);
    if (rc == SOLARIS_OK) rc = solaris_engine_flush(engine, 5000, &error);
    if (rc == SOLARIS_OK) rc = solaris_engine_stop(engine, &operation, &error);
    if (rc == SOLARIS_OK) rc = solaris_engine_flush(engine, 5000, &error);
    solaris_status_t cleanup = solaris_engine_destroy(engine, NULL);
    return rc == SOLARIS_OK && cleanup == SOLARIS_OK ? 0 : 1;
}
```

带事件的可构建版本见 [minimal_host.c](../../examples/minimal_host.c)，完整契约见 [engine.h](../../include/solaris/engine.h)。独立 flush 不等待持续运行的网络通道；先提交 stop 再 flush 才是全部 I/O 资源与回调的停止屏障。
