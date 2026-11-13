# M0 工程决策记录

日期：2026-11-03。实现状态以 [开发计划](DEVELOPMENT_PLAN.md) 为准。

## M0-01：构建和依赖

主构建入口采用 **CMake 3.24+**，自有代码使用 C11，依赖构建与跨平台工具链由 CMake 管理。移除原 xmake/CMake 双入口，避免维护两套源码枚举。选择 CMake 的直接目标是标准安装/导出包、C/C++ 消费测试和各平台原生工具链支持。

[modules/builtin.json](../../modules/builtin.json) 是自有模块源码、依赖、公开头文件和导出函数的唯一清单。CMake 从中生成 ELF/Mach-O/Windows 导出白名单；M0 仅包含 SDK/runtime，协议 descriptor 注册在 M1 扩展。

[dependencies/lock.json](../../dependencies/lock.json) 固定依赖与参考提交：

| 项目 | 决定 | 当前是否编译 |
| --- | --- | --- |
| libuv | 1.53.0，固定提交及归档 SHA-256；私有静态链接进共享 SDK | 是 |
| libyaml（历史选择） | M2 曾使用 0.2.5；CFG 迁移后 parser/shim/依赖移除，当前使用自有 Conf lexer/parser | 否 |
| yyjson | 0.12.0，固定提交；用于后续 JSON 诊断/便利接口，不替代原生 C 类型 | 否 |
| mihomo（历史参考） | M2 固定参考工具已移至 tests/archive/yaml，不进入原生默认门禁 | 否 |

没有因命名复用而继承旧版本：libuv 选择本次核对的正式发布 1.53.0。共享/静态构建都使用相同固定源码，获取时校验内容 hash。CMake 官方的 `FETCHCONTENT_SOURCE_DIR_SOLARIS_UV` 可用于受控离线缓存；使用覆盖时由调用方确保来源与 lock 一致。

共享 SDK 只导出清单中的 `solaris_*` 函数。静态 SDK 安装 `libsolaris.a` 与私有的 `libsolaris_uv.a`，由 `Solaris::core` 传播系统链接依赖；不是一个已经合并的 Apple XCFramework。单归档/平台包组装在对应平台阶段完成。

## M0-02：新源码树

原框架、旧头文件、旧平台脚本和旧构建入口从当前源码树移除，原内容仍可在提交 `f9ca89ac3cf13808463beac9b4130d6639ffb1c7` 查看。不会建立长期并行的 legacy 源码层。

当前编译的自有代码只包含 `src/api/`、`src/core/`、`src/runtime/` 和 `include/solaris/`。协议/密码/栈代码在后续按新契约选择性复用；保留的第三方源码和 patch 不进入 M0 链接。

## M0-03：最小 C SDK

公开 SDK 使用普通 C 函数、opaque engine、固定宽度状态值与无指针 snapshot。无旧 schema、ABI getter、版本协商或保留槽位。产品版本字符串只用于识别构建。

create 同步建立控制线程；start/stop 异步、有界、FIFO。每个接受操作产生唯一 ID 和一次完成事件，拒绝时 ID 为零且无回调。`flush` 等待调用入口时已接受操作及其回调完成；`destroy` 关闭 admission、取消排队操作并 join。

M0 仅支持一个控制 worker，对 `io_workers > 1` 返回 ENOTSUP。RUNNING 表示控制运行时可用，不代表已建立代理、TUN 或 YAML 配置。M1 多 worker 数据面继续按 [运行时规范](RUNTIME.md) 开发。

失败注入、allocator 和逻辑时钟是私有的逐实例 runtime services，不进入安装头文件或共享库导出。可注入时钟目前覆盖事件时间与 uptime；同步 `flush` deadline 使用 OS 单调时钟，M1 timer/scheduler 的虚拟时钟尚未实现。

## M0-04/M0-05：打包和验证

共享/静态使用同一实现清单。独立消费测试先安装 SDK，再重命名安装前缀，只用搬迁后的 `Solaris::core` 编译并运行 C/C++ 宿主；检查只安装声明的五个公共头文件。

生命周期契约覆盖参数与能力拒绝、两处内存分配失败、mutex/condition/thread/loop/async 初始化失败、唤醒失败回滚、背压、flush/回调屏障、回调内安全重入、销毁取消、并发提交与独立实例。

GitHub Actions 配置 macOS/Linux/Windows 的共享/静态矩阵和 Linux sanitizers。工作流文件存在不等于远端 CI 已通过；实际运行结果另记于开发计划。

## M0-07：TUN backend 边界

首个 TUN 栈方案采用 **单 stack owner 的 lwIP TCP backend + 独立 UDP association 路径**。lwIP 使用此前核对的固定源码作为后续复用候选；M0 不下载、链接或激活 TUN。

后端输入/输出边界确定为：

- 支持宿主借用 fd 与 packet callback 两种入口；fd/系统 VPN 生命周期属于宿主。
- packet ingress 交付 owned buffer 或受严格批次生命周期约束的借用 buffer，带地址族和必要的入站身份。
- TCP 栈仅由 stack executor 操作，通过有序 stream 桥与出站 worker 通信；出站线程不直接调用 lwIP 全局状态。
- UDP 提取完整报文和 metadata 后按 association key 分派，不经过共享 TCP 栈串行路径。
- 输出通过受线程与容量约束的宿主 packet sink；停止排空后才释放宿主上下文。
- 多实例/并行栈必须由独立 backend 能力证明，不为原 lwIP 增加一个 context 指针就宣称隔离。

具体 backend C vtable、packet codec 和真机验证在 M1/M3 实现。M0 的决定仅固定责任、生命周期与并行边界。

参考：[CMake FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html)、[libuv 1.53.0](https://github.com/libuv/libuv/releases/tag/v1.53.0)、[LibYAML](https://github.com/yaml/libyaml/tree/0.2.5)、[yyjson](https://github.com/ibireme/yyjson/tree/0.12.0)。
