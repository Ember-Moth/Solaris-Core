# 当前 C SDK：M0 生命周期

本页描述当前已经实现的 API。完整目标能力见 [配置与宿主 SDK 设计](CONFIGURATION_AND_SDK.md)，完成状态见 [开发计划](DEVELOPMENT_PLAN.md)。

## 构建与使用

需要 CMake 3.24+、C11 编译器；测试还需要 Python 3.9+ 和 C++11 编译器。首次配置下载 lock 指定的 libuv，之后同一构建目录可复用依赖。

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

包含 `<solaris/core.h>`，或按需包含 engine/error/version 头文件。静态安装的私有 libuv 归档需要一并保留，链接由导出目标完成；共享包包含其私有实现，不向宿主暴露 libuv API。

## 已实现入口

| 函数 | 行为 |
| --- | --- |
| `solaris_engine_options_init` | 填充默认控制 worker 数与命令容量 |
| `solaris_engine_create` | 同步创建，复制 options/host；失败输出 NULL |
| `solaris_engine_start` | 异步切换控制 runtime 到 RUNNING |
| `solaris_engine_stop` | 异步停止控制 runtime；重复 stop 仍完成一次操作 |
| `solaris_engine_get_snapshot` | 拷贝无指针状态、操作计数、closing、uptime |
| `solaris_engine_flush` | 等待入口时已接受操作及其回调完成 |
| `solaris_engine_destroy` | 关闭新操作，取消排队操作，等待回调/线程退出并释放 |
| `solaris_status_string` | 返回静态状态说明 |
| `solaris_version_string` | 返回产品版本字符串 |

M0 没有 YAML、协议、监听、DNS 或 TUN API；不存在返回假成功的占位实现。`io_workers` 的零值取默认 1，其他大于 1 的值明确返回 ENOTSUP。命令队列默认 32，支持 1–1024，零值取默认。

## 调用和事件契约

start/stop 成功时写入非零 operation ID，失败时写零且不触发事件。ID 在单个 engine 内严格递增；多个调用线程按接纳顺序排列。队列满返回 EBUSY，重复 start（已运行或已有运行请求）也返回 EBUSY，拒绝不会改变请求状态。

事件在 owner 线程执行，不会在提交调用栈内直接调用，但可能在另一线程的 start/stop 返回前到达。宿主必须在提交前准备好回调上下文，不能假设“API 返回后事件才可能出现”。event 指针借用到回调返回，拷贝整个结构体即可独立保存。

回调允许提交下一操作与读取 snapshot；`flush`、`destroy` 会等待 owner，因此从回调内调用返回 EDEADLOCK，并保持对象有效。不要让回调等待其宿主线程中的 flush/destroy，否则宿主自行造成循环等待。

回调可选；未安装时仍记录完成状态，flush/snapshot 可用于无事件宿主。snapshot 只保留最近完成结果，若需要每个操作结果应安装事件回调。

## 完成屏障与销毁

`flush(engine, timeout_ms, ...)` 等待调用入口时已接受的命令及这些命令的回调全部返回。后续提交的操作不属于该屏障，需要再 flush；成功只是完成屏障，不代替具体操作状态。零超时为轮询，`SOLARIS_TIMEOUT_INFINITE` 无限等待，超时不取消操作。

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

带事件的可构建版本见 [minimal_host.c](../../examples/minimal_host.c)，完整契约见 [engine.h](../../include/solaris/engine.h)。M1 才实现真正的多 worker 数据面和协议任务作用域。
