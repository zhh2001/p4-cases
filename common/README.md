# 公共运行逻辑

各案例通过 `run_helpers.sh` 编译 P4、启动拓扑并保留测试退出码。脚本只管理本次启动的拓扑进程，不调用全局 `pkill` 或 `mn -c`。

`compile_p4` 按源码文件名生成 JSON 和 P4Info。例如 `indirect_meter.p4` 生成 `build/indirect_meter.json` 和 `build/indirect_meter.p4info.txt`。拓扑读取这两个文件，每次运行都会重新编译。

## 拓扑和控制器

使用 `NetworkRuntime` 管理 Mininet 和控制器：

```python
from common.runtime import NetworkRuntime

with NetworkRuntime(MyTopo()) as runtime:
    net = runtime.net
    controller = runtime.start_controller(["/path/to/controller", "-addr", "127.0.0.1:9559"])
    if not controller.wait_ready("ready", timeout=15):
        raise RuntimeError("controller did not become ready")
    # 在此执行测试或启动 Mininet CLI。
```

控制器输出由后台线程持续读取并显示。`wait_ready` 和 `lines_for` 使用单调时钟限制等待时间，静默控制器不会阻塞超时判断。尚未消费的输出最多缓存 4096 行，超出后继续显示日志，但读取接口会报错，避免漏读内容后仍把测试判为成功。

需要向控制器发送 stdin 命令时，使用 `interactive=True`，再调用 `controller.send("dump")`。Case 08 的计数器读取要求四秒内收到 `dump-done`，未完成的回复会报错。

退出上下文时会停止控制器及其子进程，再关闭网络。网络构建、交换机启动、控制器启动和测试阶段发生异常时都走同一套清理流程。SIGINT 和 SIGTERM 分别返回 130 和 143。进程不响应 SIGTERM 时，三秒后发送 SIGKILL 并回收子进程。

## 交换机路径

默认路径为 `/usr/local/bin/simple_switch_grpc`。可以从案例目录运行：

```bash
sudo env P4_SWITCH_PATH=/your/path/simple_switch_grpc ./run.sh
```

`P4RuntimeSwitch(..., sw_path="/your/path/simple_switch_grpc")` 的显式参数优先于环境变量。启动前检查 gRPC 和 Thrift 端口占用，已有监听服务时会报错。

## 回归测试

安装 Mininet 后，从仓库根目录执行，无需 root：

```bash
python3 -m unittest discover -s tests -v
shellcheck -x common/run_helpers.sh */run.sh
```

测试覆盖日志超时、提前退出、输出过量、stdin 命令、启动异常、信号退出和进程回收。真实数据面测试仍通过各案例的 `sudo ./run.sh` 执行。
