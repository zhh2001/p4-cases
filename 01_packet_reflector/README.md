# Case 01：报文反射器

这个案例展示最小的 P4 处理流程：解析以太头，交换源 MAC 和目的 MAC，再从入端口原路送回。控制器只安装流水线，无需写入表项。

## 反射规则

```text
h1 -- port 1 -- s1
    <---------
```

默认拓扑包含一个交换机和一个主机。完整以太头的源地址与目的地址对调，EtherType、载荷、VLAN 标签及填充字节保持原样。以太头不足 14 字节或解析失败的报文丢弃。

反射方向只取决于入端口，不依赖 MAC 地址。未知地址、零地址、广播和组播地址也执行相同的对调。P4 不解析以太头之后的内容，IPv4 的 TTL 和校验和、IPv6 的 Hop Limit 不参与判断。

## 文件

| 文件                 | 作用                                          |
| -------------------- | --------------------------------------------- |
| `main.p4`            | 检查解析状态、对调 MAC 并选择入端口作为出端口 |
| `topology.py`        | 构建拓扑、管理探针并核对完整回包              |
| `packets.py`         | 构造测试帧和预期的 MAC 对调结果               |
| `test.py`            | 在主机内发送帧并采集带标记的入站帧            |
| `controller/main.go` | 安装流水线并等待退出信号                      |
| `run.sh`             | 编译、启动网络并运行测试                      |

## 运行与测试

在案例目录执行：

```bash
sudo ./run.sh
sudo ./run.sh cli
```

默认发送 92 帧。测试覆盖主机地址、未知地址、零地址、广播和组播目的地址，以及 12 种内容，包括 IPv4、IPv6、ARP、单层 VLAN、QinQ、填充字节和 1500 字节载荷。还检查重复帧，以及源 MAC 为主机地址、零地址、广播、组播和源目的地址相同的情况。TTL 为 0 或 1、Hop Limit 为 0 和 IPv4 校验和错误的帧也应完整反射。

接收探针就绪后才开始发送。测试逐字节核对回包，要求 MAC 正确对调、其他字节保持原样，每次发送只返回一个副本。遗漏、额外副本、内容改动、错误出端口、探针异常退出、回复无效、等待超时或控制器提前退出都会使测试失败。Linux 接收路径剥离的外层 VLAN 标签通过辅助数据恢复。

预期关键输出：

```text
Reflector probes: sent=92 reflected=92 hosts=1
SUCCESS: MAC swapping, ingress reflection and complete frames validated
```

`topology.py` 支持 `--n-hosts`，范围为 1 到 254。编译后可用多主机拓扑检查不同入端口的回包，确保其他主机没有收到副本：

```bash
sudo /usr/bin/python3 topology.py --n-hosts 3 --run-test \
    --p4info build/main.p4info.txt --config build/main.json \
    --controller bin/controller
```

反射器不会转发到另一主机，主机之间的 `pingAll` 不属于成功判据。在仓库根目录运行回归测试：

```bash
/usr/bin/python3 -m unittest discover -s tests -v
go test ./...
```

## 排查问题

先查看控制器输出、`/tmp/s1.log` 和 `/tmp/s1.log.stderr`，确认流水线安装成功。探针参数可通过 `python3 test.py send --help` 和 `python3 test.py receive --help` 查看。

自动测试结束、启动失败或收到退出信号时会清理本次网络。若进程被强制终止，先确认没有其他拓扑运行，再手动清理残留。
