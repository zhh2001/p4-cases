# Case 02：端口中继器

这个案例用硬编码的端口映射实现双向转发，控制器只安装流水线，无需写入表项。

## 转发规则

```text
h1 -- port 1 -- s1 -- port 2 -- h2
```

端口 1 收到的完整以太帧转发到端口 2，端口 2 收到的转发到端口 1。其他入端口的报文，以及以太头不足 14 字节的报文均丢弃。

目的 MAC 不影响转发方向。发往发送主机自身、未知地址、广播和组播地址的帧都转发到另一端口。P4 不解析以太头之后的内容，MAC、EtherType、载荷、VLAN 标签和填充字节均保持原样。IPv4 的 TTL 和校验和、IPv6 的 Hop Limit 也不参与转发判断。

如果需要调整端口映射，需要修改并重新编译 `main.p4`。下一个案例会通过表项配置转发端口。

## 文件

| 文件                 | 作用                                 |
| -------------------- | ------------------------------------ |
| `main.p4`            | 解析以太头，检查解析状态并选择出端口 |
| `topology.py`        | 两主机拓扑、探针管理和完整帧校验     |
| `packets.py`         | 构造双向测试帧和重复帧               |
| `test.py`            | 在主机内发送帧并采集带标记的入站帧   |
| `controller/main.go` | 安装流水线并等待退出信号             |
| `run.sh`             | 编译、启动网络并运行测试             |

## 运行与测试

在案例目录执行：

```bash
sudo ./run.sh
sudo ./run.sh cli
```

默认测试发送 174 帧，两个方向各 87 帧。每个方向覆盖 7 种目的 MAC 和 12 种内容，包括 IPv4、IPv6、ARP、单层 VLAN、QinQ、填充字节、1500 字节载荷及重复帧。TTL 为 0 或 1、Hop Limit 为 0 和 IPv4 校验和错误的帧也应完整转发。

两个接收探针就绪后才开始发送。测试逐字节比较全部帧及每帧的份数，检查遗漏、重复、内容改动和返回源端口的帧。Linux 接收路径剥离的外层 VLAN 标签通过辅助数据恢复。探针异常退出、回复无效、发送数量不足、等待超时或控制器提前退出都会使测试失败。

完整帧检查后执行 `pingAll`，验证双向 ARP 和 ICMP 通信。预期关键输出：

```text
Repeater probes: sent=174 received=174
ping drop ratio: 0.0%
SUCCESS: bidirectional repeater forwarding and complete frames validated
```

在仓库根目录运行回归测试：

```bash
/usr/bin/python3 -m unittest discover -s tests -v
go test ./...
```

## 排查问题

先查看控制器输出、`/tmp/s1.log` 和 `/tmp/s1.log.stderr`，确认流水线安装成功。`test.py` 的 `send` 和 `receive` 子命令使用显式参数，可通过 `python3 test.py send --help` 和 `python3 test.py receive --help` 查看用法。

自动测试结束、启动失败或收到退出信号时会清理本次网络。若进程被强制终止，先确认没有其他拓扑运行，再手动清理残留。
