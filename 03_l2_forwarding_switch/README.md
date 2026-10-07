# Case 03：静态 L2 转发交换机

本案例从 Case 02 的硬编码端口判断转向表驱动转发。控制器安装目的 MAC 与出口的映射，P4 通过 `dmac` 表的 exact 匹配选择端口。

## 拓扑与转发规则

默认拓扑是一台交换机 `s1` 和四台主机 `h1` 至 `h4`。主机 `hN` 使用 `10.0.0.N/24`，连接交换机端口 N。MAC 的最后一个字节按主机编号的十六进制生成，例如 `h10` 使用 `00:00:00:00:00:0a`。

- 目的 MAC 命中其他端口时，完整转发原帧。
- 表项出口等于入端口时，丢弃报文。
- 未命中的单播、广播和组播均丢弃，解析失败或缺少完整以太网头的报文也丢弃。
- 数据面只读取以太网头，不修改 IP 跳数、校验和、VLAN 标签或负载。IPv4 TTL 为 0 或 1、IPv6 hopLimit 为 0、IPv4 校验和错误的报文仍按目的 MAC 转发。

拓扑在启动控制器前，为主机安装永久 ARP 邻居记录，并检查命令是否成功。ARP 广播因此不影响主机互通。

## 文件

| 文件                                                    | 作用                                         |
| ------------------------------------------------------- | -------------------------------------------- |
| `main.p4`                                               | 目的 MAC 精确匹配、入端口过滤和默认丢弃      |
| `controller/main.go`                                    | 安装 pipeline，按主机数量写入 `dmac` 表项    |
| `topology.py`                                           | 创建拓扑、配置静态 ARP、管理控制器并验证转发 |
| `packets.py`                                            | 生成逐方向转发和丢弃测试报文                 |
| `probe.py`                                              | 发送原始帧并捕获完整报文                     |
| `run.sh`                                                | 编译并启动案例                               |
| `controller/main_test.go`、`../tests/test_static_l2.py` | 地址、报文证据和失败处理的回归测试           |

## P4 与控制器

`dmac` 的键是 `hdr.ethernet.dstAddr`，容量为 256。命中时调用 `forward(egress_port)`，默认动作是 `drop`。表匹配后比较入口和出口，避免将报文送回源端口。

控制器使用表名 `MyIngress.dmac`、动作名 `MyIngress.forward` 和参数名 `egress_port`。这些全限定名可在编译生成的 `build/main.p4info.txt` 中查看。

控制器的 `-hosts` 和拓扑的 `--n-hosts` 必须保持一致，默认均为 4，允许范围为 1 至 254。这个范围对应固定 `/24` 子网的可用主机地址。`h100` 的 MAC 为 `00:00:00:00:00:64`，`h254` 的 MAC 为 `00:00:00:00:00:fe`。

## 运行

在案例目录执行：

```bash
sudo ./run.sh
sudo ./run.sh cli
```

默认模式检查原始报文并运行 `pingAll`。CLI 模式配置相同的转发表和静态 ARP，可手动执行 `pingall`。

先通过 `run.sh` 生成编译产物，也可以指定主机数量：

```bash
sudo /usr/bin/python3 topology.py --n-hosts 12 --run-test \
    --p4info build/main.p4info.txt --config build/main.json \
    --controller bin/controller
```

## 自动化验证

四主机测试发送 124 帧，其中 80 帧应转发、44 帧应丢弃，每台主机应收到 20 帧。测试覆盖所有主机方向，以及 IPv4、IPv6、单播 ARP、VLAN、双层 VLAN、最短帧填充和 1500 字节负载。入端口回送、未匹配单播、广播和组播均不得到达任何主机。

接收结果按完整帧和出现次数核对，报文缺失、重复、错投、回送或字节变化都会导致失败。Linux 抓包可能将外层 VLAN 标签放在辅助数据中，`probe.py` 根据 [`PACKET_AUXDATA`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_packet.h) 还原标签后再比较。探针失败、控制器退出和静态 ARP 配置失败也会使测试失败。

```text
*** Results: 0% dropped (12/12 received)
ping drop ratio: 0.0%
L2 probes: sent=124 forwarded=80 dropped=44
SUCCESS: static L2 forwarding and complete frames validated
```

其他主机数量按相同规则生成报文，单主机拓扑只检查丢弃行为，跳过 `pingAll`。从仓库根目录运行回归测试：

```bash
/usr/bin/python3 -m unittest discover -s tests -p test_static_l2.py -v
go test ./03_l2_forwarding_switch/controller
```

需要广播或动态 MAC 学习时，可继续阅读 Case 04 和 Case 05。
