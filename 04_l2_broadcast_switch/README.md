# Case 04：L2 广播交换机

本案例在 Case 03 的静态单播表基础上，使用 Packet Replication Engine（PRE）处理未匹配流量。控制器为每个入端口安装一个复制组，把报文送到其他端口，使 ARP 广播可以完成邻居解析。

## 拓扑与转发规则

默认拓扑是一台交换机 `s1` 和四台主机 `h1` 至 `h4`。主机 `hN` 使用 `10.0.0.N/24`，连接交换机端口 N。MAC 的最后一个字节按编号的十六进制生成，例如 `h10` 使用 `00:00:00:00:00:0a`，`h100` 使用 `00:00:00:00:00:64`。

- 目的 MAC 命中其他端口时，只向该端口转发一份完整原帧。
- 已知单播的出口等于入端口时，丢弃报文。
- 目的 MAC 未命中时，选择入端口对应的复制组，向其他每个端口各转发一份。未知单播、广播和组播都遵循这一规则。
- 未匹配流量缺少复制组选择表项时丢弃。解析失败或以太网头不完整的报文也丢弃。
- 数据面只读取以太网头，保留 MAC、EtherType、VLAN 标签、IP 头、负载和填充。IPv4 TTL 为 0 或 1、IPv6 hopLimit 为 0、IPv4 校验和错误的报文仍按二层规则处理。

本案例不安装静态 ARP。主机通过广播请求和单播回复解析邻居，控制器不学习 MAC 地址。

## 表与复制组

`dmac` 使用 `hdr.ethernet.dstAddr` 的 exact 匹配，命中时调用 `forward(egress_port)`。默认动作是 `NoAction`，未命中后继续执行 `select_mcast_grp`。

`select_mcast_grp` 使用 `standard_metadata.ingress_port` 的 exact 匹配，调用 `set_mcast_grp(mcast_grp)` 选择复制组，默认动作是 `drop`。入口与已知单播出口的比较在表匹配后进行。

两张表的容量均为 128，因此控制器的 `-hosts` 和拓扑的 `--n-hosts` 允许范围为 1 至 128。两者默认均为 4，必须保持一致。

| 入端口 | 复制组 ID | 复制到的端口 |
| ------ | --------- | ------------ |
| 1      | 1         | 2、3、4      |
| 2      | 2         | 1、3、4      |
| 3      | 3         | 1、2、4      |
| 4      | 4         | 1、2、3      |

复制组通过 P4Runtime 的 `PacketReplicationEngineEntry` 安装，不属于 P4 的匹配表。单主机拓扑没有其他出口，控制器只安装一条 `dmac` 表项，跳过复制组及选择表项，所有测试报文均丢弃。

## 文件

| 文件                                                       | 作用                                            |
| ---------------------------------------------------------- | ----------------------------------------------- |
| `main.p4`                                                  | 单播匹配、入端口过滤、复制组选择和解析检查      |
| `controller/main.go`                                       | 安装 pipeline、单播表项、PRE 复制组和选择表项   |
| `topology.py`                                              | 创建拓扑、管理控制器、检查动态 ARP 和完整报文   |
| `packets.py`                                               | 生成逐方向单播、泛洪和丢弃测试报文              |
| `probe.py`                                                 | 发送原始帧并捕获完整报文                        |
| `run.sh`                                                   | 编译并启动案例                                  |
| `controller/main_test.go`、`../tests/test_broadcast_l2.py` | 地址、复制组、ARP、报文证据和失败处理的回归测试 |

## 运行

在案例目录执行：

```bash
sudo ./run.sh
sudo ./run.sh cli
```

默认模式检查动态 ARP、主机互通和完整报文。CLI 模式安装相同的转发表和复制组，可手动执行 `pingall`。

先通过 `run.sh` 生成编译产物，也可以指定主机数量：

```bash
sudo /usr/bin/python3 topology.py --n-hosts 12 --run-test \
    --p4info build/main.p4info.txt --config build/main.json \
    --controller bin/controller
```

## 自动化验证

测试先清空每台主机的邻居缓存，再运行 `pingAll`，检查全部对端是否解析为正确的 MAC，并确认邻居记录由动态 ARP 产生。

四主机报文测试发送 300 帧，预期交付 692 个完整副本，丢弃 16 帧，每台主机应收到 173 帧。其中 80 个副本来自已知单播，612 个副本来自未知单播、广播和组播的泛洪。每份泛洪报文必须到达所有其他主机各一次，入端口不得收到回送。

报文覆盖 IPv4、IPv6、ARP、VLAN、双层 VLAN、最短帧填充和 1500 字节负载。接收结果按完整帧和出现次数核对，缺失、重复、错投、回送或字节变化都会导致失败。抓包脚本会根据 Linux 的 `PACKET_AUXDATA` 还原被放入辅助数据的外层 VLAN 标签，再比较完整帧。

```text
*** Results: 0% dropped (12/12 received)
ping drop ratio: 0.0%
L2 probes: sent=300 delivered=692 dropped=16
SUCCESS: L2 unicast, flooding and dynamic ARP validated
```

其他主机数量按相同规则生成报文，单主机跳过 `pingAll`，检查全部 66 帧均未返回。探针失败、ARP 配置或读取失败、控制器退出都会使测试失败，并清理本次启动的进程。

从仓库根目录运行回归测试：

```bash
/usr/bin/python3 -m unittest discover -s tests -p test_broadcast_l2.py -v
go test ./04_l2_broadcast_switch/controller
```

需要动态 MAC 学习时，可继续阅读 Case 05。
