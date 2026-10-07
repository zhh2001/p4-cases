# Case 11：VXLAN 封装

本案例按内层目的 MAC 选择 VTEP，将收到的完整以太网帧封装进 IPv4 VXLAN 报文，再送到指定出口。

拓扑为 `h1 → s1 → h2`。h1 从端口 1 发送内层帧，h2 从端口 2 接收封装后的帧。本案例只展示封装，不提供解封装或双向 IP 路由。

## 数据面

解析器只提取内层以太网头，剩余内容作为载荷保留。`vtep` 表按内层目的 MAC 精确匹配，命中后执行 `encap`，为四个外层头调用 `setValid()` 并填写字段。

出包顺序如下：

```text
Outer Ethernet / Outer IPv4 / UDP / VXLAN / Inner Ethernet / Inner Payload
     14 B           20 B       8 B    8 B         14 B          可变
```

设收到的完整内层帧长度为 `L`，其中包含内层以太网头，不包含 FCS，则：

- 外层 IPv4 Total Length 为 `L + 36`。
- 外层 UDP Length 为 `L + 16`。
- 封装后的完整以太网帧长度为 `L + 50`。

P4 使用 `standard_metadata.packet_length` 计算长度，包含内层载荷和实际收到的填充字节。封装前检查 `L ≤ 65499`，避免外层 IPv4 的 16 位长度字段溢出。解析错误和未命中 VTEP 的报文明确丢弃。

`MyComputeChecksum` 在长度和其他 IPv4 字段填写后更新外层 IPv4 校验和。外层 UDP 校验和保留为零，这是本案例采用的 IPv4 VXLAN 形式。VXLAN 的 I 标志为 1，其余标志和保留字段均为零，格式说明见 [RFC 7348](https://www.rfc-editor.org/rfc/rfc7348)。

## 控制器配置

控制器只安装一条封装规则：

| 字段          | 值                  |
| ------------- | ------------------- |
| 内层目的 MAC  | `00:00:00:11:11:11` |
| 出口          | 2                   |
| 外层目的 MAC  | `00:00:00:00:00:02` |
| 外层源 MAC    | `00:00:00:de:ad:01` |
| 外层源 IPv4   | `192.168.1.1`       |
| 外层目的 IPv4 | `192.168.1.2`       |
| VNI           | 5000                |

以上出口、外层地址和 VNI 通过六个 action 参数传入。其他字段由 P4 设置：IPv4 TTL 为 64，UDP 源端口为 12345，目的端口为 4789。

```go
entry, err := tableentry.NewBuilder(p, "MyIngress.vtep").
    Match("hdr.inner_eth.dstAddr", tableentry.Exact(codec.MustMAC("00:00:00:11:11:11"))).
    Action("MyIngress.encap",
        tableentry.Param("egress_port", codec.MustEncodeUint(2, 9)),
        tableentry.Param("outer_dmac", codec.MustMAC("00:00:00:00:00:02")),
        tableentry.Param("outer_smac", codec.MustMAC("00:00:00:de:ad:01")),
        tableentry.Param("outer_sip", codec.MustIPv4("192.168.1.1")),
        tableentry.Param("outer_dip", codec.MustIPv4("192.168.1.2")),
        tableentry.Param("vni", codec.MustEncodeUint(5000, 24))).
    Build()
```

`forward_plain` 动作保留在 P4 中供实验使用，当前控制器没有安装对应表项。

## MTU

封装增加 50 字节。拓扑将 h1 接入链路的两端 MTU 保持为 1500，将 s1 到 h2 链路的两端 MTU 设置为 1600，为标准内层帧预留封装空间。配置失败会终止启动并清理本次网络。

自动测试最大内层帧为 1514 字节，封装后为 1564 字节，外层 IPv4 长度为 1550 字节，可通过 MTU 1600 的链路。

65499 字节是 IPv4 长度字段能表示的内层上限，不代表当前链路能传输这么大的帧。本案例不做分片或路径 MTU 探测，部署时需要为底层链路配置足够的 MTU。

## 文件

| 文件                 | 作用                                             |
| -------------------- | ------------------------------------------------ |
| `main.p4`            | 添加外层头，按入包长度填写字段并更新 IPv4 校验和 |
| `controller/main.go` | 安装一条 VTEP 封装规则                           |
| `packets.py`         | 构造内层测试帧和预期的完整封装帧                 |
| `test_sniff.py`      | 使用原始套接字发送和捕获完整帧                   |
| `topology.py`        | 配置链路 MTU，创建拓扑并验证交付内容             |
| `run.sh`             | 编译并运行自动测试或交互模式                     |

## 运行和验证

```bash
cd 11_vxlan_encap
sudo ./run.sh
```

收发脚本只使用 Python 标准库，需要 root 权限，不需要 Scapy。

测试包含 11 个场景，每个场景发送 5 帧，共 55 帧：

| 类别                                    | 场景数 | 要求               |
| --------------------------------------- | ------ | ------------------ |
| 60、64、128、512、1500、1514 字节内层帧 | 6      | 全部封装并完整交付 |
| 带 VLAN、IPv4、ARP 的内层帧             | 3      | 保留内层头部和内容 |
| 未匹配目的 MAC 的 60、1514 字节帧       | 2      | 全部丢弃           |

h1 和 h2 同时捕获本轮流量。捕获按原始以太网源地址筛选，避免畸形外层长度影响高层解码。h2 必须收到恰好 45 个预期封装帧，h1 不应收到测试帧。完整比较覆盖外层地址、长度、TTL、端口、IPv4 校验和、UDP 零校验和、VXLAN 标志、保留位、VNI，以及内层的每个字节。

每帧使用唯一源 MAC 标识。捕获进程就绪后才发送报文，并检查所有收发进程的退出码与回复。空捕获、丢包、重复、内容变化、错误出口、收发失败或超时都会使测试失败，随后清理本次启动的进程。

部分输出如下：

```text
raw-60: received=5/5, expected=5
raw-1514: received=5/5, expected=5
vlan: received=5/5, expected=5
ipv4: received=5/5, expected=5
arp: received=5/5, expected=5
unmatched-60: received=0/5, expected=0
unmatched-1514: received=0/5, expected=0
SUCCESS: VXLAN lengths, checksum, outer headers and inner frames match expectations
```

交互模式：

```bash
sudo ./run.sh cli
```

在仓库根目录运行无需交换机的测试：

```bash
/usr/bin/python3 -m unittest discover -s tests -p test_vxlan_encap.py -v
```

## 范围

内层以太网帧按原始字节封装，包含内层 VLAN 时也保持原样。本案例不解析内层 IP 选项、传输层或校验和。外层只使用无选项的 IPv4，不支持 IPv6 封装，不计算 UDP 非零校验和，也不按内层流量散列 UDP 源端口。

扩展解封装时，需要识别外层协议、验证长度和 VXLAN 字段，再移除对应外层头。增加多个 VTEP 时，可以写入更多目的 MAC 表项，为各条目设置不同的外层地址和 VNI。
