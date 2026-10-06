# Case 10：防火墙 ACL

本案例在二层转发后应用 IPv4 ACL，通过 ternary 匹配和优先级实现允许与拒绝规则。拓扑包含两台主机和一台交换机：`h1 (10.0.0.1) ↔ s1 ↔ h2 (10.0.0.2)`。

## 匹配规则

ACL 匹配四个字段：源 IPv4 地址、目的 IPv4 地址、协议号和目的端口。数值更大的优先级先匹配，未命中任何规则时允许通过。

| 优先级 | 源地址     | 目的地址   | 协议 | 目的端口 | 动作 |
| ------ | ---------- | ---------- | ---- | -------- | ---- |
| 100    | 任意       | `10.0.0.2` | TCP  | 22       | 拒绝 |
| 90     | 任意       | `10.0.0.2` | TCP  | 任意     | 允许 |
| 80     | `10.0.0.1` | 任意       | UDP  | 5000     | 拒绝 |

因此，`h1 → h2` 的 TCP/22 同时匹配前两条规则，由优先级 100 的拒绝规则决定结果。TCP/80 命中优先级 90 的允许规则，UDP/1234 使用默认允许动作。

规则具有方向性。`h2 → h1` 的 TCP/22 和 UDP/5000 不命中上述拒绝规则，会使用默认允许动作。

控制器使用 SDK 构建表项。以下代码展示 TCP/22 规则的关键部分：

```go
tableentry.NewBuilder(p, "MyIngress.acl").
    Match("hdr.ipv4.dstAddr",
        tableentry.Ternary(codec.MustIPv4("10.0.0.2"),
            []byte{0xff, 0xff, 0xff, 0xff})).
    Match("hdr.ipv4.protocol",
        tableentry.Ternary([]byte{6}, []byte{0xff})).
    Match("hdr.l4.dstPort",
        tableentry.Ternary(codec.MustEncodeUint(22, 16),
            []byte{0xff, 0xff})).
    Action("MyIngress.deny").
    Priority(100).
    Build()
```

不匹配的字段可以省略，全零掩码也表示通配。这里的源地址为任意地址。

## IPv4 Options 和分片

IPv4 的 IHL 以四字节为单位，正常范围为 5 到 15。因此头部长度可能为 20 到 60 字节，Options 最多占 40 字节，字段定义见 [RFC 791](https://www.rfc-editor.org/rfc/rfc791)。

解析器先检查版本号和长度，再提取 `(IHL - 5) × 4` 字节 Options，最后读取 TCP 或 UDP 的源端口和目的端口。Options 使用 `varbit<320>` 保存，出包时放回 IPv4 固定头和传输层头之间，保持报文内容不变。

解析过程还检查：

- IPv4 版本号为 4，IHL 至少为 5。
- Total Length 不小于头部长度，也不超过实际收到的 IPv4 数据长度。
- TCP 和 UDP 分别至少具有 20 字节和 8 字节的传输层头部长度。
- 解析发生错误时，入方向直接丢弃报文。

本案例丢弃所有 IPv4 分片，包括 `MF=1` 的首片和片偏移非零的后续片。设置 DF 但未实际分片的报文仍按 ACL 处理。不进行分片重组。

## 文件

| 文件                 | 作用                                               |
| -------------------- | -------------------------------------------------- |
| `main.p4`            | 解析 IPv4 和 Options，检查分片，执行二层转发与 ACL |
| `controller/main.go` | 安装两条 MAC 转发表项和三条 ACL 规则               |
| `packets.py`         | 构造正常、带 Options、异常和分片测试报文           |
| `test.py`            | 在主机内发送指定帧并捕获本轮报文                   |
| `topology.py`        | 创建拓扑并比较 ACL 测试结果                        |
| `run.sh`             | 编译、启动和运行自动测试                           |

## 运行和验证

```bash
cd 10_firewall_acl
sudo ./run.sh
```

收发脚本使用 Python 原始套接字，需要 root 权限，不需要 Scapy。

自动测试包含 40 个场景，每个场景发送 5 帧，共 200 帧：

| 类别                   | 场景数 | 检查内容                                                              |
| ---------------------- | ------ | --------------------------------------------------------------------- |
| `h1 → h2` 的四条基础流 | 16     | 无 Options、4 字节 Options、40 字节 Options、内容类似端口号的 Options |
| `h2 → h1` 的反向流     | 8      | 无 Options 和 40 字节 Options，检查规则方向性                         |
| 其他允许报文           | 4      | ICMP、带 Options 的 ICMP、ARP、设置 DF 的 TCP                         |
| 异常报文               | 8      | 版本号、IHL、Total Length、截断和不足的 TCP/UDP 头部长度              |
| IPv4 分片              | 4      | TCP 和 UDP 的首片与后续片                                             |

每帧使用不同的源 MAC 标识，捕获进程按本轮随机 MAC 前缀筛选。标识位于以太网头部，截断的 IPv4 报文也能被识别。允许报文必须逐字节保持一致并恰好收到一次，拒绝报文必须完全没有出现。

捕获进程准备好后才发送报文。测试检查所有收发进程的退出码和回复，捕获失败、发送失败、超时、丢包、重复或内容变化都会使测试失败。两个主机也必须实际收到允许流量，因此空捕获不能证明拒绝规则生效。

关键输出如下，其余场景逐行输出结果：

```text
h1-tcp80-options40: received=5/5, expected=5
h1-tcp22-options4: received=0/5, expected=0
h1-udp5000-options40: received=0/5, expected=0
h1-udp1234-port-like-options: received=5/5, expected=5
tcp-first-fragment: received=0/5, expected=0
udp-later-fragment: received=0/5, expected=0
SUCCESS: ACL decisions, IPv4 options and rejected packets match expectations
```

进入交互模式：

```bash
sudo ./run.sh cli
```

二层表只配置了两台主机的单播 MAC。使用 `pingall` 前，可在 Mininet CLI 中配置静态 ARP：

```text
h1 arp -s 10.0.0.2 00:00:00:00:00:02
h2 arp -s 10.0.0.1 00:00:00:00:00:01
pingall
```

无需启动交换机的回归测试在仓库根目录运行：

```bash
python3 -m unittest discover -s tests -p test_firewall_acl.py -v
```

## 范围

ACL 处理以太网直接承载的 IPv4，其他以太网类型继续按 MAC 表转发。本案例不解析 VLAN 或 IPv6，不跟踪 TCP 连接状态，也不解释 Options 的具体类型。

长度检查只针对上述解析所需的头部结构，不验证 IPv4、TCP 或 UDP 校验和。测试生成有效校验和，并检查允许报文的完整内容，确保 Options 在转发后得到保留。
