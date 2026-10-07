# Case 12：基于 Register 的 UDP 流计数

本案例使用 1024 个 32 位 register 槽位统计 UDP 包数。P4 根据流量字段计算索引，再读取计数、加一并写回。不同 UDP 流可能落入同一槽位，该槽位保存这些流的包数之和。

Case 08 的 counter 由 extern 维护包数和字节数。本案例由 P4 程序决定 register 的索引与更新方式，适合演示自定义数据面状态。

## 拓扑与转发

```text
h1 (port 1) -- s1 -- (port 2) h2
```

h1 和 h2 的地址为 `10.0.0.1/24` 和 `10.0.0.2/24`，MAC 分别为 `00:00:00:00:00:01` 和 `00:00:00:00:00:02`。交换机将端口 1 和端口 2 的报文交叉转发，保留 MAC、TTL、校验和、Options 和负载。

本案例做二层转发，TTL 为 0 或 1 的合法 IPv4 报文也保持原样。ARP、非 IPv4 报文及其他 IP 协议可以转发，但不增加 UDP 流计数。

## 数据面计数

只统计合法且未分片的 IPv4 UDP 报文。解析器根据 IHL 读取 IPv4 Options，再读取 UDP 头，并检查 IPv4 版本、头长、总长、UDP 长度以及覆盖 Options 的 IPv4 校验和。格式异常或 IPv4 校验和错误时丢弃报文，不更新 register。

IPv4 分片正常转发，首片、中间片和末片都不参与 UDP 流计数，分片负载不会被当成端口读取。

协议固定为 UDP，因此实际哈希输入是四个字段：源 IP、目的 IP、源端口和目的端口。索引为 `CRC16(input) % 1024`，范围是 0 到 1023。IPv4 Options、包标识、负载和入端口不参与哈希。

```p4
register<bit<32>>(1024) flow_counter;

hash(slot, HashAlgorithm.crc16, (bit<16>)0,
     { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
       hdr.udp.srcPort, hdr.udp.dstPort },
     (bit<16>)1024);

@atomic {
    bit<32> current;
    flow_counter.read(current, (bit<32>)slot);
    flow_counter.write((bit<32>)slot, current + 1);
}
```

`max` 参数使用 `bit<16>`，能够表示 1024。计数采用 32 位无符号算术，超过 `0xffffffff` 后回绕到零。读、加一和写回放在 `@atomic` 块中，相关要求见 [v1model register 说明](https://github.com/p4lang/p4c/blob/main/p4include/v1model.p4)。

## 控制器与寄存器读取

控制器安装 pipeline，并尝试通过 P4Runtime 将槽位 1023 设为 42。成功时记录写入结果，明确返回 `Unimplemented` 时跳过该写入。连接、权限、参数或超时等其他失败会使控制器退出。

P4Runtime 的逐项写入错误可以封装在 `Unknown` 状态中，控制器检查其中的错误详情，避免把所有 `Unknown` 都当成“不支持”。当前运行环境的 register 读写支持情况由实际响应确认。

自动验证通过 `simple_switch_CLI` 的 Thrift 接口读取整个数组。每次读取必须包含全部 1024 个有效值，CLI 失败、错误提示、缺失槽位、重复槽位或格式异常都会使测试失败。

测试在本次创建的交换机上通过 Thrift 设置初值，并读回确认只有指定槽位变化。每组流量比较发送前后的完整快照，按 32 位回绕规则核对精确增量。

## 自动验证

默认发送 216 个报文，其中 192 个应完整转发，24 个应丢弃，168 个应增加 UDP 计数。测试分四组执行：

| 测试组                   | 发送 | 转发 | 丢弃 | 计数 |
| ------------------------ | ---- | ---- | ---- | ---- |
| `udp-flows`              | 104  | 104  | 0    | 104  |
| `collisions`             | 32   | 32   | 0    | 32   |
| `excluded-and-malformed` | 48   | 24   | 24   | 0    |
| `wraparound`             | 32   | 32   | 0    | 32   |

覆盖内容包括：

- 双向重复 UDP 流，变化的源 IP、目的 IP、源端口和目的端口。
- 4 字节和 40 字节 IPv4 Options、最小 UDP 头、1500 字节 IP 报文、UDP 零校验和和 TTL 边界。
- 两组不同流在槽位 0 和 1023 上碰撞，精确核对合并后的包数。
- ARP、TCP、其他 IP 协议及完整分片组正常转发，所有槽位保持不变。
- 丢弃 IPv4 或 UDP 长度异常、截断报文和 IPv4 校验和错误报文。
- 将槽位 0 设为 `0xfffffffe` 后，从两个入端口并行发送同一条 UDP 流的 32 个报文，最终值应为 30。

测试还验证已有非零值和空闲期间的数组稳定性。两个主机同时抓取带标记的入向报文，每包必须只到达对端一次，内容逐字节保持一致。发送失败、抓包失败、控制器退出或超时都会返回非零状态，并清理本次进程与网络。

## 运行

```bash
sudo ./run.sh
sudo ./run.sh cli
```

Mininet CLI 中可以运行 `pingall`，两个主机应互通。在另一终端启动 Thrift CLI：

```bash
simple_switch_CLI --thrift-port 9090
```

在 Thrift CLI 中输入：

```text
register_read MyIngress.flow_counter
```

默认自动验证的输出示例：

```text
register seed skipped: RegisterEntry write is unimplemented
register-counter ready
udp-flows: sent=104 forwarded=104 dropped=0 counted=104
collisions: sent=32 forwarded=32 dropped=0 counted=32
excluded-and-malformed: sent=48 forwarded=24 dropped=24 counted=0
wraparound: sent=32 forwarded=32 dropped=0 counted=32
SUCCESS: 216 frames preserve forwarding and exact register deltas
```

在仓库根目录运行相关回归测试：

```bash
/usr/bin/python3 -m unittest discover -s tests -p test_register_flow_counter.py -v
go test -race ./12_register_flow_counter/controller
```

## 文件说明

| 文件                 | 用途                                           |
| -------------------- | ---------------------------------------------- |
| `main.p4`            | 二层转发、IPv4 和 UDP 解析校验及 register 更新 |
| `controller/main.go` | 安装 pipeline、尝试 register 写入并处理退出    |
| `topology.py`        | 管理拓扑、解析完整数组、核对计数和交付         |
| `packets.py`         | 生成流量、计算 CRC16 槽位和寻找碰撞流          |
| `probe.py`           | 发送报文清单并抓取带标记的入向报文             |
| `run.sh`             | 编译、启动、自动验证和资源清理                 |
