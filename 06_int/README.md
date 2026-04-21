# 🛰️ Case 06 · 带内网络遥测(INT)

> **学习目标**: 多交换机(3 台)转发 + **IPv4 Options** 承载的 INT 元数据。数据面在转发时**顺手注入自己的 swid / 队列深度 / 出端口**,控制面只负责"装好表,其他我不管"。

## 拓扑

```
            h4
             │
             │
h1 ── s1 ── s3 ── h3
      │
      s2
      │
      h2
```

端口编号(与 `controller/main.go` 里的 `switchConfig` 一致):

| 交换机 | port 1 | port 2 | port 3 |
| --- | --- | --- | --- |
| s1 | h1  | s2   | s3   |
| s2 | h2  | s1   | —    |
| s3 | h3  | h4   | s1   |

IP / MAC:

| 主机 | IP | MAC |
| --- | --- | --- |
| h1 | 10.0.1.1 | 00:00:0a:00:01:01 |
| h2 | 10.0.2.2 | 00:00:0a:00:02:02 |
| h3 | 10.0.3.3 | 00:00:0a:00:03:03 |
| h4 | 10.0.3.4 | 00:00:0a:00:03:04 |

## 功能

- 每台交换机是**IPv4 LPM 路由器**:匹配目的 IP 前缀 → 重写 dst MAC + 设置 egress。
- 若数据包**携带 INT IPv4 Option**(option number 31),egress pipeline **追加**一段 `SwitchTrace(swid, qdepth, portid)`。多跳之后接收端能看到完整路径。
- h1 → h2 途中经过 s1 和 s2,接收方看到 INT 栈包含 2 条(s1 和 s2 的 swid)。

## 文件

| 文件 | 作用 |
| --- | --- |
| `main.p4` | 完整 INT pipeline(带 ingress LPM 路由 + egress INT 注入 + IPv4 checksum 重算) |
| `topology.py` | 3 交换机 4 主机拓扑,并行拉起 3 个 BMv2 实例(9559/9560/9561) |
| `controller/main.go` | 单一 Go 程序,用 `-switch-id` 区分 s1/s2/s3,各自装不同的 LPM 表和 `int_table` 默认动作 |
| `test_send.py` | h1 发一个预封装了空 INT option 的 UDP 包 |
| `test_receive.py` | h2 捕获并解析 INT 栈,验证含 s1 + s2 |
| `run.sh` | 编译 + 3 控制器并行 + 自动验证 |

## P4 要点

INT 头的"逐跳追加"靠 egress:

```p4
action add_int_header(switch_id_t swid){
    hdr.int_count.num_switches = hdr.int_count.num_switches + 1;
    hdr.int_headers.push_front(1);
    hdr.int_headers[0].setValid();
    hdr.int_headers[0].switch_id  = (bit<13>)swid;
    hdr.int_headers[0].queue_depth = (bit<13>)standard_metadata.deq_qdepth;
    hdr.int_headers[0].output_port = (bit<6>) standard_metadata.egress_port;
    hdr.ipv4.ihl = hdr.ipv4.ihl + 1;
    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
    hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 4;
}

table int_table {
    actions = { add_int_header; NoAction; }
    default_action = NoAction();       // 控制器把它改成 add_int_header(我的 swid)
}
```

## Go 控制器要点

同一二进制,三份配置:

```go
func configFor(switchID uint64) switchConfig {
    switch switchID {
    case 1: return switchConfig{
        deviceID: 1, switchID: 1,
        lpm: []lpmEntry{
            {"10.0.1.1", 32, "00:00:0a:00:01:01", 1},
            {"10.0.2.2", 32, "00:01:0a:00:02:02", 2},
            {"10.0.3.0", 24, "00:00:00:03:01:00", 3},
        }}
    case 2: ...
    case 3: ...
    }
}
```

动态改**表默认动作**:

```go
defInt, _ := tableentry.NewBuilder(p, "MyEgress.int_table").
    AsDefault().
    Action("MyEgress.add_int_header",
        tableentry.Param("swid", codec.MustEncodeUint(cfg.switchID, 13))).
    Build()
c.WriteTableEntry(ctx, client.UpdateModify, defInt)   // 注意是 MODIFY
```

(P4Runtime 约定:写默认动作用 `MODIFY`,不是 `INSERT`。)

## 运行

```bash
sudo ./run.sh          # 自动 send/receive 测试
sudo ./run.sh cli      # 进 mininet CLI 自己玩(h1 可以 ping h2)
```

## 预期输出

```
    ctrl1: s1 ready
    ctrl2: s2 ready
    ctrl3: s3 ready
*** Sending INT-carrying UDP packet h1 -> h2
received: src=00:01:0a:00:02:02 dst=00:00:0a:00:02:02
IP: 0.0.0.0 -> 10.0.2.2 ihl=8
INT count=2
  swid=2 qdepth=0 portid=1
  swid=1 qdepth=0 portid=2
SUCCESS: INT stack carries s1 and s2 traces
```

INT 栈的顺序是**倒序**:`swid=2` 在前(最新 push,即 s2 egress),`swid=1` 在后(更早 push,s1 egress)。这是 `push_front` 造成的,符合规范。

## 故障排查

**INT 栈只有 1 条**:  
某台交换机的 `int_table default_action` 没设成 `add_int_header`。检查控制器日志,确认 3 个 "int_table default = add_int_header(swid=N)" 都出现。

**`SUCCESS` 失败并打出"no UDP packet received"**:  
静态 ARP 或 LPM 某条配错了。按日志看哪一跳丢。用 `sudo ./run.sh cli` 进入 mininet,在 h1 上 `tcpdump -i h1-eth0`,在 h2 上也 tcpdump,对比看包停在哪一跳。

## 延伸

- 真实 INT 规范(INT-MD)要复杂得多——本案例是最简化的"教学 INT"。想做生产级可以参考 `p4lang/p4app-int` 或 `hyperxpro/in-band-network-telemetry`。
- 本案例**不统计 qdepth / latency**;仅记录 swid + port。加上时间戳字段就是一个完整的 P-Telemetry 基座。
