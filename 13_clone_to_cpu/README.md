# 🐛 Case 13 · 克隆到 CPU(pre.CloneSession + PacketIn)

> **学习目标**: 用 **P4Runtime CloneSession** 把数据面的每个包拷贝一份送给控制器。BMv2 的 `simple_switch_grpc` 支持 `--cpu-port`,CPU 端口出的包会作为 `PacketIn` 流消息送到 gRPC stream。SDK 的 `client.OnPacketIn` 直接对接。

## Pipeline

```p4
const bit<32> CPU_CLONE_SESSION_ID = 99;

apply {
    meta.ingress_port = standard_metadata.ingress_port;   // 存到 meta
    cross_forward();                                       // 正常 1<->2 转发

    // 克隆一份给 CPU session 99;控制器把 session 的 replica 设成 cpu_port
    clone_preserving_field_list(CloneType.I2E, CPU_CLONE_SESSION_ID, 0);
}
```

egress 阶段识别"这是我刚 clone 出来的副本"(`instance_type == 1`),给它打上 `cpu_t` 头:

```p4
if (standard_metadata.instance_type == 1) {
    hdr.cpu.setValid();
    hdr.cpu.ingress_port   = (bit<16>)meta.ingress_port;
    hdr.ethernet.etherType = ETHERTYPE_CPU;  // 0x1010
}
```

## 控制器做两件事

```go
// 1) 告诉交换机:session 99 的复制品送到 cpu port (510)
preW.InsertCloneSession(ctx, pre.CloneSession{
    ID:       99,
    Replicas: []pre.Replica{{EgressPort: 510}},
})

// 2) 订阅 PacketIn
c.OnPacketIn(func(_ context.Context, msg *p4v1.PacketIn) {
    payload := msg.GetPayload()
    ethType := binary.BigEndian.Uint16(payload[12:14])
    ingressPort := binary.BigEndian.Uint16(payload[14:16])
    fmt.Printf("packet-in ... ingress_port=%d\n", ingressPort)
})
```

## 与 Case 05 (Digest) 的对比

| | Clone-to-CPU(本例) | Digest(Case 05) |
| --- | --- | --- |
| 通道 | **整包**通过 CPU 端口传 | 单条结构体(几个字段)通过 digest 通道传 |
| 代价 | 整包复制,流量大 | 只发摘要,轻量 |
| 用途 | 需要完整包内容做进一步处理(IDS、sFlow、复杂 ACL 学习) | 只需要字段值(MAC 学习、事件告警) |
| BMv2 操作码 | `clone_preserving_field_list(I2E, session_id, field_list_id)` + egress 改包 | `digest<T>(receiver, value)` |
| SDK API | `pre.Writer.InsertCloneSession` + `client.OnPacketIn` | `digest.NewSubscriber(...).OnDigest(...)` |

## 运行

```bash
sudo ./run.sh
```

## 预期输出

```
    controller: clone session 99 -> cpu port 510 installed
    controller: clone-to-cpu ready
*** h1 sending 10 frames to h2
    controller: packet-in #1  ingress_port=1 payload=...
    controller: packet-in #2  ingress_port=1 payload=...
    ...
packet-in arrivals: 20 (expected >= 10)
SUCCESS: every data-plane packet was cloned to the controller
```

arrivals 通常**大于**注入数量,因为 mininet host 自己会发 IPv6 RA / ARP 等背景流量,这些也走 clone 路径。**测试只要 ≥ 我们注入的 10 就算过**。

## 故障排查

**0 packet-ins**:  
- 检查 `P4RuntimeSwitch` 启动时传了 `cpu_port=510` 给 `simple_switch_grpc --cpu-port 510`。
- 检查 CloneSession insert 是否成功。BMv2 的 `pre.CloneSessionEntry` 要求 replica 是 CPU port 编号(对 simple_switch_grpc 是 `--cpu-port` 指定的那个)。

**packet-in 有但 ethType 不是 0x1010**:  
egress 的 `instance_type == 1` 没触发。检查 `clone_preserving_field_list` 调用是否在 ingress 的 apply 里。

## 延伸

- **反向(CPU 主动注入包)**: 使用 `client.SendPacketOut` 把整包从控制器送回 BMv2 的特定 egress port(如正好做一个"从 CPU 插入 ARP Reply"的把戏)。
- **过滤**: 不对所有包 clone,只对 ACL 命中的某一类;把 `clone_preserving_field_list` 放到 table action 里而不是 apply 末尾。
- **与 digest 组合**: 先让 smac 未知的包 digest 通知"有新 MAC",控制器决定感兴趣了再下个表条目让后续同源包 clone 到 CPU 看详情。
