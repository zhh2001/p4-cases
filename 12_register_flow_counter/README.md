# 📈 Case 12 · 基于 Register 的逐流计数器

> **学习目标**: P4 register 作为**用户控制的数据面状态**——自己决定索引怎么算、写什么、什么时候读,比 counter extern 灵活得多。

## 与 Case 08(counter)的区别

| | Case 08 · Counter | Case 12 · Register |
| --- | --- | --- |
| 索引选择 | 只能是 action 参数或直接索引(ingress_port) | **任意表达式**,例如 hash(5-tuple) |
| 语义 | 包数+字节数,自动维护 | 单个 bit<W> 值,**P4 程序决定**如何更新 |
| 可做 | 简单包/字节统计 | 状态机、阈值、流调度… |
| P4Runtime 读 | ✅ `CounterEntry` | ⚠️ BMv2 的 `RegisterEntry` 目前 **Unimplemented**,本案例用 **BMv2 Thrift CLI** 读回 |

## Pipeline

```p4
register<bit<32>>(1024) flow_counter;

apply {
    cross_forward();     // 1 <-> 2 转发
    if (hdr.udp.isValid()) {
        slot_t slot;
        hash(slot, HashAlgorithm.crc16, (bit<16>)0,
             { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
               hdr.udp.srcPort,  hdr.udp.dstPort },
             (bit<16>)1024);         // [!] 类型关键:比 slot_t 宽
        bit<32> current;
        flow_counter.read(current, (bit<32>)slot);
        flow_counter.write((bit<32>)slot, current + 1);
    }
}
```

**踩过的坑**: `hash(...)` 的 `max` 参数用 `(bit<10>)1024` 会溢出为 0,BMv2 会警告 `hash max given as 0, but treating it as 1`,所有包塞进 slot 0(或 1)。**`max` 必须用比 slot 更宽的类型**。这里用 `bit<16>`。

## 测试方式

1. 控制器推 pipeline(register.Write 走 P4Runtime,BMv2 返回 Unimplemented,日志 warn)
2. run.sh 从 h1 发 30 个 **5-tuple 完全相同** 的 UDP 包
3. 所有包会 hash 到同一个 slot(实测是 slot 986)
4. 测试用 `simple_switch_CLI` 通过 Thrift(:9090)读 `flow_counter`,解析数组确认 slot 986 = 30

## Go 控制器要点

```go
r, _ := register.NewReader(c, p)
r.Write(ctx, "MyIngress.flow_counter", 1023, codec.MustEncodeUint(42, 32))
// ↑ 若 BMv2 支持 P4Runtime register write,slot 1023 会被置 42;
//   现在 BMv2 返回 Unimplemented,只是一个"API 能 call,target 没支持"的 warn。
```

P4Runtime 本身**规范上**支持 register 读写;但 BMv2 2024 之前的发布一直没接入 `RegisterEntry` handler。`p4lang/behavioral-model#PR-XXXX` 有进展,关注即可。

## 运行

```bash
sudo ./run.sh
```

## 预期输出

```
    controller: warn: register write not accepted by BMv2 (...) — continuing
    controller: register-counter ready
*** Sending 30 identical-5-tuple UDP packets from h1
*** Dumping flow_counter via Thrift :9090
--- thrift dump ---
RuntimeCmd: flow_counter= 0, 0, 0, ..., 30, ..., 0
--------------------
slot=986 value=30
largest data-plane slot: slot=986 value=30
SUCCESS: 30-packet flow counted into register slot 986 (val=30)
```

## 延伸

- **实时 top-N 流统计**: 每个 slot 除计数外再存 5-tuple 摘要,周期性读取最大值。
- **滑动窗口**: 用两个 register 数组轮转,控制器定时"翻页"。
- **阈值黑名单**: 当某 slot 超过阈值,再在 ACL 表里插 deny 规则(需要控制器订阅)。
- **切回 counter extern**: 若只关心包/字节数,Case 08 的 direct/indirect counter 更简单,P4Runtime 读取也有支持。
