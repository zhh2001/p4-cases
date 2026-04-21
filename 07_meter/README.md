# 🚦 Case 07 · 双速率三色计量器(Meter)

> **学习目标**: P4 的 **meter extern**——按源 MAC 对流量做"三色"分类,并对非绿色流量丢包。控制器通过 P4Runtime `MeterEntry` 配置速率。

## 什么是 meter?

双速率三色标记(trTCM)简化版:
- **Green (tag=0)**: 低于 CIR(承诺速率),通过。
- **Yellow (tag=1)**: CIR 和 PIR 之间,转发但标记。
- **Red (tag=2)**: 超出 PIR,丢弃(典型语义;本例中非 green 即丢)。

## Pipeline 两张表

```
apply {
    standard_metadata.egress_spec = 2;   // 任意包默认出 port 2
    m_read.apply();                      // src MAC → 选 meter 实例 → 写入 meta.meter_tag
    m_filter.apply();                    // 根据 meta.meter_tag 决定过/丢
}
```

`m_read` 命中时执行 `my_meter.execute_meter(index, meta.meter_tag)`;未命中则 tag 保持 0(默认 green)。`m_filter` 只为 tag=0 配置了 NoAction,其余 tag 被**默认 action = drop** 吞掉。

## 本案例的配置

| MAC | 效果 |
| --- | --- |
| `aa:aa:aa:aa:aa:aa` | 命中 `m_read` → meter 着色 → 超速即丢 |
| 其它 | 跳过 meter → 始终 green → 始终通过 |

meter 速率(`controller/main.go` 里通过 flag 可调):

```
CIR=10 pps   CBurst=5 packets
PIR=20 pps   PBurst=10 packets
```

## 文件

| 文件 | 作用 |
| --- | --- |
| `indirect_meter.p4` | 间接 meter (8192 个实例,action 参数选实例) |
| `direct_meter.p4` | 直接 meter (绑定在表上,实例即条目,供参考对比) |
| `topology.py` | 2 主机拓扑;发两组突发流量并统计收到数量 |
| `controller/main.go` | 推 pipeline + 写 `m_read` + `m_filter` + `MeterEntry` 配速率 |

## Go 控制器要点

```go
mr, _ := meter.NewReader(c, p)
mr.Write(ctx, "MyIngress.my_meter", meterIndex /*0*/, meter.Config{
    CIR: 10, CBurst: 5, PIR: 20, PBurst: 10,
})
```

SDK 的 `meter.NewReader` 虽然名字含 Reader,但 Read 和 Write 都提供。Write 对应 P4Runtime 的 `MeterEntry` MODIFY。

## 运行

```bash
sudo ./run.sh
```

## 预期输出

```
    controller: m_read: src=aa:aa:aa:aa:aa:aa -> m_action(index=0)
    controller: m_filter: tag=0 -> NoAction (non-zero tags drop via default)
    controller: meter[0]: CIR=10 cburst=5 PIR=20 pburst=10
    controller: meter-switch ready: metered src=aa:aa:aa:aa:aa:aa, cburst=5 packets
*** Phase 1: send 30 packets from non-metered src (expect ~30 on h2)
*** Phase 2: send 30 packets from metered src (expect partial drop)
Unmetered received: 30/30
Metered   received: 22/30
SUCCESS: non-metered MAC passes, metered MAC experiences drops
```

`22/30` 的具体数字会因调度和 BMv2 实时抖动略有不同,但**必然明显低于 30**。

## 延伸

- **Yellow 单独处理**:再加一个 `m_filter` 条目 `tag=1 → some_action` 来放行但标记(如改 DSCP)。
- **Direct meter**:`direct_meter.p4` 里 meter 绑在 `m_read` 表上,实例即表条目。
