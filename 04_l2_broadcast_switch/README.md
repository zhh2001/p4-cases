# 📣 Case 04 · L2 广播交换机(PRE / MulticastGroup)

> **学习目标**: 引入 **Packet Replication Engine (PRE)**——目的 MAC 未知时 **泛洪(flood)** 到除入端口外的所有端口。ARP 广播第一次即可工作。

## 相对 Case 03 的增量

- `dmac.apply()` 未命中时,不再丢弃,而是转到 `select_mcast_grp` 表(键=入端口,动作 = 设置 `standard_metadata.mcast_grp`)。
- **每个入端口对应一个不同的 multicast group**(flood-except-self 集合):
  - ingress=1 → group 1 = {2, 3, 4}
  - ingress=2 → group 2 = {1, 3, 4}
  - ingress=3 → group 3 = {1, 2, 4}
  - ingress=4 → group 4 = {1, 2, 3}

Multicast group 本身**不是**一张 P4 表,而是 P4Runtime 的 `PacketReplicationEngineEntry`。本案例首次用到 SDK 的 `pre` 包。

## 文件

| 文件 | 作用 |
| --- | --- |
| `main.p4` | `dmac` + `select_mcast_grp` 两张表,`if (!dmac.hit) select_mcast_grp.apply();` |
| `topology.py` | 4 主机拓扑,**不**灌静态 ARP(广播机制自己去处理) |
| `controller/main.go` | 推 pipeline + dmac 表项 + 4 个 MulticastGroup + 4 个 select_mcast_grp 表项 |

## Go 控制器要点

```go
preW, _ := pre.NewWriter(c)
for ingress := 1; ingress <= 4; ingress++ {
    replicas := []pre.Replica{}
    for p := 1; p <= 4; p++ {
        if p != ingress {
            replicas = append(replicas, pre.Replica{EgressPort: uint32(p)})
        }
    }
    preW.InsertMulticastGroup(ctx, pre.MulticastGroup{
        ID:       uint32(ingress),
        Replicas: replicas,
    })
}
```

SDK 的 `pre.Writer` 屏蔽了 `PacketReplicationEngineEntry` 这种 proto 细节,直接操作 `MulticastGroup` 对象。

## 运行

```bash
sudo ./run.sh          # pingAll,不需要预先 ARP
sudo ./run.sh cli      # 手动验证
```

## 预期输出

```
    controller: multicast group 1 = ports [2 3 4]
    controller: multicast group 2 = ports [1 3 4]
    controller: multicast group 3 = ports [1 2 4]
    controller: multicast group 4 = ports [1 2 3]
    controller: broadcast-switch ready: 4 dmac entries, 4 multicast groups
*** Results: 0% dropped (12/12 received)
SUCCESS: ARP + unicast reachable via dmac + multicast groups
```

## 延伸

- **仍然要手写 dmac 表项**:下一个案例(05)会让控制器通过 digest 事件**自动学习** MAC,无需手写。
- **广播风暴风险**:真实设备上多播组不能随便配,否则环路会把整个网络打挂。教学中 mininet 拓扑无环,所以没问题。
