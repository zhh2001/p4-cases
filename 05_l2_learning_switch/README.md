# 🧠 Case 05 · L2 学习交换机(Digest)

> **学习目标**: 理解**数据面通知控制面**的机制。交换机通过 `digest<T>` 把"我看见了一个陌生源 MAC"的事件推送给控制器,控制器根据事件回填 `smac` + `dmac` 表,完成 **MAC 自学习**。

## 与 Case 04 的区别

- `dmac` 表仍是单播 exact,**`smac` 表**同步引入:键 = 源 MAC,默认 action = `mac_learn` → 触发 digest。
- 控制器**订阅** `learn_t` digest;每次收到 `(srcAddr, ingress_port)` 就:
  1. 给 `smac` 加一条 `srcAddr → NoAction`(下次同源就不再触发 digest)
  2. 给 `dmac` 加一条 `srcAddr → forward(ingress_port)`(回包路径已学会)
- 未知目的依然靠 Case 04 的多播组 flood。

这就是**真·自学习交换机**,和生产级 L2 交换机的控制面逻辑本质相同。

## 文件

| 文件 | 作用 |
| --- | --- |
| `main_digest.p4` | 三表 pipeline:`smac`(学) + `dmac`(转) + `broadcast`(泛洪) |
| `main_cpu.p4` | 另一种学习模式:通过 `clone_preserving_field_list` 把拷贝塞给 CPU 端口(需 `pre.CloneSession`,留作拓展)|
| `topology.py` | 4 主机拓扑 |
| `controller/main.go` | 推 pipeline + 初始化 PRE + **订阅 digest** + 动态回填表 |
| `run.sh` | 跑两轮 pingAll;第二轮应命中纯单播快路径 |

## P4 要点

```p4
action mac_learn() {
    meta.learn.srcAddr = hdr.ethernet.srcAddr;
    meta.learn.ingress_port = standard_metadata.ingress_port;
    digest<learn_t>(1, meta.learn);   // <-- 关键:通知控制面
}

table smac {
    key     = { hdr.ethernet.srcAddr: exact; }
    actions = { mac_learn; NoAction; }
    default_action = mac_learn;        // 未匹配 = 陌生 MAC,触发 digest
}
```

## Go 控制器要点

```go
digestSub, _ := digest.NewSubscriber(c, p)
digestSub.OnDigest("learn_t", func(ctx context.Context, msg *p4v1.DigestList) {
    for _, member := range msg.GetData() {
        srcMAC, ingressPort, _ := decodeLearnStruct(member)
        installLearned(ctx, c, p, srcMAC, ingressPort)    // smac + dmac
    }
    digestSub.Ack(ctx, msg)      // 必须 ack,否则 BMv2 会重发
})
```

其中 `decodeLearnStruct` 把 digest 的 `P4Data.Struct` 反序列化成 `(mac bytes, port uint32)`。

## 运行

```bash
sudo ./run.sh          # 跑两轮 pingAll
```

## 预期输出

```
    controller: learning-switch ready: 4 ports, flooding unknown destinations
*** Running pingAll — MAC learning occurs in-flight
*** Results: 0% dropped (12/12 received)
*** Running pingAll again — everything should now be unicast
*** Results: 0% dropped (12/12 received)
SUCCESS: learning switch reached steady state
```

## 与 CPU-Clone 变体的关系

仓库里的 `main_cpu.p4` 演示了**另一种**学习路径——用 `clone_preserving_field_list` 把拷贝塞回 CPU 端口,控制器在那里 sniff。它需要 `pre.CloneSession`。本案例默认走 digest 路径,因为 digest 是 P4Runtime 原生机制、控制面开销更小。

## 延伸

- **移除 MAC 老化**:真设备上 MAC 会过期;本案例未实现,练习题:给控制器加一个 idle timeout + 在 `dmac` 上启用 `IdleTimeoutNs`(SDK 支持)。
- **多交换机 MAC 学习**:Case 06 是多交换机案例,但走 L3 路由;L2 跨交换机学习需要中间广播,留作拓展。
