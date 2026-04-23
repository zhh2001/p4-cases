# 🌐 Case 09 · ECMP 等价多路径

> **学习目标**: 用 **5-tuple hash** 把同一前缀的流量分摊到多个等价下一跳。单条流始终走同一条路径(避免乱序),不同流之间按 hash 分布。

## 拓扑

```
          h2 (port 2)
           |
    h1 -- s1
           |
          h3 (port 3)
```

1 交换机,3 主机。h1 是流量源,h2 和 h3 是两个 ECMP 成员。

## Pipeline 架构

```
hdr.ipv4.dstAddr ─LPM─> ipv4_lpm ──┬─ set_nhop(direct, 对 /32)
                                   │
                                   └─ set_ecmp_select(base, count) ──hash──> meta.ecmp_select
                                                                             │
                                                                             └─> ecmp_nhop (exact)
                                                                                    │
                                                                                    └─ set_nhop(具体下一跳)
```

两张表:`ipv4_lpm` 做目的 IP 路由决策(同时有 direct /32 条目和 /24 ECMP 条目),命中 `set_ecmp_select` 时触发哈希写入 `meta.ecmp_select`,再用它去 `ecmp_nhop` 表选最终下一跳。

Hash 覆盖 5-tuple:`(srcAddr, dstAddr, protocol, udp.srcPort, udp.dstPort)` 经 CRC-16 → `ecmp_select` 值。

## 控制器布表

| 表 | 条目 |
| --- | --- |
| `ipv4_lpm` | `10.0.0.1/32 → set_nhop(port=1, mac=h1)` 等 3 条 direct,**以及** `10.0.0.0/24 → set_ecmp_select(base=0, count=2)` |
| `ecmp_nhop` | `[0] → port 2 (h2)`,`[1] → port 3 (h3)` |

LPM 最长前缀匹配保证 direct /32 胜过 /24,h1/h2/h3 自身的回包不重入 ECMP。

## 测试

`topology.py` 从 h1 发 20 个 UDP 包,**sport 从 1000 到 1019 递增**,dport 固定 5000,dst IP 全部 `10.0.0.100`(不存在的主机,但 /24 的 ECMP 条目会接管)。sniffer 分别在 h2 和 h3 抓取带 `b"ecmp-test"` 前缀的 UDP payload。

期望:`h2+h3 合计 == 20` 且 `h2 > 0 && h3 > 0`。

## 运行

```bash
sudo ./run.sh        # 流量分布测试
sudo ./run.sh cli    # 进 mininet CLI
```

## 预期输出

```
    controller: 10.0.0.0/24 -> ecmp group(base=0, count=2)
    controller: ecmp_nhop[0] -> port 2 mac 00:00:00:00:00:02
    controller: ecmp_nhop[1] -> port 3 mac 00:00:00:00:00:03
    controller: ecmp ready: 3 direct routes + 2-way ECMP group
h2 received: 10/20
h3 received: 10/20
SUCCESS: ECMP distributed 20/20 flows across both members
```

具体数字会因 hash 种子略有浮动(CRC-16 对连续 sport 常常 50/50 均分,其它序列可能偏斜)。

## 延伸

- **增加 ECMP 成员数**:改控制器中的 `ecmp_count` + 增加 `ecmp_nhop` 条目。
- **加权 ECMP**:给"更重"的下一跳在 `ecmp_nhop` 里重复几个索引(WCMP,Weighted)。
- **故障切换**:检测某路径 down 后把 `ecmp_count` 从 2 改回 1(MODIFY `ipv4_lpm` 条目)。
