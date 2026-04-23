# 🛡️ Case 10 · 防火墙 ACL(TERNARY + priority)

> **学习目标**: 用 **TERNARY 匹配 + 优先级** 实现经典五元组防火墙。同一张表里低优先级的"宽泛 allow"与高优先级的"特定 deny"可以共存,P4Runtime 会按 priority 最高者胜。

## 拓扑

2 主机,1 交换机:`h1 (10.0.0.1) <-> s1 <-> h2 (10.0.0.2)`。

## Pipeline

```
dmac (exact, L2 forward) → acl (ternary, 4 字段)
```

ACL 键:`(srcIP, dstIP, protocol, dstPort)`。
动作:`allow` (no-op) / `deny` (drop) / `NoAction`。
**默认动作 = `allow`**,即"没规则命中就放行"——所以控制器只需装 deny 规则,类似 iptables 的白名单反向。

## 控制器装的规则

| Priority | src | dst | proto | dport | 动作 |
| --- | --- | --- | --- | --- | --- |
| 100 | `*` | `10.0.0.2/32` | TCP(6) | 22 | **DENY** |
|  90 | `*` | `10.0.0.2/32` | TCP(6) | `*` | ALLOW |
|  80 | `10.0.0.1/32` | `*` | UDP(17) | 5000 | **DENY** |

"允许 h2 上的所有 TCP 服务,**除了** SSH(22)"——标准的高优先级例外模式。

## 测试

4 条流:

| 流 | 期望 | 实测 |
| --- | --- | --- |
| h1 → h2 TCP/80 | ALLOW(规则 2) | 5/5 |
| h1 → h2 TCP/22 | DENY(规则 1 比 2 优先) | 0/5 |
| h1 → h2 UDP/5000 | DENY(规则 3) | 0/5 |
| h1 → h2 UDP/1234 | ALLOW(default_action) | 5/5 |

## Go 控制器要点

TERNARY 匹配在 SDK 里是:

```go
tableentry.NewBuilder(p, "MyIngress.acl").
    Match("hdr.ipv4.srcAddr",
        tableentry.Ternary([]byte{0,0,0,0}, []byte{0,0,0,0})).   // don't-care
    Match("hdr.ipv4.dstAddr",
        tableentry.Ternary(codec.MustIPv4("10.0.0.2"),
                           []byte{0xff,0xff,0xff,0xff})).        // exact
    Match("hdr.ipv4.protocol",
        tableentry.Ternary([]byte{6}, []byte{0xff})).             // TCP
    Match("hdr.l4.dstPort",
        tableentry.Ternary(codec.MustEncodeUint(22, 16),
                           []byte{0xff, 0xff})).                  // port 22
    Action("MyIngress.deny").
    Priority(100).
    Build()
```

mask 全 0 表示"这个字段不关心"。P4Runtime 要求 TERNARY 表每条必须有 `priority` 字段,**priority 数字越大越优先**。

## 运行

```bash
sudo ./run.sh
```

## 延伸

- **加反向规则**:让 h2 → h1 的 ICMP 也能走(本案例里 ICMP 的 protocol=1 无 L4 端口,但 L4 parser 会跳过 → 只有前 3 个字段参与匹配)。
- **stateful firewall**:给 P4 加一个 register 跟踪 TCP 三次握手状态,控制器可以读取活跃会话。
- **rate-limited drop**:结合 Case 07 的 meter,把 DENY 替换成"允许但 rate-limit"。
