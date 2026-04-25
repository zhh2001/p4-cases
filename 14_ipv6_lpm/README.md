# Case 14 — IPv6 LPM 路由

把"最长前缀匹配"从 32 位 IPv4 拉到 128 位 IPv6,顺手做一次最小可信的 L3 路由器：解析以太/IPv6 头、在 LPM 表里查下一跳、改写 MAC、递减 `hopLimit`、按端口转出。

## 核心知识点

| 元素 | 实际作用 |
| --- | --- |
| `bit<128> ip6Addr_t` | P4 原生支持 128 位字段,无需特殊宏 |
| `key = { hdr.ipv6.dstAddr: lpm; }` | 同一个 `lpm` 关键字处理 32 / 48 / 128 位前缀 |
| `default_action = drop` | 没匹配任何条目就直接丢弃,典型路由 FIB 缺省行为 |
| 控制器同时下 `/64` 和 `/128` | 演示"长前缀优先",这也是路由表里 host route 比 subnet route 高优先级的根因 |
| `hdr.ipv6.hopLimit - 1` | 在 P4 里减 1 是直接的算术,`hopLimit==0/1` 时进 ingress 早返回的 drop 分支 |

> **为什么 IPv6 不用 `MyComputeChecksum`?** IPv6 头里没有校验和字段(只有 L4 有),deparser 只 `emit(ethernet)` + `emit(ipv6)` 就把改动重新打包写出去。

## 拓扑

```
         h1 (00:01)──┐
                     │ port 1
         h2 (00:02)──┼─ s1 ─┐
                     │ port 2
         h3 (00:03)──┘
                       port 3
```

每个主机各自一个 /64:

| Host | MAC | IPv6 |
| --- | --- | --- |
| h1 | `00:00:00:00:00:01` | `2001:db8:1::1/64` |
| h2 | `00:00:00:00:00:02` | `2001:db8:2::1/64` |
| h3 | `00:00:00:00:00:03` | `2001:db8:3::1/64` |

主机出帧时把 dst MAC 设成"网关 MAC" `00:00:00:00:0a:01`,这个 MAC 对应"路由器在该入端口的接口"——在 P4 里 `ipv6_forward` 会用它当作出帧的 src MAC,从而完成一次完整的 L2 重写。

## 控制器装的 4 条路由

| 前缀 | 端口 | 下一跳 MAC | 备注 |
| --- | --- | --- | --- |
| `2001:db8:1::/64` | 1 | h1 MAC | h1 自己的子网 |
| `2001:db8:2::/64` | 2 | h2 MAC | h2 自己的子网 |
| `2001:db8:3::/64` | 3 | h3 MAC | h3 自己的子网 |
| `2001:db8:3::1/128` | 3 | h3 MAC | 与 /64 同下一跳,**专门用来证明 /128 比 /64 先匹配** |

## 自动化验证

`sudo ./run.sh` 会跑 4 条测试流:

| Flow | dst | 期望 |
| --- | --- | --- |
| A | `2001:db8:2::1` | h2 收 5 包,`hopLimit==63`,dst MAC 已写为 h2 MAC (`/64` 命中) |
| B | `2001:db8:3::1` | h3 收 5 包 (`/128` 比 `/64` 优先) |
| C | `2001:db8:3::42` | h3 收 5 包 (`/128` 没命中,回退到 `/64`) |
| D | `2001:db8:9::1` | h2/h3 都不应收到任何包 (无路由 -> drop) |

收到时 sniffer 会同时校验 `Ether.dst` 和 `IPv6.hlim`——只有同时满足"目标 MAC 已重写"+"hop_limit 已减 1"才计数,任何一项错都会被算作没收到,测试就失败。这就把"路由器有没有真把活儿干完"卡死了。

最终输出:

```
SUCCESS: IPv6 LPM (longer-prefix wins, hop_limit decrement, dst-MAC rewrite) all working
```

## 进 CLI 手动玩

```bash
sudo ./run.sh cli
```

进入 mininet shell 后,可以在 h1 上发任意目的的 IPv6 包看 BMv2 是否分发到正确端口:

```
mininet> h1 python3 -c "from scapy.all import *; sendp(Ether(src='00:00:00:00:00:01', dst='00:00:00:00:0a:01')/IPv6(src='2001:db8:1::1', dst='2001:db8:2::55', hlim=64)/b'hi', iface='h1-eth0')"
mininet> h2 tcpdump -nn -i h2-eth0 ip6
```

## 排错

**`Address already in use`**  
上次没干净退,先 `sudo mn -c && sudo pkill -f simple_switch_grpc`。

**没有任何 IPv6 包到达 h2/h3**  
最常见是 BMv2 把包 drop 了。看控制器日志确认 4 条路由都装上了；如果装上了但还是 drop,那很可能 `hopLimit` 已经为 0(scapy 默认 64,正常情况)或 ipv6 头解析失败(看 BMv2 stderr)。

**dst-MAC 没改写,sniffer 抓到的还是 `00:00:00:00:0a:01`**  
说明 LPM 没匹配上,落进了 `default_action = drop`,然后包被 BMv2 多播给 ingress port 之外的所有端口——但 BMv2 dropped packets 不会出现在任何端口上,所以这种情况通常不会发生。如果真发生了,检查 P4 是否把 action 顺序写错。
