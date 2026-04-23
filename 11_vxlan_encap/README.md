# 📦 Case 11 · VXLAN 封装

> **学习目标**: 演示 **P4 如何给一个入包"套一层"**——把原始 Ethernet 帧裹进 Outer-Eth + Outer-IPv4 + UDP + VXLAN 头再输出。这是所有 Overlay (VXLAN / NVGRE / Geneve) 的基础动作。

## 拓扑

```
h1 --port 1-- s1 --port 2-- h2
      (plain frame)     (VXLAN wrapped)
```

## Pipeline

```
  +-- parse(inner_eth) --+
  |                       v
  vtep table (exact on inner dst MAC)
     |
     +-- encap(egress_port, outer_dmac, outer_smac,
               outer_sip,   outer_dip, vni)
           → emit outer_eth / outer_ipv4 / outer_udp / vxlan / inner_eth
```

解析器极简:只 extract 原始以太头。动作 `encap` 用 `setValid()` 把 4 个外层 header 填上,deparser 顺序拼接就得到完整 VXLAN 包。

## 控制器装的规则

```go
entry := tableentry.NewBuilder(p, "MyIngress.vtep").
    Match("hdr.inner_eth.dstAddr", tableentry.Exact(codec.MustMAC("00:00:00:11:11:11"))).
    Action("MyIngress.encap",
        tableentry.Param("egress_port", codec.MustEncodeUint(2, 9)),
        tableentry.Param("outer_dmac", codec.MustMAC("00:00:00:00:00:02")),
        tableentry.Param("outer_smac", codec.MustMAC("00:00:00:de:ad:01")),
        tableentry.Param("outer_sip", codec.MustIPv4("192.168.1.1")),
        tableentry.Param("outer_dip", codec.MustIPv4("192.168.1.2")),
        tableentry.Param("vni", codec.MustEncodeUint(5000, 24))).
    Build()
```

一条表项,6 个 action 参数,把所有外层头都参数化了——这样同一个 P4 程序可以支持任意多个 VTEP 目的地。

## 测试逻辑

1. h2 启动 sniffer,等待 `UDP.dport == 4789` 的包(VXLAN 标准端口)
2. h1 用 scapy 发一帧 `Ether(dst=00:00:00:11:11:11)/b"inner-payload"`
3. sniffer 抓到后解析:outer eth(14B) + outer ipv4(20B) + outer udp(8B) + vxlan(8B) 之后的 offset 就是 inner_eth
4. 校验 VNI == 5000,inner_dst == 00:00:00:11:11:11

## 运行

```bash
sudo ./run.sh
```

## 预期输出

```
    controller: vtep: inner_dmac=00:00:00:11:11:11 -> encap vni=5000, port=2
    controller: vxlan ready: 1 vtep entry installed
1
vni=5000 inner_dst=00:00:00:11:11:11
SUCCESS: VXLAN encap observed on h2 with VNI=5000 and expected inner MAC
```

## 延伸

- **双向(decap)**:增加一个 `decap` 表用来识别入向 VXLAN 包(outer UDP.dport == 4789)并 `setInvalid` 外层。需要修 parser 以区分 VXLAN 入包和普通入包。
- **多 VTEP**:vtep 表可以写多条,按不同 inner dst MAC 封装到不同 VNI/outer tunnel。
- **Overlay 路由**:让 inner 是 IPv4 包,控制器根据 inner dst 决定用哪个 VNI。这是 EVPN 的基础。
