# 🧭 Case 03 · 静态 L2 转发交换机

> **学习目标**: 从"硬编码 if-else"(Case 02)升级到"**表驱动**"——用 exact 匹配的 `dmac` 表把目的 MAC → 出端口。这是 match-action 编程范式的第一课。

## 拓扑

星型:1 交换机,4 主机(h1..h4)。每个主机 IP `10.0.0.N`,MAC `00:00:00:00:00:0N`,连在 s1 的 port N 上。

## 功能

- 控制器向 `dmac` 表写入 4 条:`MAC → 出端口 N`。
- 因为 P4 **只做 exact 单播**,ARP 广播不会被表匹配,所以 `topology.py` 预先给每台主机灌了静态 ARP 表。
- `pingAll` 应 100% 通。

## 文件

| 文件 | 作用 |
| --- | --- |
| `main.p4` | `dmac` exact 表,命中调用 `forward(port)` |
| `topology.py` | 4 主机拓扑 + 静态 ARP 注入 |
| `controller/main.go` | 推 pipeline + 写 4 条 dmac 表项 |
| `run.sh` | 一键编译 + 启动 + `pingAll` |

## P4 要点

```p4
table dmac {
    key     = { hdr.ethernet.dstAddr: exact; }
    actions = { forward; NoAction; }
    size    = 256;
    default_action = NoAction;
}
```

## Go 控制器要点

```go
for n := 1; n <= 4; n++ {
    mac := fmt.Sprintf("00:00:00:00:00:%02d", n)
    entry, _ := tableentry.NewBuilder(p, "MyIngress.dmac").
        Match("hdr.ethernet.dstAddr", tableentry.Exact(codec.MustMAC(mac))).
        Action("MyIngress.forward",
            tableentry.Param("egress_port", codec.MustEncodeUint(uint64(n), 9))).
        Build()
    c.WriteTableEntry(ctx, client.UpdateInsert, entry)
}
```

注意**名字全是 P4 编译器给出的"全限定名"**:表 `MyIngress.dmac`,action `MyIngress.forward`,字段 `hdr.ethernet.dstAddr`。用 `p4c --p4runtime-files` 产出的 `main.p4info.txt` 自检。

## 运行

```bash
sudo ./run.sh          # pingAll,期待 0% 丢包
sudo ./run.sh cli      # 进入 mininet CLI
```

## 预期输出

```
    controller: dmac 00:00:00:00:00:01 -> port 1 installed
    controller: dmac 00:00:00:00:00:02 -> port 2 installed
    controller: dmac 00:00:00:00:00:03 -> port 3 installed
    controller: dmac 00:00:00:00:00:04 -> port 4 installed
*** Results: 0% dropped (12/12 received)
SUCCESS: full mesh reachable via dmac table
```

## 延伸

- **不灌静态 ARP 也能 ping 通**:需要广播机制,交给 Case 04。
- **MAC 学习而非手工**:交给 Case 05。
