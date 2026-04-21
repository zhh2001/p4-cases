# 📊 Case 08 · 按端口统计(Counter)

> **学习目标**: P4 的 **counter extern**,按 ingress 端口统计包数和字节数;控制器通过 P4Runtime `CounterEntry` **读**回累积值。

## Pipeline

```p4
counter(512, CounterType.packets_and_bytes) port_counter;
apply {
    port_counter.count((bit<32>)standard_metadata.ingress_port);
    // 教学目的:再做一个 1<->2 cross-forward,让包真的能到对端
    if (ingress == 1) egress = 2; else if (ingress == 2) egress = 1; else drop;
}
```

没有表,只有 counter extern + 硬编码 cross-forward(你也可以认为是"Case 02 + 计数器")。

## 交互模型

控制器不"订阅"counter,它的 API 是**按需读**。本案例让 Go 控制器在 `stdin` 上开一个命令循环:`dump` 一行 → 读一次 counter → 打印到 `stdout`。`topology.py` 在测试里发送 `dump`,然后发 20 帧,再 `dump`,对比增量。

## 文件

| 文件 | 作用 |
| --- | --- |
| `indirect_counter.p4` | 间接 counter(容量 512,用 ingress_port 当索引) |
| `direct_counter.p4` | 直接 counter(供对比) |
| `controller/main.go` | 推 pipeline + 处理 `dump` 命令 + 通过 `counter.NewReader` 读取 |
| `topology.py` | 2 主机;调用 `dump`、发 20 帧、再 `dump`、验证 port 1 增量 ≥ 20 |

## Go 控制器要点

```go
r, _ := counter.NewReader(c, p)
for _, port := range []int64{1, 2} {
    entries, _ := r.Read(ctx, "MyIngress.port_counter", port)   // port=具体索引
    var pkts, bytes int64
    for _, e := range entries {
        pkts += e.Packets
        bytes += e.Bytes
    }
    fmt.Printf("port=%d packets=%d bytes=%d\n", port, pkts, bytes)
}
```

`counter.NewReader(c, p).Read(ctx, "<name>", index)` —— `index=-1` 读所有条目,非负则读单条。

## 运行

```bash
sudo ./run.sh
```

## 预期输出

```
    controller: counter ready; send 'dump' on stdin to print port_counter[1..2]
*** Initial counter snapshot
    controller: port=1 packets=0 bytes=0
    controller: port=2 packets=0 bytes=0
*** Sending 20 frames from h1
*** Post-blast counter snapshot
    controller: port=1 packets=1208 bytes=18692
    controller: port=2 packets=9 bytes=782
port 1 packet delta = 1208 (expected >= 20)
SUCCESS: port 1 counter incremented by the blasted frames
```

port 1 增量远大于 20 的原因:mininet host 每秒会自发送 IPv6 RA / ARP / broadcast 等,这些也进了 counter。**只有一个条件必须成立**:port 1 增量 ≥ 我们的 20 帧。

## 延伸

- **重置 counter**:P4Runtime 没有通用 reset;常规做法是 MODIFY counter 条目,把值清零。SDK `counter.Reader.Write(ctx, name, idx, 0, 0)` 能做到。
- **Direct counter**:`direct_counter.p4` 展示把 counter 绑在表上,和 meter 的 direct 变体是对偶结构。
