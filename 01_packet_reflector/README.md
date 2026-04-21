# 📦 Case 01 · Packet Reflector

> **学习目标**：理解 P4 最小处理模型 `Parse → Match-Action → Deparse`;看懂控制器只做 **推 pipeline** 这一件事，不下任何表项。

## 功能

单交换机 `s1` + 单主机 `h1`。交换机收到任何数据包,**交换源/目的 MAC**,然后**从入端口原路送回**。主机发 1 帧即收到 1 帧,MAC 已对调。

```
     +----+                +----+
     | h1 |==== port 1 ====| s1 |   (P4 程序把包反弹回去)
     +----+                +----+
```

## 文件一览

| 文件 | 作用 |
| --- | --- |
| `main.p4` | P4_16 数据面程序:解析以太头 → 交换 MAC → `egress_spec = ingress_port` → 重封装 |
| `topology.py` | Mininet 拓扑脚本。1 交换机 1 主机。用 `common/p4switch.py` 的 `P4RuntimeSwitch` 拉起 BMv2 |
| `controller/main.go` | Go 控制器:连接 BMv2 gRPC → 赢仲裁 → 推 pipeline → 睡到被 SIGTERM |
| `test.py` | 在 h1 命名空间里跑的 scapy 验证脚本 |
| `run.sh` | 一条命令的编译 + 启动 + 验证 + 清理 |

## P4 源代码要点

```p4
action swap_mac() {
    macAddr_t tmp = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
    hdr.ethernet.dstAddr = tmp;
}
action set_egress_spec() {
    standard_metadata.egress_spec = standard_metadata.ingress_port;
}
apply {
    swap_mac();
    set_egress_spec();
}
```

全部逻辑硬编码在 ingress 的 `apply{}` 里——**没有表、没有 action 参数、没有匹配字段**。所以 P4Info 里其实连 table 都没有,控制器要做的只剩 `SetForwardingPipelineConfig` 这一件事。

## 控制器要点

`controller/main.go` 只有 ~60 行:

```go
c, _ := client.Dial(ctx, addr, client.WithDeviceID(1), client.WithElectionID(...), client.WithInsecure())
c.BecomePrimary(ctx)
p, _ := pipeline.LoadText(p4infoBytes, bmv2ConfigBytes)
c.SetPipeline(ctx, p, client.SetPipelineOptions{})
fmt.Println("pipeline installed via VERIFY_AND_COMMIT; reflector ready")
<-ctx.Done()
```

**没有调用任何写表/配置 counter/meter 的 API**。这是 P4Runtime 控制器的"下限" —— 唯一职责就是把编译产物下发到目标。

## 运行

```bash
cd 01_packet_reflector
sudo ./run.sh          # 自动跑测试,输出 SUCCESS 退出
sudo ./run.sh cli      # 运行拓扑后进入 mininet CLI,手工玩
```

## 预期输出

```
*** Starting BMv2 for s1 on :9559
*** Launching Go controller to push pipeline
    controller: pipeline installed via VERIFY_AND_COMMIT; reflector ready
*** Running test in h1
SUCCESS: packet reflected with MACs swapped (src=02:aa:bb:cc:dd:ee dst=00:00:00:00:00:01)
*** Done
```

测试细节:
- h1 发一帧 `Ether(src=h1_mac, dst=02:aa:bb:cc:dd:ee)/b"hello-reflector"`
- 等 3 秒内在同一张网卡上收到反向帧 `Ether(src=02:aa:bb:cc:dd:ee, dst=h1_mac)/b"hello-reflector"`
- payload 完整,MAC 正确对调 → 判定成功

## 故障排查

**`Address already in use`** 端口 9559 被上次 BMv2 残留占用。  
→ `sudo mn -c && sudo pkill -f simple_switch_grpc`

**`pipeline installed` 不出现**,卡在 `Launching Go controller`  
→ 看 `/tmp/s1.log.stderr`,BMv2 启动失败。常见是 `simple_switch_grpc` 不在 `/usr/local/bin/`。

**测试跑到 `Terminated` 然后超时**  
→ h1 命名空间内 scapy 无法收发。一般是 iptables/Docker bridge 残留干扰。先 `sudo mn -c`。

## 延伸

这个案例是"**无状态**"反射器。可以挑战:

- 扩展成**基于 MAC 的有状态**反射(只反射源 MAC 在白名单内的包,要用 exact 表) → 见 Case 03
- 反射**之前**打一个 register(+1),让控制器能读到"总共反射了多少包" → 类似 Case 08 counter
