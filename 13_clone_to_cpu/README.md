# Case 13：克隆到 CPU

本案例将 `h1` 和 `h2` 之间的报文正常转发，同时复制一份发送到 CPU 端口。BMv2 将 CPU 端口的报文送入 P4Runtime 的 `PacketIn` 通道，控制器通过 `OnPacketIn` 接收。

拓扑使用交换机端口 1 和 2 连接主机，CPU 端口为 510，clone session ID 为 99。

## 数据面

入方向记录原始入端口，并将原包从另一主机端口发出。随后调用 `clone_preserving_field_list`，生成发往 clone session 99 的副本。

```p4
meta.ingress_port = standard_metadata.ingress_port;
clone_preserving_field_list(CloneType.I2E, CPU_CLONE_SESSION_ID, 0);
```

`meta.ingress_port` 使用 `@field_list(0)` 标注，使它保留到副本的出方向处理阶段。

出方向通过 `instance_type == 1` 识别 I2E 副本，并加入 CPU 头。原包继续沿正常转发路径发送。

```p4
if (standard_metadata.instance_type == 1) {
    hdr.cpu.setValid();
    hdr.cpu.ingress_port = (bit<16>)meta.ingress_port;
    hdr.ethernet.etherType = ETHERTYPE_CPU;
}
```

控制器收到的副本格式如下：

| 字节位置  | 内容                       |
| --------- | -------------------------- |
| 0 到 5    | 原包的目的 MAC             |
| 6 到 11   | 原包的源 MAC               |
| 12 到 13  | EtherType `0x1010`         |
| 14 到 15  | 原始入端口，使用网络字节序 |
| 16 及以后 | 原包的以太网负载           |

原包的 EtherType 会被替换，副本不保留这个字段的原值。测试发送的原包使用 EtherType `0x88b5`。

## 控制器

控制器安装流水线后，将 clone session 99 的副本端口配置为 510，然后注册 PacketIn 回调。

```go
preW.InsertCloneSession(ctx, pre.CloneSession{
    ID:       99,
    Replicas: []pre.Replica{{EgressPort: 510}},
})
```

回调检查报文长度、CPU EtherType 和入端口。当前拓扑只接受入端口 1 和 2。通过检查后才增加有效 PacketIn 数量，并输出完整报文的十六进制内容。

完整负载用于关联测试报文。只输出前几个字节无法核对唯一标识、序号和负载是否保留。

## 文件

| 文件                      | 作用                                    |
| ------------------------- | --------------------------------------- |
| `main.p4`                 | 原包转发、I2E clone 和 CPU 头生成       |
| `controller/main.go`      | 配置 clone session，解析并输出 PacketIn |
| `controller/main_test.go` | 检查短报文、EtherType 和入端口解析      |
| `topology.py`             | 创建拓扑，验证双向转发和对应副本        |
| `test.py`                 | 在主机内发送和捕获带唯一标识的测试报文  |
| `run.sh`                  | 编译、启动和运行自动测试                |

## 运行和验证

```bash
cd 13_clone_to_cpu
sudo ./run.sh
```

报文收发使用 Python 原始套接字，需要 root 权限，不需要 Scapy。其他依赖与公共运行模块相同。

测试分别检查 `h1 → h2` 和 `h2 → h1`，每个方向发送 10 个报文。每轮都有新的随机标识，每个报文也有不同的序号。

通过条件包括：

1. 发送进程成功退出，确认发送了 10 个不同的报文。
2. 目标主机收到每个原包一次，MAC、EtherType 和完整负载与发送内容一致。
3. 控制器收到每个测试报文的副本一次，MAC 和负载保持一致。
4. 副本的 CPU EtherType 为 `0x1010`，CPU 头和日志中的入端口均与发送主机一致。
5. 测试期间控制器保持运行。

捕获进程会先确认套接字已准备好，随后才启动发送。子进程错误、超时、缺包、重复副本或错误入端口都会使测试失败。退出时回收本轮收发进程。

控制器也会收到 ARP、IPv6 等后台报文。自动测试只核对带本轮标识的报文，不使用所有 PacketIn 的累计数量作为通过条件。

关键输出如下：

```text
controller: clone session 99 -> cpu port 510 installed
controller: clone-to-cpu ready
h1 -> h2: sent=10, forwarded=10, cloned=10, ingress_port=1
h2 -> h1: sent=10, forwarded=10, cloned=10, ingress_port=2
SUCCESS: every test frame was forwarded and cloned with its ingress port
```

控制器的逐包日志可能穿插其中。退出时显示的有效 PacketIn 总数包含后台流量，可以大于 20。

进入交互模式：

```bash
sudo ./run.sh cli
```

无需启动交换机的回归测试在仓库根目录运行：

```bash
go test ./13_clone_to_cpu/controller
/usr/bin/python3 -m unittest discover -s tests -p test_clone_to_cpu.py -v
```

## 与 Case 05 的区别

| 项目       | 本案例                       | Case 05                    |
| ---------- | ---------------------------- | -------------------------- |
| 通知内容   | 带 CPU 头的报文副本          | MAC 和入端口组成的学习事件 |
| 用途       | 检查报文内容或送往控制面处理 | 学习 MAC 并写入转发表      |
| 交换机配置 | clone session 和 CPU 端口    | `DigestEntry`              |
| 控制器接收 | `OnPacketIn`                 | `OnDigest`                 |

## 排查和延伸

没有对应副本时，先检查 BMv2 启动参数中的 `--cpu-port 510`，以及控制器是否成功安装 clone session 99。若报文到达控制器但解析失败，再检查出方向是否生成了 CPU 头，以及 `@field_list(0)` 是否保留了入端口。

本案例复制所有从主机端口进入的报文。后续可以将 clone 放入表动作，只复制满足指定条件的流量。CPU 主动发送报文属于 PacketOut 路径，需要另外设计相应的处理逻辑。
