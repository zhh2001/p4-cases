# Case 05：L2 学习交换机

本案例通过 digest 把新源 MAC 和入端口通知控制器。控制器写入 `smac` 和 `dmac`，让后续报文按已学习的目的 MAC 单播转发。默认拓扑包含四台主机和一台交换机。

## 与 Case 04 的区别

Case 04 由控制器预先配置转发表。本案例根据交换机实际收到的报文学习 MAC。目的 MAC 尚未学习时，报文通过多播组发往除入端口以外的主机。

| 表 | 匹配键 | 命中后的动作 | 未命中时的动作 |
| --- | --- | --- | --- |
| `smac` | 源 MAC | `NoAction`，停止通知同一源 MAC | `mac_learn`，生成 digest |
| `dmac` | 目的 MAC | `forward`，从已学习的端口发出 | 进入泛洪路径 |
| `broadcast` | 入端口 | 选择不含入端口的多播组 | `NoAction` |

## 文件

| 文件 | 作用 |
| --- | --- |
| `main_digest.p4` | digest 学习、单播转发和泛洪 |
| `main_cpu.p4` | CPU clone 学习路径的 P4 示例，默认运行入口不使用它 |
| `controller/main.go` | 安装流水线和多播组，启用 digest，处理学习事件 |
| `controller/main_test.go` | 验证 digest 配置、数据解码和表项写入失败后的处理 |
| `topology.py` | 创建拓扑，读回表项并检查报文转发 |
| `test.py` | 在主机中发送和捕获带标识的以太网报文 |
| `run.sh` | 编译、启动和运行自动测试 |

## digest 的启用和处理

注册 `OnDigest` 回调只是订阅控制器收到的消息。交换机还需要一条 `DigestEntry` 才会发送 digest。控制器从 P4Info 查找 `learn_t` 的 ID，并在输出就绪信息之前写入以下配置：

| 配置 | 值 | 含义 |
| --- | --- | --- |
| `max_timeout_ns` | `0` | 不等待批量收集 |
| `max_list_size` | `1` | 每个消息列表只包含一个学习事件 |
| `ack_timeout_ns` | `1000000000` | 重复事件缓存的超时为一秒 |

回调把消息放入有容量限制的队列，主循环负责写表。每个学习事件按以下顺序处理：

1. 解码 MAC 和入端口，检查 MAC 长度、单播地址和端口范围。
2. 写入 `dmac`，建立回包所需的转发路径。
3. 写入 `smac`，停止该源 MAC 后续触发 digest。
4. 两张表都写入成功后，记录已学习状态。
5. 处理完消息列表后发送 `DigestListAck`。

如果写表失败，控制器会记录错误，并保留后续学习事件重新尝试的机会。重试遇到已有表项时使用 `MODIFY`，这样部分写入成功的状态也能继续处理。

ACK 用于移除交换机的重复事件缓存。digest 是尽力交付机制，不保证消息一定送达，也不保证重发。协议定义见 [P4Runtime 的 DigestEntry 说明](https://p4lang.github.io/p4runtime/spec/v1.5.0/P4Runtime-Spec.html#sec-digestentry)。

## 运行和验证

```bash
cd 05_l2_learning_switch
sudo ./run.sh
```

除公共运行依赖外，自动测试还需要 `simple_switch_CLI` 读回交换机表项。报文检查使用 Python 原始套接字，需要 root 权限。

测试按顺序检查：

1. 从 `h1` 向未知目的 MAC 发送三帧。其他主机各收到三帧，`h1` 不收到回送副本。
2. 运行第一轮 `pingAll`，要求零丢包。
3. 读回 `smac` 和 `dmac`，确认每台主机的 MAC 都已学习，并映射到正确的入端口。
4. 运行第二轮 `pingAll`，要求零丢包。
5. 分别检查 `h1 → h2` 和 `h2 → h1`。目标主机各收到三帧，其余主机收到零帧。

捕获进程启动失败、超时、读表失败、缺少报文或多出副本都会让测试失败。只有两轮 ping 连通不足以通过检查，因为泛洪也可能提供连通性。

默认四主机的关键输出如下，控制器日志和 Mininet 输出可能穿插其中：

```text
controller: learning-switch ready: 4 ports, flooding unknown destinations
Delivery h1 -> 02:ff:ff:ff:ff:fe: h1=0, h2=3, h3=3, h4=3
Learned tables: 4 host MACs mapped to their ingress ports
Delivery h1 -> 00:00:00:00:00:02: h1=0, h2=3, h3=0, h4=0
Delivery h2 -> 00:00:00:00:00:01: h1=3, h2=0, h3=0, h4=0
SUCCESS: host MACs learned and unicast delivered without flooding
```

两轮 `pingAll` 均应显示 `0% dropped (12/12 received)`。

进入交互模式：

```bash
sudo ./run.sh cli
```

也可以直接调用拓扑入口调整主机数。参数允许 2 到 254，默认值为 4。`smac` 和 `dmac` 各有 256 个表项，实际学习容量还要考虑其他源 MAC：

```bash
sudo python3 topology.py \
  --p4info build/main_digest.p4info.txt \
  --config build/main_digest.json \
  --controller bin/controller \
  --n-hosts 3 --run-test
```

无需启动交换机的回归测试在仓库根目录运行：

```bash
go test ./05_l2_learning_switch/controller
python3 -m unittest discover -s tests -p test_learning_switch.py -v
```

## 范围和延伸

本案例面向固定拓扑，同一 MAC 使用首次学习到的端口，不支持 MAC 老化或主机迁移。`smac` 命中后会停止该源 MAC 的学习通知，因此迁移支持还需要调整数据面的匹配方式和控制器状态管理。

`main_cpu.p4` 展示通过 CPU clone 通知控制面的另一种路径。它还需要 clone session 和对应的控制器收包逻辑，目前作为 P4 示例保留，不属于默认运行和端到端验证流程。

后续可以加入 MAC 老化、端口迁移和多交换机学习。跨交换机泛洪还需要考虑环路。
