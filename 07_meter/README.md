# Case 07：按源 MAC 计量流量

本案例使用双速率三色计量器，按源 MAC 选择计量实例。只转发绿色报文，黄色和红色报文都会被丢弃。

拓扑为 `h1 → s1 → h2`。数据面固定使用出端口 2，演示 h1 到 h2 的单向流量，不提供双向交换或 IP 路由。

## 颜色与速率

v1model 的 meter 返回三种颜色：

| 颜色 | 值  | 本案例的动作 |
| ---- | --- | ------------ |
| 绿色 | 0   | 转发         |
| 黄色 | 1   | 丢弃         |
| 红色 | 2   | 丢弃         |

CIR 是承诺速率，PIR 是峰值速率。CBurst 和 PBurst 分别表示对应令牌桶的容量。令牌随时间补充，达到桶容量后不再增加。双速率三色标记的背景见 [RFC 2698](https://www.rfc-editor.org/rfc/rfc2698)。本案例使用 `MeterType.packets`，速率单位为包每秒，桶容量单位为包。

控制器的默认配置如下，自动测试也明确使用这些参数：

```text
CIR=10 pps   CBurst=5 packets
PIR=20 pps   PBurst=10 packets
```

控制器支持 `-cir`、`-cburst`、`-pir`、`-pburst` 参数。速率和桶容量必须为正，PIR 不得小于 CIR。配置写入后，控制器读回计量实例 0，确认四个参数一致才输出就绪信息。

## 两张表

```p4
apply {
    standard_metadata.egress_spec = 2;
    meta.meter_tag = 0;
    m_read.apply();
    m_filter.apply();
}
```

每个报文进入处理逻辑时，`meter_tag` 显式初始化为绿色。`m_read` 按源 MAC 选择实例，命中时执行计量并更新颜色，未命中时保持绿色。`m_filter` 只配置 `tag=0 → NoAction`，默认动作丢弃其他颜色。

| 源 MAC              | 行为                                           |
| ------------------- | ---------------------------------------------- |
| `aa:aa:aa:aa:aa:aa` | 命中 `m_read`，使用实例 0 计量，只转发绿色报文 |
| 其他 MAC            | 跳过计量，保持绿色并转发                       |

间接计量器包含 8192 个实例，由 action 参数指定实例索引。`direct_meter.p4` 展示直接计量器与表项绑定的写法，也显式初始化颜色。它作为源码对照参与编译检查，`run.sh` 和本案例的控制器使用间接计量器。

## 文件

| 文件                 | 作用                                     |
| -------------------- | ---------------------------------------- |
| `indirect_meter.p4`  | 按索引执行计量，按颜色过滤               |
| `direct_meter.p4`    | 展示直接计量器与表项绑定                 |
| `controller/main.go` | 安装表项，校验参数并写入、读回计量配置   |
| `topology.py`        | 创建拓扑，验证突发、丢包和令牌恢复       |
| `test.py`            | 使用原始套接字发送和捕获完整帧，记录时间 |
| `run.sh`             | 编译并启动测试或交互模式                 |

## Go 控制器

```go
mr, err := meter.NewReader(c, p)
if err != nil {
    log.Fatalf("meter reader: %v", err)
}
if err := mr.Write(ctx, "MyIngress.my_meter", meterIndex, meterConfig); err != nil {
    log.Fatalf("configure meter: %v", err)
}
entries, err := mr.Read(ctx, "MyIngress.my_meter", meterIndex)
if err != nil {
    log.Fatalf("read meter configuration: %v", err)
}
if err := checkMeterConfig(entries, meterConfig); err != nil {
    log.Fatalf("verify meter configuration: %v", err)
}
```

SDK 的 `meter.NewReader` 同时提供 Read 和 Write。Write 使用 P4Runtime 的 `MeterEntry` MODIFY，Read 返回配置，不返回实时令牌余额或报文颜色。

## 运行和验证

```bash
cd 07_meter
sudo ./run.sh
```

收发脚本只使用 Python 标准库的原始套接字，需要 root 权限，不需要 Scapy。每轮突发预先生成报文，并通过一个套接字连续发送。

测试依次验证四个阶段，共发送 95 帧：

| 阶段                 | 发送数 | 要求                                            |
| -------------------- | ------ | ----------------------------------------------- |
| 非计量源，计量测试前 | 30     | 全部收到                                        |
| 计量源突发           | 30     | 最初 5 帧通过，后续按令牌预算受限，必须出现丢包 |
| 计量源补充令牌后     | 5      | 全部收到                                        |
| 非计量源，计量测试后 | 30     | 全部收到                                        |

计量阶段根据实际发送和接收时间计算上限 `CBurst + ceil(CIR × elapsed)`。计时涵盖首次发送到最后一次发送或接收的时段，向上取整为令牌补充留出边界余量。整个突发必须在 0.5 秒内完成，因此默认配置下最多允许 10 帧通过。超过时限会明确报告时序不满足要求。

恢复阶段在前一阶段捕获结束后，再等待 `CBurst / CIR + 0.1` 秒，确认计量源能重新通过完整的承诺突发。这样可以识别把该源永久丢弃的错误实现。

测试帧带有本轮随机标识、阶段号和序号，长度覆盖 60、80、100、120 字节。捕获进程按源 MAC 筛选原始帧，避免依赖高层协议解析。收到的每帧必须属于本阶段，内容完全一致且没有重复。非计量和恢复阶段必须完整交付，计量阶段也必须收到最初的承诺突发，因此空捕获不能判定为成功。

捕获进程报告就绪后才启动发送。发送、捕获、回复格式、超时或控制器退出都会使测试失败，并清理本次启动的进程。

一次正常输出如下，计时和计量帧数可能有小幅变化：

```text
unmetered-before: received=30/30, expected=30, burst=0.007021s
metered-burst: received=5/30, expected=5..6, burst=0.001710s
metered-after-refill: received=5/5, expected=5, burst=0.001550s
unmetered-after: received=30/30, expected=30, burst=0.006282s
SUCCESS: unmetered delivery, burst policing and token refill match expectations
```

交互模式使用同一组计量配置：

```bash
sudo ./run.sh cli
```

在仓库根目录执行无需交换机的测试：

```bash
/usr/bin/python3 -m unittest discover -s tests -p test_meter.py -v
go test ./07_meter/controller
```

## 延伸

可为 `m_filter` 增加黄色报文的处理动作，例如转发并标记 DSCP。使用直接计量器时，需要将配置写到对应表项的直接计量资源，不能沿用这里的间接 `MeterEntry` 索引配置。
