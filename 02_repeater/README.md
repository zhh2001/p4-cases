# 🔁 Case 02 · Port Repeater

> **学习目标**: 理解 P4 最简单的"端口映射"行为;体会"硬编码的 if-else"与"查找表"的差别。

## 功能

两端口交换机,**P4 程序硬编码** 1↔2 互转:

```
h1  --port 1 -- s1 -- port 2--  h2
           (ingress==1 → egress=2;ingress==2 → egress=1)
```

依然**无需下表**,控制器只推 pipeline。如果要改转发方向,必须重新编译 P4;这正是"硬编码控制面"的局限,下一案例 (03) 会展示用表替换掉这种硬编码。

## 文件

| 文件 | 作用 |
| --- | --- |
| `main.p4` | 解析以太头 → `if-else` 选择 egress → 重封装 |
| `topology.py` | Mininet 2 主机拓扑 |
| `controller/main.go` | 推 pipeline → 睡到被 SIGTERM |
| `test.py` | h1 发 / h2 收一帧验证 |
| `run.sh` | 一键编译 + 启动 + 测试 |

## P4 要点

```p4
apply {
    if (standard_metadata.ingress_port == 1) {
        standard_metadata.egress_spec = 2;
    } else if (standard_metadata.ingress_port == 2) {
        standard_metadata.egress_spec = 1;
    } else {
        mark_to_drop(standard_metadata);
    }
}
```

注意 **无 `table.apply()`**,**无 action**,一切都在 `apply{}` 的控制流里。

## 运行

```bash
sudo ./run.sh          # 自动测试
sudo ./run.sh cli      # 进入 mininet CLI
```

## 预期输出

```
    controller: pipeline installed via VERIFY_AND_COMMIT; repeater ready
*** Starting sniffer on h2
*** Sending test frame from h1
    SEND: 00:00:00:00:00:01 -> 00:00:00:00:00:02 payload=b'hello-repeater'
SUCCESS: received src=00:00:00:00:00:01 dst=00:00:00:00:00:02 payload=b'hello-repeater'
```

## 故障排查

**h2 没收到包**:  
→ `sudo mn -c` 清理残留,重跑。

**`test.py` 脚本本身挂住**:  
→ 检查 scapy 版本 ≥ 2.4.5(有 `AsyncSniffer`);`python3 -c "import scapy; print(scapy.__version__)"`。
