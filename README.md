# 🧾 P4 Cases

[![ci](https://github.com/zhh2001/p4-cases/actions/workflows/ci.yml/badge.svg)](https://github.com/zhh2001/p4-cases/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/zhh2001/p4runtime-go-controller.svg)](https://pkg.go.dev/github.com/zhh2001/p4runtime-go-controller)

一组 **P4_16 + P4Runtime + Mininet** 的可运行教学案例，每个案例都配有：

- 📝 `main.p4` 数据面源码
- 🐍 `topology.py` 纯 Mininet 拓扑
- 🐹 `controller/main.go` 用 [`p4runtime-go-controller`](https://github.com/zhh2001/p4runtime-go-controller) 写的控制面
- ✅ `run.sh` 一键编译 + 启动 + 自动化验证 + 资源清理
- 📖 中文 README，逐条讲 P4 结构、控制器代码、期望行为、故障排查

案例使用 **Ubuntu 24.04 LTS + Mininet 2.3.0 + BMv2 + Go 1.25** 运行，自动化测试的检查项见下文。

---

## 📚 学习路径

按编号由浅入深，每个后一个在前一个的基础上加一点：

| 编号                            | 案例              | 核心概念                               | 控制器做什么                                     |
| ------------------------------- | ----------------- | -------------------------------------- | ------------------------------------------------ |
| [01](01_packet_reflector/)      | Packet Reflector  | Parse → Match-Action → Deparse         | **只推 pipeline**                                |
| [02](02_repeater/)              | Port Repeater     | 硬编码 `if-else` vs 查找表             | 只推 pipeline                                    |
| [03](03_l2_forwarding_switch/)  | L2 静态转发       | EXACT 表 + action 参数                 | 写 4 条 `dmac` 表项                              |
| [04](04_l2_broadcast_switch/)   | L2 广播交换机     | **PRE / MulticastGroup**               | 上面 + 4 个 mcast 组 + `select_mcast_grp` 表项   |
| [05](05_l2_learning_switch/)    | L2 学习交换机     | **Digest** (数据面→控制面通知)         | 启用并订阅 digest，动态写入 `smac`/`dmac`        |
| [06](06_int/)                   | 带内网络遥测      | **多交换机 + IPv4 Options + 逐跳遥测** | 并行 3 个控制器，各装 LPM + `int_table` 默认动作 |
| [07](07_meter/)                 | Meter             | **Meter extern / 三色标记**            | `MeterEntry` 配 CIR/PIR，drop 非绿流量           |
| [08](08_counter/)               | Counter           | **Counter extern / 读取累积值**        | 按索引或表项读取包数和字节数                     |
| [09](09_ecmp_hash/)             | ECMP 多路径       | **5-tuple hash + ecmp group**          | direct /32 + /24 ECMP + `ecmp_nhop` 2 个成员     |
| [10](10_firewall_acl/)          | 防火墙 ACL        | **TERNARY 表 + priority**              | 3 条不同优先级的 allow/deny 规则                 |
| [11](11_vxlan_encap/)           | VXLAN 封装        | **头部插入 / `setValid()`**            | 一条 vtep 表，配置出口、外层地址与 VNI           |
| [12](12_register_flow_counter/) | Register 逐流统计 | **register + hash(5-tuple)**           | 纯数据面维护，控制器通过 Thrift 读回             |
| [13](13_clone_to_cpu/)          | 克隆到 CPU        | **CloneSession + PacketIn**            | 每包 clone 到 CPU port，控制器 `OnPacketIn` 收包 |
| [14](14_ipv6_lpm/)              | IPv6 LPM 路由     | **128 位 LPM + L3 重写 + hopLimit**    | 4 条路由(/64×3 + /128×1)，演示长前缀优先         |

---

## 🏗️ 前置要求

| 组件                        | 最低版本 | 安装命令                                                   |
| --------------------------- | -------- | ---------------------------------------------------------- |
| Ubuntu                      | 22.04+   | -                                                          |
| Mininet                     | 2.3.0+   | `sudo apt install mininet openvswitch-switch`              |
| BMv2 (`simple_switch_grpc`) | 最新     | `sudo apt install p4lang-bmv2` 或源码编                    |
| P4C                         | 最新     | `sudo apt install p4lang-p4c` 或源码编                     |
| Python 3 + Scapy            | 2.5+     | `sudo apt install python3-scapy`                           |
| Go                          | 1.25+    | 从 go.dev 下载 tarball                                     |
| `p4runtime-go-controller`   | v1.1+    | `go get github.com/zhh2001/p4runtime-go-controller@latest` |

## 🚀 快速开始

```bash
# 只需克隆本仓库——SDK 由 go.mod 自动从 proxy.golang.org 拉取
git clone git@github.com:zhh2001/p4-cases.git
cd p4-cases

# 跑第一个案例
cd 01_packet_reflector
sudo ./run.sh
```

> 想同步改 SDK？在仓库根目录放一个 `go.work` 指向本地 `p4runtime-go-controller` 即可，`go.work` / `go.work.sum` 已在 `.gitignore` 中，不会污染仓库。

看到 `SUCCESS: packet reflected with MACs swapped` 就说明从 P4 编译到 Go 控制面再到 scapy 验证整条链路都正常了。

## 📂 仓库布局

```
p4-cases/
├── README.md                    # 本文件
├── go.mod                       # Go 模块(所有案例的控制器共用一个模块)
├── common/
│   ├── p4switch.py              # Mininet Switch 子类，拉起 simple_switch_grpc
│   ├── runtime.py               # 控制器日志读取、超时和网络清理
│   └── run_helpers.sh           # 每个案例 run.sh 共享的工具函数
├── tests/                      # 公共运行逻辑和案例的回归测试
├── 01_packet_reflector/
│   ├── main.p4
│   ├── topology.py
│   ├── test.py
│   ├── controller/main.go
│   ├── run.sh
│   └── README.md
├── 02_repeater/ ... 14_ipv6_lpm/
└── .gitignore
```

每个案例的 `build/` 保存 P4 编译产物，`bin/` 保存 Go 控制器，两者都已加入 `.gitignore`。公共运行模块的用法和回归测试见 [common/README.md](common/README.md)。

## 🔌 控制器 SDK

所有 Go 控制器都基于 [`p4runtime-go-controller`](https://github.com/zhh2001/p4runtime-go-controller)——一个纯 Go 的 P4Runtime 客户端：

- `client.Dial` + `BecomePrimary` 处理 gRPC + 仲裁
- `pipeline.LoadText` + `client.SetPipeline` 推 P4Info + bmv2.json
- `tableentry.Builder` 写表，`codec.MustMAC/MustIPv4/MustEncodeUint` 做规范字节编码
- `pre.Writer` 管 MulticastGroup / CloneSession(本仓库 Case 04/05/13 用到)
- `digest.NewSubscriber` 订阅 digest 事件(Case 05)
- `counter.NewReader` / `meter.NewReader` 读/写 counter、meter(Case 07/08)

版本 v1.1.0 起，PRE 被正式纳入 API。各案例的 `controller/main.go` 演示 SDK 的调用方式，并处理相应的控制面逻辑。

## 🧪 自动化验证

每个 `run.sh` 的 `sudo ./run.sh` 模式都内置了端到端检查：

| 案例    | 判定方式                                                                                                            |
| ------- | ------------------------------------------------------------------------------------------------------------------- |
| 01      | scapy 在 h1 上捕获 MAC 已对调的回包                                                                                 |
| 02      | h1 发、h2 收(scapy sniff)                                                                                           |
| 03 / 04 | Mininet `pingAll`，期望 0% 丢包                                                                                     |
| 05      | 读回两张 MAC 表并核对端口，两轮 `pingAll` 零丢包，逐主机捕获报文验证泛洪和学习后的单播                              |
| 06      | h2 的 INT 栈包含 `swid ∈ {1,2}` 至少 2 条                                                                           |
| 07      | 完整交付非计量流量，按实际突发时长核对计量上限，并验证令牌补充后恢复转发                                            |
| 08      | 两种 counter 均验证双向完整转发，精确核对两个端口的包数和字节数                                                     |
| 09      | h2 和 h3 均收到 >0 的 ECMP 分发流量                                                                                 |
| 10      | 按 IHL 读取端口，核对双向正常和 Options 流量，丢弃 IPv4 分片及所检查的格式异常报文                                  |
| 11      | 按入包长度生成 VXLAN 外层头，逐字节核对完整封装帧，并检查未匹配流量的丢弃                                           |
| 12      | Thrift 读出 register 某 slot = 注入包数                                                                             |
| 13      | 双向各发送 10 帧，逐包核对主机收到的原包和控制器收到的副本，并检查 CPU 头中的入端口                                 |
| 14      | 4 条 IPv6 流：`/64` 命中、`/128` 长前缀覆盖、回退到 `/64`、无路由的流被 drop。同时校验 `hopLimit-1` 和 dst-MAC 重写 |

不想跑测试、只想进 mininet CLI 手动玩：`sudo ./run.sh cli`。

## 🧹 故障排查通则

**`Address already in use` / BMv2 起不来**  
先查看日志和端口占用，确认是否有其他拓扑正在运行。`run.sh` 只清理本次启动的控制器和网络，启动失败、测试异常或收到 SIGINT / SIGTERM 时也会清理。若进程被 SIGKILL 强制终止，确认没有其他 Mininet 网络在使用后，再手动运行 `sudo mn -c` 并停止残留的 BMv2 进程。

**Go 编译报"toolchain not available"**  
机器上装了老版本 Go 1.22 和新版 Go 1.25，PATH 里老的在前。`common/run_helpers.sh` 已经自动把 `/usr/local/go/bin` 前置到 PATH，直接用 run.sh 就行。

**`simple_switch_grpc` 找不到**  
通过 `sudo env P4_SWITCH_PATH=/your/path/simple_switch_grpc ./run.sh` 指定路径，确保环境变量传入 root 进程。直接创建 `P4RuntimeSwitch` 时，也可以传入 `sw_path`，该参数优先于环境变量。

**`pingAll` 部分丢包**  
绝大多数是静态 ARP 没注入(Case 03)或多播组缺配(Case 04)。看控制器日志应该能看到哪条表项未写成功。

**scapy 版本太老**  
部分案例的测试依赖 `AsyncSniffer`(scapy ≥ 2.4.5)。`sudo pip3 install --upgrade --break-system-packages scapy`。

## 🗺️ 路线图

本仓库已实现 14 个案例，覆盖 P4 入门到进阶的常见模式。后续候选：

- [ ] **Stateful firewall** (register 维护 TCP 会话状态)
- [ ] **NAT / SNAT** (五元组改写 + session 表)
- [ ] **MPLS label swap / pop**
- [ ] **Watchdog / liveness** (register 超时阈值 + 控制器周期读取 + 黑名单注入)
- [ ] **INT-MD 完整版** (时间戳 + 路径染色)

欢迎 PR 添加新案例。每个新案例的目录结构请参考现有案例。

## 🤝 协作

- Issues：任何运行失败、文档歧义、P4 / Go 改进都欢迎
- PR：新案例请同时提供 P4 源、Mininet 拓扑、Go 控制器、自动化测试、中文 README
- 代码风格：P4 用 4 空格缩进，Go 用 `gofmt` 格式化，Python 用 `black` 格式化。

## 📜 License

Apache-2.0。P4 源码、BMv2 相关工具、以及 Mininet 保留各自的原上游 license。

---

## 🔗 相关项目

- [`p4runtime-go-controller`](https://github.com/zhh2001/p4runtime-go-controller) — 本仓库控制器所基于的 Go SDK
- [`p4lang/behavioral-model`](https://github.com/p4lang/behavioral-model) — BMv2 软件交换机
- [`p4lang/p4c`](https://github.com/p4lang/p4c) — 官方 P4 编译器
- [`p4lang/p4runtime`](https://github.com/p4lang/p4runtime) — P4Runtime 协议规范及 proto 定义
- [`mininet/mininet`](http://mininet.org) — 网络命名空间拓扑模拟器
