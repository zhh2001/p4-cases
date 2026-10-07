# P4 Cases

[![ci](https://github.com/zhh2001/p4-cases/actions/workflows/ci.yml/badge.svg)](https://github.com/zhh2001/p4-cases/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/zhh2001/p4runtime-go-controller.svg)](https://pkg.go.dev/github.com/zhh2001/p4runtime-go-controller)

14 个基于 P4_16、P4Runtime 和 Mininet 的教学案例。每个案例包含 P4 数据面、Go 控制器、Mininet 拓扑、自动验证脚本和中文说明。

## 学习路径

| 编号                            | 案例          | 核心概念                   | 控制器职责                        |
| ------------------------------- | ------------- | -------------------------- | --------------------------------- |
| [01](01_packet_reflector/)      | 报文反射器    | MAC 对调与入端口反射       | 安装流水线                        |
| [02](02_repeater/)              | 端口中继器    | 固定端口映射               | 安装流水线                        |
| [03](03_l2_forwarding_switch/)  | L2 静态转发   | EXACT 表与入端口过滤       | 写入目的 MAC 表项                 |
| [04](04_l2_broadcast_switch/)   | L2 广播交换机 | PRE 与多播组               | 配置单播表和按入端口选择的泛洪组  |
| [05](05_l2_learning_switch/)    | L2 学习交换机 | Digest 与动态学习          | 订阅 Digest 并更新源、目的 MAC 表 |
| [06](06_int/)                   | 带内网络遥测  | IPv4 Options 与逐跳记录    | 为三个交换机配置路由和遥测动作    |
| [07](07_meter/)                 | 流量计量      | Meter 与三色标记           | 配置间接计量器的速率和突发容量    |
| [08](08_counter/)               | 流量计数      | 间接与直接 Counter         | 读取端口包数和字节数              |
| [09](09_ecmp_hash/)             | ECMP 多路径   | 五元组哈希与分片路径一致性 | 配置直达路由、ECMP 组和下一跳     |
| [10](10_firewall_acl/)          | 防火墙 ACL    | TERNARY 表与优先级         | 配置允许和丢弃规则                |
| [11](11_vxlan_encap/)           | VXLAN 封装    | 插入外层头部               | 配置 VTEP、出口和 VNI             |
| [12](12_register_flow_counter/) | UDP 流计数    | Register 与四元组哈希      | 安装流水线并尝试写入寄存器初值    |
| [13](13_clone_to_cpu/)          | 克隆到 CPU    | CloneSession 与 PacketIn   | 配置克隆会话并接收副本            |
| [14](14_ipv6_lpm/)              | IPv6 路由     | 128 位 LPM 与跳数处理      | 配置 /64 和 /128 路由及不同下一跳 |

## 运行环境

本地验证环境为 Ubuntu 24.04、Mininet 2.3.0、Python 3.12 和 Go 1.25。Mininet 拓扑和原始套接字收发需要 root 权限。

| 组件       | 要求与安装参考                                                                                                                                                                                                                                                      |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Mininet    | Ubuntu 上安装 `mininet`，拓扑脚本使用系统 Python 的 Mininet 模块                                                                                                                                                                                                    |
| Python     | 使用 `/usr/bin/python3`，报文探针使用标准库原始套接字                                                                                                                                                                                                               |
| P4C        | 支持 BMv2、v1model 和 P4_16，见 [官方安装说明](https://github.com/p4lang/p4c/blob/main/README.md)                                                                                                                                                                   |
| BMv2       | 需要支持 Thrift 的 `simple_switch_grpc` 和工具 `simple_switch_CLI`，见 [BMv2 安装说明](https://github.com/p4lang/behavioral-model/blob/main/README.md)及 [gRPC 目标说明](https://github.com/p4lang/behavioral-model/blob/main/targets/simple_switch_grpc/README.md) |
| Go         | `go.mod` 要求 Go 1.25.0 或更高版本，见 [官方安装说明](https://go.dev/doc/install)                                                                                                                                                                                   |
| ShellCheck | 用于检查运行脚本，Ubuntu 包名为 `shellcheck`                                                                                                                                                                                                                        |

```bash
sudo apt-get update
sudo apt-get install -y mininet shellcheck
```

P4C 和 BMv2 的软件源配置见上游说明。Go 依赖由根目录的 `go.mod` 和 `go.sum` 固定，构建控制器时自动下载。

## 快速开始

```bash
git clone git@github.com:zhh2001/p4-cases.git
cd p4-cases/01_packet_reflector
sudo ./run.sh
```

`run.sh` 编译 P4 和 Go，启动网络及控制器，再执行报文检查。Case 01 的关键输出为：

```text
Reflector probes: sent=92 reflected=92 hosts=1
SUCCESS: MAC swapping, ingress reflection and complete frames validated
```

在案例目录执行 `sudo ./run.sh cli` 可进入 Mininet CLI。Case 08 还支持 `sudo ./run.sh test direct` 和 `sudo ./run.sh cli direct`。

## 仓库布局

```text
p4-cases/
├── go.mod                       # 所有控制器共用的 Go 模块
├── common/
│   ├── p4switch.py               # 启动和管理 simple_switch_grpc
│   ├── runtime.py                # 控制器输出、超时与网络清理
│   └── run_helpers.sh            # 编译和启动的公共 Shell 函数
├── tests/                       # 运行生命周期和报文校验的回归测试
├── 01_packet_reflector/
│   ├── main.p4
│   ├── topology.py
│   ├── packets.py
│   ├── test.py
│   ├── controller/main.go
│   ├── run.sh
│   └── README.md
└── 02_repeater/ ... 14_ipv6_lpm/
```

多数案例使用 `main.p4`。Case 05 默认使用 `main_digest.p4`，Case 07 使用 `indirect_meter.p4`，Case 08 按参数选择 `indirect_counter.p4` 或 `direct_counter.p4`。

各案例的 `build/` 和 `bin/` 分别保存 P4 产物和控制器，均已加入 `.gitignore`。公共接口和资源管理说明见 [common/README.md](common/README.md)。本地联调 SDK 时可通过已忽略的 `go.work` 指向本地模块。

## 自动验证

在仓库根目录运行无需 root 的检查：

```bash
/usr/bin/python3 -m compileall -q common tests ./*/*.py
/usr/bin/python3 -m unittest discover -s tests -v
go vet ./...
go test -race ./...
shellcheck -x common/run_helpers.sh */run.sh
```

单元测试覆盖运行生命周期、超时、退出状态、报文构造和结果校验。真实数据面仍需逐个运行案例的 `sudo ./run.sh`，确认退出码为零且出现预期的成功输出。完整验证包含 14 个默认案例和 Case 08 的 direct 模式，共 15 种运行方式。各拓扑使用相同的默认端口，应顺序运行。

| 案例 | 默认端到端检查                                                                        |
| ---- | ------------------------------------------------------------------------------------- |
| 01   | 逐字节核对 92 帧的 MAC 对调、完整内容和份数，检查原入端口反射                         |
| 02   | 核对双向 174 帧的完整内容、份数和出端口，再验证 ARP 与 ICMP                           |
| 03   | 核对 124 帧的交付或丢弃，覆盖所有方向、VLAN、入端口过滤和未匹配流量，并运行 `pingAll` |
| 04   | 清空 ARP 后验证解析和互通，核对 300 帧产生的 692 个副本，检查单播、泛洪和入端口过滤   |
| 05   | 读回 MAC 表并核对端口，两轮 `pingAll` 零丢包，抓包验证学习前泛洪与学习后单播          |
| 06   | 核对 63 帧 IPv4 与 INT 报文，覆盖所有主机方向、记录上限、长度、校验和与丢弃行为       |
| 07   | 核对非计量流量的完整交付，按实际突发时长检查计量上限，并验证令牌补充后恢复转发        |
| 08   | 两种 Counter 模式均验证双向完整转发，精确核对两个端口的包数和字节数                   |
| 09   | 按 CRC16 核对 243 包的路径和内容，检查同流一致性、直达路由、分片与异常输入            |
| 10   | 按 IHL 读取端口，核对双向正常和 Options 流量，检查分片及格式异常报文的丢弃            |
| 11   | 核对完整 VXLAN 封装帧、外层长度和校验和，并检查未匹配流量的丢弃                       |
| 12   | 核对全部 1024 槽位的增量，检查双向转发、哈希碰撞、分片不计数和 32 位回绕              |
| 13   | 双向各发 10 帧，核对主机原包、控制器副本和 CPU 头中的入端口                           |
| 14   | 核对 228 包的三端完整帧，检查最长前缀、子网边界、扩展头、分片、跳数和异常长度         |

具体转发边界、测试流量和预期输出见各案例 README。Case 01 只反射报文，Case 07 和 Case 11 演示单向处理，Case 14 使用 IPv6 路由，不能统一用 IPv4 `pingAll` 判断成功。

仓库共有 17 份 P4 源码。Case 05 的 `main_cpu.p4` 和 Case 07 的 `direct_meter.p4` 用于源码对照，仅参与编译检查，现有控制器和 `run.sh` 不提供其端到端运行入口。

## CI 检查

| 任务      | 环境         | 检查内容                                                         |
| --------- | ------------ | ---------------------------------------------------------------- |
| P4 编译   | Ubuntu 22.04 | 安装 p4lang OBS 二进制包，编译全部 17 份 P4 源码并上传产物       |
| Go 控制器 | Ubuntu 24.04 | 检查依赖整理后的差异，运行 `go vet` 和 `go test`，构建全部控制器 |
| Python    | Ubuntu 24.04 | 安装 Mininet，检查语法并运行 `tests/` 中的单元测试               |
| Shell     | Ubuntu 24.04 | 检查公共脚本和全部案例的 `run.sh`                                |

CI 当前不运行真实 Mininet 和 BMv2 网络。P4 编译任务输出实际编译器版本，本地编译通过后仍需检查 CI 使用的工具链是否通过。

## 排查问题

- 交换机或控制器启动失败：查看控制器输出、`/tmp/s1.log` 和 `/tmp/s1.log.stderr`。多交换机拓扑按交换机名称生成日志。
- 端口被占用：先确认是否有其他拓扑运行。公共运行模块在启动前检查 gRPC 和 Thrift 端口，不会停止已有服务。
- 找不到交换机：在案例目录使用 `sudo env P4_SWITCH_PATH=/your/path/simple_switch_grpc ./run.sh`。直接创建交换机时可指定 `sw_path`，优先级高于环境变量。
- 找不到 Mininet：检查 `/usr/bin/python3` 能否导入 `mininet`，避免使用未安装该模块的虚拟环境。
- Go 工具链不可用：检查 `go version` 和 `go.mod` 的要求。运行脚本会优先使用 `/usr/local/go/bin` 中已安装的 Go。
- 报文测试失败：按案例 README 对照预期的路由、表项和丢弃规则，检查完整测试日志。

正常退出、测试异常、SIGINT 和 SIGTERM 都会清理本次启动的进程与网络。若进程被 SIGKILL 强制终止，确认没有其他拓扑运行后，再手动执行 `sudo mn -c` 并停止残留的 BMv2 进程。

## 协作

新案例采用 `NN_case_name/` 目录，提供 P4 源码、拓扑、Go 控制器、自动验证和中文 README，并更新学习路径与 CI 的 `CASES` 列表。共享运行逻辑放在 `common/`，回归测试放在 `tests/`。

P4 使用 4 空格缩进，Go 使用 `gofmt`，Python 使用 `black`。PR 说明预期行为、实际测试结果和运行限制，报文测试应核对完整内容、份数及出端口。提交信息用简短、中性的英文描述变更。

后续可补充 Stateful Firewall、NAT、MPLS、控制器存活检测和更完整的 INT 示例。

## 相关项目与许可

- [p4runtime-go-controller](https://github.com/zhh2001/p4runtime-go-controller)：本仓库控制器使用的 Go SDK。
- [BMv2](https://github.com/p4lang/behavioral-model)：软件交换机。
- [P4C](https://github.com/p4lang/p4c)：P4 编译器。
- [P4Runtime](https://github.com/p4lang/p4runtime)：控制面协议。
- [Mininet](http://mininet.org)：网络拓扑模拟器。

本仓库采用 [Apache-2.0](LICENSE) 许可。
