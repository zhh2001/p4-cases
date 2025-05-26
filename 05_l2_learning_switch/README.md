# 二层学习交换机示例

## 简介

本示例实现了一个具备二层学习能力的以太网 P4 交换机。相比基础的 L2 转发逻辑，该示例引入了自动学习源 MAC 地址与入端口的映射机制，模拟真实 L2 交换机的行为，显著增强了交换机的智能化水平。

本示例构建于先前的基本 L2 广播交换机之上，实现了以下关键特性：

- 动态学习源 MAC 地址与入端口映射；
- 利用控制器动态更新转发表项；
- 对未知目的地址实现广播处理；
- 展示两种学习方式：数据包复制至控制器（Copy-to-CPU）与 Digest 消息发送；

## 网络拓扑

采用典型的星型拓扑结构，核心交换机连接四台主机，具体如下：

```text
+--+      +--+     ++-+
|h1+------+  +-----+h2+
+--+      +  +     +--+
          +s1+
+--+      +  +     ++-+
|h3+------+  +-----+h4+
+--+      +-++     +--+
```

## 核心功能说明

### MAC 学习机制

交换机在收到数据包后，将检查源 MAC 地址是否为已知项：

- **若为未知地址**：触发学习流程，提取 `(src_mac, ingress_port)` 二元组，并通过控制平面发送至控制器；
- **控制器响应**：
  - 在 `smac` 表中记录该源地址，避免重复学习；
  - 在 `dmac` 表中添加对应转发规则；
- **目的地址处理**：
  - 若 `dmac` 命中：直接转发；
  - 若未命中：通过 `broadcast` 表实现多播广播处理。

### 学习方式

#### 1. Clone to CPU 模式

通过 Simple Switch 的 `clone_preserving_field_list` 指令复制数据包，附带学习信息（源 MAC 和 `ingress_port`），并封装在自定义 `cpu_t` 头部中，发送至控制器专用 CPU 端口。需使用 `@field_list` 保证元数据透传。

#### 2. Digest 模式

使用 `digest` 将学习信息封装为结构体并提交至控制器。该方式在性能与解耦方面更具优势，适合生产部署。

## 使用方法

### 启动拓扑与控制器

#### Clone to CPU 模式

```bash
# 启动网络
sudo python main_cpu.py

# 启动控制器（另一个终端）
sudo python controller.py s1 cpu
```

#### Digest 模式

```bash
# 启动网络
sudo python main_digest.py

# 启动控制器（另一个终端）
sudo python controller.py s1 digest
```

### 网络测试

在 Mininet CLI 中测试主机互通性：

```bash
mininet> pingall
```

### 表项验证

```bash
simple_switch_CLI --thrift-port 9090
RuntimeCmd: table_dump dmac
```

应可观察到交换机动态学习后的 `dmac` 表项。

## 拓展建议

完成单交换机场景测试后，可扩展至多交换机（无环路）拓扑，验证控制器跨交换机的学习能力和网络全域连通性。
