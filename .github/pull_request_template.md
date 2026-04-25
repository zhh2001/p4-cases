<!--
提 PR 前先过一下 checklist，这份清单覆盖本仓库所有案例的最低保障，
不满足的项请在 PR 正文里写清楚理由，方便评审。
-->

## 变更摘要

<!-- 1-3 句话。这是新案例还是改现有案例？核心要点是什么？ -->

## 类型

- [ ] 新案例
- [ ] 现有案例 bug 修复
- [ ] 文档 / README 改动
- [ ] common/ 基础设施
- [ ] CI / workflow

## 新案例 Checklist （只有新案例才需要勾选）

- [ ] `NN_case_name/main.p4` —— P4_16 源码，`p4c -b bmv2 --arch v1model --std p4-16` 能编过
- [ ] `NN_case_name/topology.py` —— 纯 Mininet 拓扑
- [ ] `NN_case_name/controller/main.go` —— 基于 `p4runtime-go-controller` 的控制器
- [ ] `NN_case_name/run.sh` —— 支持 `sudo ./run.sh` (自动验证) 和 `sudo ./run.sh cli` 两种模式
- [ ] `NN_case_name/README.md` —— 中文说明：P4 结构、控制器做什么、验证方式、排错
- [ ] 自动化验证：`sudo ./run.sh` 最终输出 `SUCCESS: ...`，失败时非零退出
- [ ] 顶层 README.md "学习路径" 表格加了新行
- [ ] `.github/workflows/ci.yml` 的 `CASES` 环境变量里加了新目录名

## 验证

- [ ] `go vet ./...` 通过
- [ ] `shellcheck -x common/run_helpers.sh NN_case_name/run.sh` 通过
- [ ] 本地 `sudo ./run.sh` 在 Ubuntu 22.04+ / Mininet 2.3.0+ / BMv2 上跑过，输出粘贴在下方

```
<!-- 贴 run.sh 最后 20-30 行，到 SUCCESS / FAILURE 为止 -->
```

## 其它

<!-- 关联 issue、外部参考、已知限制等。没有可删 -->
