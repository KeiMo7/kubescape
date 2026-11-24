# 审计行为分析报告样例（reports/）

本目录存放“接口审计事件行为分析”功能的测试与回归真实输出。

## 目录内容

| 文件 | 说明 |
| --- | --- |
| `sample-events/part1.jsonl.gz` / `sample-events/part2.tar.gz` | 合成的一周审计事件导出（2,174 行），含五类可疑行为 + 大量噪声 + 5 行非法行 + 3 条缺时间戳事件 + 乱序事件，以两种归档格式存放，验证多文件/归档读取 |
| `audit-report.json` | 对两个归档运行 `kubescape audit` 的 JSON 报告（默认格式） |
| `audit-report.sarif` | 同一次扫描的 SARIF 2.1.0 输出（`--format sarif`） |
| `audit-report.pretty.txt` | 同一次扫描的文本表格输出（`--format pretty`） |
| `corrupt-demo/` | 损坏归档降级演示输入（`broken.tgz` 不是合法归档） |
| `audit-report-partial.json` | 归档损坏时的输出：`status: "partial"`，已完成部分保留，`partialReason` 标注原因，命令以非零码退出 |
| `test-output.txt` | `go test ./core/pkg/auditlog/ ./cmd/audit/ -count=1 -v` 的完整真实输出（16 个测试全部通过） |
| `memory-test-output.txt` | 流式内存上限验证的真实输出 |

## 复现方式

```bash
go build -o /tmp/kubescape .
/tmp/kubescape audit reports/sample-events/part1.jsonl.gz reports/sample-events/part2.tar.gz
/tmp/kubescape audit reports/sample-events/part1.jsonl.gz reports/sample-events/part2.tar.gz --format sarif
/tmp/kubescape audit reports/sample-events/part1.jsonl.gz reports/sample-events/part2.tar.gz --format pretty
```

## 内存上限实测（流式处理）

来自 `memory-test-output.txt`（Linux, VmHWM 高水位）：

| 输入体积 | 事件数 | 峰值 RSS | 结论 |
| --- | --- | --- | --- |
| 100 MiB | 395,526 | 47.9 MB | 远低于 256 MB 预算 |
| 1 GiB（十亿字节级） | 4,050,175 | 58.9 MB | 输入放大 10 倍，RSS 基本不变 → 内存不随文件体积增长 |

## 样本中五类行为的检出情况（audit-report.json）

- `bulk-sensitive-read`：alice（三种拼写归一）25 个不同 secret，30 次事件，重复访问去重；
- `privileged-workload`：deployer 创建特权 Pod + hostPath Deployment，合并为 1 条、2 个对象；
- `privileged-role-binding`：eve 把 cluster-admin 绑给普通用户 mallory；
- `exec-into-container`：ops 调试 SA exec 进 2 个 Pod、4 个会话（101 视为成功）；
- `anonymous-access`：system:anonymous 3 次成功读取；403 与无响应状态的事件均未计入。

噪声（平台控制面流量、普通 configmap 读取、低于阈值的 secret 读取、失败的特权 Pod 创建、绑定非特权角色、绑定 cluster-admin 给平台主体、失败的 exec）零误报。
