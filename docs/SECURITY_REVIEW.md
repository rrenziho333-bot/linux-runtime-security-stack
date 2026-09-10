# 安全审查与升级说明

审查基线：`fc9ef14aa2e5122e241fc42faefddc1a46c702b6`。修复日期：2026-09-10。

这是一轮代码与回归测试驱动的安全加固，不是“已证明不存在任何漏洞”的认证。

## 已修复的问题

| 级别 | 原问题与影响 | 修复 |
|---|---|---|
| P1 | 看板绑定全部网卡，部署自动开端口，没有鉴权；其他主机可读取命令、路径、策略和安全状态 | 只允许绑定回环地址，取消自动开端口，检查 Host 防 DNS 重绑定；远程通过 SSH 或有鉴权的 TLS 代理访问 |
| P1 | BPF 只检查常规文件操作，共享可写 mmap 或只读映射升级 mprotect 可以绕过文件写保护 | 新增 `mmap_file` 和 `file_mprotect` hooks；共享可写映射按同一策略判断，私有写时复制映射仍允许 |
| P1 | 缺失基线被当成 100 分；停止采集后接口仍可返回新的高分响应 | 缺失、空、未完成、过期或执行失败的基线标记不可用；检查 TSA 心跳、服务状态与日志读取状态，数据不可用返回 HTTP 503 |
| P1 | 日志位置先于事件处理提交；进程崩溃可能跳过未入库事件，去重记录也可能先提交导致事件不再计分 | 可嵌套 SQLite 事务；事件、去重、限速、状态与日志确认位置一起提交；失败时回放未确认事件 |
| P2 | 持续日志流使报告、基线刷新和清理任务无法运行 | 每轮先检查周期任务；增加每 5 秒心跳和定期基线刷新 |
| P2 | copytruncate 后按旧位置定位，或轮转前存在不完整行，可能漏读或停住 | 截断从文件开头重新读取；不完整行也检查轮转；单行读取限制为约 1 MiB 字符 |
| P2 | 畸形 BPF 字段、嵌套 JSON 或非法 tags 可使处理异常 | 验证用于计分的数值字段、过滤非法 tags，忽略解析失败事件并保留服务运行 |
| P2 | 降级后修改源配置，却未在恢复完整模式时重新启用 BPF 事件源 | systemd 显式传递运行时模式，源配置不再被重写；降级时停止旧控制器 |
| P2 | 远程归档直接解压，单文件下载名没有约束 | 只读取预期普通文件，拒绝穿越路径、链接、超限或重名成员；限制目标文件名 |
| P2 | YAML 字段拼错可被忽略，目录可作为“受保护文件”载入 | Go 使用严格字段解析，拒绝多文档、空策略及非普通文件 |

另外修复了看板 PID 不一致时仍可能关联事件的问题、零权重时两个评分实现的差异，以及历史事件中写入旧 runtime 分值的问题。增加有效风险查询索引；清理历史数据不会提前移除未过期风险。

内核依据：[Linux 的 file_permission 说明明确区分 mmap 权限检查](https://github.com/torvalds/linux/blob/v6.8/security/security.c#L2493)，[mmap_file / file_mprotect hook 定义](https://github.com/torvalds/linux/blob/v6.8/include/linux/lsm_hook_defs.h#L172)。

## 升级后的操作变化

### 远程访问

看板与 API 只绑定 `127.0.0.1:8766`，程序拒绝直接绑定 `0.0.0.0`。不再自动修改防火墙。历史部署添加过的防火墙规则不会被本次脚本删除，但服务现在不在这些网卡上监听。

在访问端运行并保持连接：

```bash
ssh -N -L 127.0.0.1:8766:127.0.0.1:8766 user@linux-host
```

随后在访问端打开 `http://127.0.0.1:8766/`，或查询本机 8766 端口的评分 API。若访问端已有程序占用端口，可将前一个 `8766` 改成 `18766`。

需要多用户网络集成时，部署有鉴权和 TLS 的反向代理，并把代理上游 Host 显式设为 `127.0.0.1:8766`。不应通过放宽应用的监听限制来省略鉴权。回环接口仍信任本机用户；没有声称对恶意本地管理员提供隔离。

### 基线与可用性

默认 `baseline_lynis.enabled: true`。需准备真实、完整且不超过 `max_report_age_seconds`（默认一天）的 Lynis 报告，否则基线和总分为未知，评分 API 返回 HTTP 503、`code:50000`、`data:null`。报告需要有 `report_version_major` 和 `finish=true` 标记，避免把写到一半的报告当作完成。

在 Linux 项目根目录，已安装 Lynis 且部署目录就绪时：

```bash
sudo lynis audit system --quick --quiet --report-file "$PWD/tsa/reports/lynis-report.dat"
sudo chown "$(id -un):$(id -gn)" tsa/reports/lynis-report.dat
sudo chmod 0640 tsa/reports/lynis-report.dat
sudo systemctl restart tsa-fusion
```

若明确只做运行时实验，可显式设置 `baseline_lynis.enabled: false`。该模式使用中性基线 100，`baseline_status` 明确显示 `disabled`，不能视为完成系统审计。

基线默认每 300 秒重新读取；外部定期扫描建议先写临时报告，再原子替换目标文件。`run_lynis` 默认仍为 false，普通用户 TSA 不应为执行扫描而提升为 root。

启动约 5 秒后，TSA 完成日志打开与心跳更新。`/api/status` 提供 `availability`，失效时页面显示“未评估”；`/healthz` 和评分 API 都会检查数据可用性。心跳超过 30 秒、启用的服务不是 active、日志未打开或基线不可用，均不会返回可用的总分。

### 部署、配置和重新构建

服务模板新增 `__BPF_LSM_MODE__`，升级时应重新运行总部署脚本，不要只替换 Python 文件。完整模式向 TSA 传入 `--bpf-lsm enabled`，降级模式传入 `disabled`。手动启动默认遵从 YAML，也可显式传入该参数。

移除了之前位置错误、实际未生效的 `bpf_lsm.whitelist`。Falco 白名单配置明确放在 `runtime_rules.whitelist`，默认为空；优先用具体 Falco 条件设置例外，避免仅凭可伪造的进程名豁免计分。

systemd 部署目录限制为英文字符、数字、`/`、`_`、`-`、`.`，例如 `/home/alice/linux-runtime-security-stack`。避免路径被 shell、sed 或 systemd 当成其他语法解释。

本次提交包含重新生成的 BPF `.go/.o`。自行修改 C 时仍必须 `go generate ./...` 后再构建；普通部署使用仓库的生成物，不会自动安装 clang。

## 回归验证

Python 测试覆盖原有功能以及 HTTP 请求、回环绑定、DNS 重绑定、失效数据、缺失基线、失败事务重放、截断/轮转、畸形事件、周期任务、公用配置开关和归档路径攻击。

Linux 上运行：

```bash
go generate ./...
go test -race ./...
go vet ./...
cd tsa
python3 -m unittest discover -s tests -v
```

仓库提供 `tests/Dockerfile` 用于可重复的 Linux 构建环境，GitHub Actions 运行同样的常规检查。Windows 跳过两项依赖 POSIX 打开文件重命名语义的测试；Linux 不跳过这两项。

本次本机验证：Linux 容器中 38 项 Python 回归测试全部通过；BPF 对象重新生成，Go 竞态测试、go vet、控制器构建以及 shell 语法检查通过。用 govulncheck v1.8.0 对 Go 1.25.14 构建的控制器二进制扫描，未报告已知漏洞。Go 内核集成测试按设计跳过，目标内核上的六个 hooks 挂载和真实阻断尚未验证。扫描结果仅代表所用版本和当时的漏洞数据库。

实际 BPF 挂载与阻断必须在可丢弃、启用了 BPF LSM 的 Linux 虚拟机验证。新增测试只保护它创建的临时文件，覆盖普通写入、共享 mmap（含 MAP_SHARED_VALIDATE）、mprotect、截断、删除、重命名以及私有映射放行：

```bash
sudo env BPF_LSM_INTEGRATION=1 /usr/local/go/bin/go test -run TestBPFEnforceIntegration -v
```

普通单元测试会明确跳过这个需要内核权限的用例。容器中的编译和单元测试通过，不等于已经完成目标内核上的端到端验证。

## 仍需注意的边界

- 已经存在的共享可写映射不会因后来加载策略而被撤销。应在相关进程启动前加载策略，并在从 audit 切换 enforce 时重启相关工作负载；本次修复拦截新映射和权限升级。
- 保护仍按 device/inode 匹配，文件重建需要刷新；没有目录级未来文件保护，也没有宣称覆盖所有文件系统、ioctl、内核或高权限绕过路径。
- 控制器未 pin links，停止或重启时会卸载，存在保护空窗；root 能改变主机安全配置。
- 两来源可分别扣分，关联是展示用启发式。权重需要按实际环境校准。
- 日志首次接入仍默认从末尾开始；已确认的历史位置会恢复。风险清理和日志轮转不等于无限吞吐或无限磁盘保护。
