# Ubuntu 虚拟机验证报告

日期：2026-09-11。分支：`codex/security-hardening`。

后续规则部署更新见第 6 节；第 1 至 5 节保留此前提交的验证范围，不把历史结果当作所有后续变更的自动证明。

验证基线为安全修复提交 `e263e7fe5c15fcf76b69e8920aaf3e88d6255ca5`，加上本报告所在提交的 `GO_BIN` 部署支持和扩展内核测试。没有修改产品内核逻辑或评分逻辑来迎合测试。

**结论：本轮目标环境中的构建、实际内核保护和端到端验收通过，可以进入合并审查；不等于无漏洞、覆盖全部 Linux 环境或可以直接用于生产。** 本轮没有自动合并 `main`。

## 1. 环境与保护措施

| 项目 | 实际环境 |
|---|---|
| 虚拟化 | VMware Workstation 16，Ubuntu 来宾，NAT |
| 系统 | Ubuntu 22.04.5 LTS，x86_64，8 vCPU，13520 MiB RAM |
| 内核 | `6.8.0-60-generic`；BTF 可用；`CONFIG_BPF_LSM=y` |
| 已启用 LSM | `lockdown,capability,bpf,yama,apparmor` |
| 检测与构建 | Falco 0.42.1 modern eBPF、clang 14、Go 1.26.8 |
| TSA | Python 3.10.12、PyYAML 5.4.1、SQLite |
| 基线 | 本轮真实执行并完成的 Lynis 系统审计 |

执行前完成 VMware 快照 `codex-before-security-validation-20260911`，另行备份旧服务配置、程序、策略和 TSA 数据。创建独立验证目录，保留旧项目目录和原有 `/usr/local/go` 1.21.0，不覆盖原受保护文件的内容。

来宾无法正常访问 GitHub/官方 Go 模块代理，因此使用 Git bundle 传入已校验提交。Go 1.26.8 官方归档在主机和来宾两侧校验 SHA256；模块通过 `goproxy.cn` 下载，保留 Go 校验和验证，`go mod verify` 通过。没有关闭 TLS、APT 签名或 Go 校验和验证。

隔离工具链解决本机旧 Go 兼容性问题。总部署脚本现在支持绝对路径 `GO_BIN`，仍以普通部署用户构建，再由 root 安装服务。

## 2. 构建与内核检查

| 检查 | 结果 |
|---|---|
| Python 回归测试 | 38 项通过，包含 Linux 日志重命名语义测试 |
| Go 常规检查 | `go test -race ./...`、`go vet ./...`、控制器构建通过 |
| BPF 生成 | `go generate ./...` 使用 clang 14 成功 |
| Shell 语法 | 总部署、Falco 部署和规则下载脚本 `bash -n` 通过 |
| Go 已知漏洞检查 | govulncheck v1.8.0 扫描 Go 1.26.8 控制器，未发现已知漏洞 |
| 真实内核挂载 | 六个 BPF LSM hooks 全部挂载成功 |
| BPF 对象兼容 | 仓库随附对象和来宾重新生成的对象分别通过同一内核集成测试 |

`TestBPFEnforceIntegration` 在临时文件上实际验证：

- enforce 拒绝普通写入、共享可写 mmap、`MAP_SHARED_VALIDATE`、共享映射的 mprotect 写权限升级、截断、删除、移走受保护文件和重命名覆盖受保护目标。
- 私有 COW 映射可写，且底层受保护文件内容保持不变。
- 无关文件可写；audit 模式和允许的 UID 可以写入、共享映射、升级权限、截断、重命名及删除。

测试进程退出后关闭自身的 BPF links，不保留临时保护策略。

## 3. 端到端与故障验收

以下 13 项在真实 systemd 服务、日志和 SQLite 数据库上通过，不是模拟返回值：

| 检查 | 实际观察 |
|---|---|
| 初始健康与接口 | 健康检查/评分为 200；分数符合 `0.4 * posture + 0.6 * runtime`；只监听回环地址，非法 Host 返回 403 |
| audit 完整链路 | 演示文件写入成功；Falco 和 BPF 均有真实事件、入库并计分；看板 API 生成双来源关联证据 |
| 自定义读取规则 | 读取演示文件产生 `Monitor specific file access` 事件 |
| enforce 完整链路 | 写入返回 `EPERM`；BPF deny 事件入库并计分 |
| 停止 Falco | 健康与评分返回 503，评分 `data:null`；重新启动恢复 |
| 停止 BPF 控制器 | 同上；不把缺失来源当成健康 |
| 停止 TSA | 同上；不把旧分数当作当前有效结果 |
| 心跳卡住 | 对 TSA 发 SIGSTOP，systemd 仍为 active，但过期心跳正确使评分不可用；SIGCONT 后恢复 |
| 进程崩溃 | SIGKILL TSA 后 systemd 自动拉起新 PID，之前入库的事件仍在 |
| 基线缺失 | 临时移走基线后 posture 为未知，评分为 503，不变成 100；恢复报告后恢复健康 |
| 显式纯检测模式 | 运行时禁用 BPF 并停止控制器，Falco-only 模式可用；源 YAML 内容未被修改；随后恢复完整模式 |
| 实际日志轮转 | BPF copytruncate 和 Falco rename/reopen 后，两来源继续入库；旧归档保留 |
| 最终恢复与完整性 | SQLite `integrity_check=ok`，策略/配置恢复，临时 systemd override 已删除 |

故障注入针对隔离验证项目。所有临时改动均在清理逻辑中恢复。完成后再次检查四个服务均为 `active`、`enabled`，健康接口为 200，监听仍为 `127.0.0.1:8766`。最终保留 audit 模式供继续实验，没有未经评估长期启用 enforce。

Falco 默认只报告第一条匹配规则；写演示文件实际可能命中官方 `Write below etc`。验收按对象、进程和时间检查真实行为，再独立验证自定义读取规则，没有为了固定规则名启用 `rule_matching: all`。参见 [Falco 规则匹配说明](https://falco.org/docs/concepts/rules/style-guide/)。

## 4. 可重复验证

先阅读 [QUICKSTART.md](QUICKSTART.md)，在有快照、BPF LSM 和 BTF 的实验虚拟机安装依赖、准备真实基线。以下命令假设已将选定的 Go 工具链加入 `PATH`，且位于项目根目录。

```bash
go version
go mod download
go mod verify
go test -race ./...
go vet ./...
PYTHONPATH=tsa python3 -m unittest discover -s tsa/tests -v
bash -n deploy-security-stack.sh falco/deploy-host-falco.sh falco/fetch-official-rules.sh

# 先测试仓库随附的 BPF 对象；只在实验虚拟机执行。
TEST_DIR="$(mktemp -d)"
go test -c -o "$TEST_DIR/lrss-kernel-test"
sudo env BPF_LSM_INTEGRATION=1 "$TEST_DIR/lrss-kernel-test" -test.run TestBPFEnforceIntegration -test.v

# 再验证本机重新生成的对象。
go generate ./...
go test -c -o "$TEST_DIR/lrss-kernel-test-rebuilt"
sudo env BPF_LSM_INTEGRATION=1 "$TEST_DIR/lrss-kernel-test-rebuilt" -test.run TestBPFEnforceIntegration -test.v

# 完成基线准备后部署，保留选定的工具链。
sudo GO_BIN="$(command -v go)" ./deploy-security-stack.sh
systemctl is-active falco-modern-bpf bpf-lsm-controller tsa-fusion tsa-dashboard
curl --fail http://127.0.0.1:8766/healthz
curl --fail http://127.0.0.1:8766/systemManage/risk/score
```

正常的非特权 Go 测试会跳过内核集成用例；看到 `SKIP` 不能当作实际阻断通过。`go generate` 会更新生成物，应在专用验证 checkout 运行。

部署后按 QUICKSTART 触发演示文件的 audit，再只对该演示文件切换 enforce，观察系统调用结果、两来源日志、SQLite 和看板关联。完成后恢复原策略。上述 13 项故障检查需要明确的服务停止/恢复、临时基线备份和日志轮转；不是 CI 默认执行内容，不能在生产机器照搬故障注入。

## 5. 未解决的风险与边界

- **主机基线不合格不能被项目测试掩盖。** Lynis 完整报告的 `hardening_index=59`，并包含 `PKGS-7392` 软件包风险警告。APT 对配置的软件源请求出现 HTTP 403，已有 Falco 源缺少公钥 `65106822B35B1B1F`。本轮没有关闭签名验证或擅自升级整个系统；必须先修复软件源和包更新流程，再复扫确认。
- **两个分数不是同一指标。** 当前 TSA 的 warnings-only 配置按该警告扣 15 分，因此 posture 为 85，不是 Lynis 原始 hardening index。最终运行时分数受测试事件影响，没有删除历史事件来制造高分。高分不是安全认证。
- **保护不是无间断的。** 控制器未 pin links，停止/重启存在保护空窗；故障时评分不可用不代表主机仍在阻断。之前存在的共享可写映射不会被策略加载撤销，inode 重建需要刷新策略，root 可改变安全配置。
- **关联仍是启发式。** 缺少 PID 时使用进程、对象和时间关联，不能当作严格取证归因；两来源可分别扣分，需要按实际业务调参。
- **覆盖范围有限。** 未验证整机冷启动、长时间压力/磁盘耗尽、所有文件系统、其他内核或所有 Falco 版本；未做完整依赖供应链审计及外部渗透测试。页面/API 响应和看板证据数据已检查，不等于完成跨浏览器视觉验收。
- **网络保持收敛。** 没有开放看板到局域网，也没有安装 SSH 服务；本次本机地址指 Ubuntu 来宾内部。远程接入需要另行配置经过认证的 SSH 转发或 TLS 代理。

因此建议将本次修复作为“已在指定 Ubuntu 环境验证的安全加固版本”进入代码审查。生产准入仍需主机补丁/账户加固、真实工作负载回归、启动和压力测试，以及运维与恢复方案。

## 6. 仓库规则部署更新验证

同日针对 `77249a6` 的规则部署功能，完成以下新增验证：

- Ubuntu 上 53 项 Python 测试全部通过，包括新增 15 项规则部署回归；Shell 语法检查通过。
- 使用实际 Falco 0.42.1，在隔离的空配置目录中安装规则：该目录没有任何系统官方规则文件，仍成功使用仓库锁定的 93 条官方定义与项目规则。此为模拟新机器规则目录的测试，不声称重新安装了一套全新操作系统。
- 重复安装、增加/移除自定义规则通过；向候选规则注入不存在的 Falco 字段时，实际引擎拒绝校验，运行配置没有切换。
- 真实执行 Falco 部署脚本成功；系统包官方文件、已有 `my-rule.yaml` 和 BPF 策略字节保持不变，旧项目规则副本没有重复加载。
- 文档中的 `Project learning file opened` 示例产生真实 Falco 事件并进入 TSA，状态 `scored`、扣 5 分。首次重启后立即读取未捕获事件；等待并重复只读操作后成功，文档已注明启动窗口。
- 示例只装入临时验证规则包；完成后恢复仓库默认自定义规则，保留旧规则包与配置备份，健康检查返回 200。
- 切换到仓库规则包后重新执行第 3 节全部 13 项端到端/故障检查，全部通过，包括真实 audit/deny、双源关联、心跳、缺失基线、纯检测模式和日志轮转；最终恢复 audit 与完整采集模式。

规则路径现在为 `/etc/falco/security-stack/rules/<规则包ID>/`，具体路径由 `falco.yaml` 的 `rules_files` 指向。本机额外规则仍显式加载。官方锁定内容不等于上游发布签名证明，也不保证所有规则启用；规则维护与新机步骤见 [FALCO_RULES.md](FALCO_RULES.md)。

## 7. 合并前复审与恢复补测

同日针对 `6ccee00` 在同一 Ubuntu 虚拟机复审规则安装、部署脚本、BPF 策略与内核集成、systemd 依赖及看板可用性逻辑，未发现新的合并阻断问题。本轮没有为了提交而增加无必要的产品代码修改。

| 补测 | 结果 |
|---|---|
| 构建与回归 | `go mod verify`、`go test -race ./...`、`go vet ./...`、53 项 Python 测试、Shell 语法和实际 Falco 候选规则校验全部通过 |
| 全部服务停止再启动 | 同时停止四个服务，确认均不活跃、SQLite 完整性正常；按 systemd 依赖启动后健康恢复，已有事件保留 |
| 恢复后的真实采集 | 演示文件 audit 写入再次产生 Falco 与 BPF 事件并入库 |
| 无效规则拒绝 | 实际 Falco 引擎拒绝不存在的字段，安装函数失败；主配置字节和原 Falco PID 均不变 |
| 规则回退 | 安装有效临时规则包后，恢复备份配置、校验并重启，重新使用此前的规则包 |
| 回退后再次部署 | 重新安装仓库默认包并重启成功；原 BPF 策略和主机额外规则内容不变 |
| 特权内核回归 | 再次以 root 执行 `TestBPFEnforceIntegration`，六个 hook 的阻断及 audit/允许 UID 路径通过 |

完成后恢复默认规则包、audit 策略与全部服务，健康和评分接口均返回 200。测试事件保留，评分会因此下降；没有清空事件或重置分数。全部服务停止再启动不等于操作系统冷启动，本轮没有重启整台虚拟机。

**合并建议：可以将本分支合并为已在上述环境验证的安全加固版本。** 第 5 节的生产边界仍然成立，尤其是控制器重启期间保护空窗与主机补丁问题；这些限制不能被测试通过或 GitHub 合并消除。建议合并不等于宣称项目不存在漏洞或已满足生产准入。
