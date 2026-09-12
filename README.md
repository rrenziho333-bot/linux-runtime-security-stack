# 主机运行时安全检测与阻断系统

把 Falco、BPF LSM、TSA、Lynis 组合成一条主机安全流水线：Falco 发现可疑行为并报警，BPF LSM 在内核对敏感文件做审计或阻断，TSA 汇总事件算风险分，Lynis 给系统基线分。

> 看板仅本机访问，远程使用 SSH 转发或有鉴权的 TLS 代理；基线或采集不可用时评分接口返回 503。技术边界和旧版本升级注意事项见本文第 8 节。

- 从空白 Ubuntu 到部署验收（唯一复现入口）：[docs/INSTALL.md](docs/INSTALL.md)
- clone 后规则在哪里、如何添加自定义规则：[docs/FALCO_RULES.md](docs/FALCO_RULES.md)
- 已验证的环境、阻断效果和未覆盖范围：[docs/VM_VALIDATION.md](docs/VM_VALIDATION.md)
- 风险分配置：[tsa/policy_config.yaml](tsa/policy_config.yaml)

> **2026-09-11 干净 Ubuntu 实测**：从 GitHub 直接克隆 main，在 Ubuntu 22.04.5、kernel 6.8.0-138-generic、Falco 0.44.1、Go 1.26.8 环境完成真实告警、enforce 阻断、评分和整机冷启动恢复。需要可用网络与正确系统时间，不等于生产安全认证，详见 [验证记录](docs/VM_VALIDATION.md)。

## 30 秒速览

- 干什么的：在 Linux 主机上做运行时安全检测。Falco 按规则报警，BPF LSM 在内核对受保护文件做审计或阻断，TSA 融合事件算风险分，Lynis 给基线分。
- 怎么跑：按 [Ubuntu 复现指南](docs/INSTALL.md) 准备依赖、内核与基线，再运行部署脚本。有 BPF LSM 才有内核保护能力，默认策略为 audit。
- 怎么验：`systemctl is-active` 看服务 → 写 `/etc/tsa-protected-demo` 触发检测 → 看板 `http://127.0.0.1:8766/` 看证据。
- 怎么对接：经 SSH 转发或有鉴权的代理查询 `GET /systemManage/risk/score`；本机地址为 `http://127.0.0.1:8766/systemManage/risk/score`。
- 跑不起来先看：依赖和 Go 路径是否正确？BTF/BPF LSM 是否可用？基线报告是否完整且新鲜？

## 1. 一张图理解项目

```text
用户/进程执行文件、提权或网络操作
                  │
          Linux 内核与系统调用
             ┌────┴────┐
             ▼         ▼
          Falco     BPF LSM
         广域检测    精确控制
         只报警      AUDIT / DENY
             └────┬────┘
                  ▼
                 TSA
       去重、限速、持久化、风险评分
                  ▲
                  │
                Lynis
              系统基线检查
                  │
                  ▼
       SQLite / JSON 报告 / Web 看板
```

## 2. 四个组件分别做什么

| 组件 | 作用 | 是否拦截 |
|---|---|---|
| Falco | 根据规则检测进程、文件、网络和容器行为 | 否，只报警 |
| BPF LSM | 在内核安全检查点匹配受保护文件 | `audit` 放行，`enforce` 拒绝 |
| TSA | 融合 Falco、BPF LSM 和 Lynis，去重并评分 | 否 |
| Lynis | 检查补丁、认证、SSH、防火墙等静态安全基线 | 否 |

TSA 不是 Falco 插件，是本项目自己写的独立融合服务。Falco 和 BPF LSM 也不重复：Falco 看得广，BPF LSM 管得准。

## 3. 一次敏感操作会发生什么

以写入 `/etc/tsa-protected-demo` 为例（部署脚本会在缺失时自动创建该文件）：

```bash
echo test | sudo tee -a /etc/tsa-protected-demo >/dev/null
```

当前策略是 `audit`，流程是：

1. Falco 匹配文件写入规则并报警；
2. BPF LSM 命中 `protect_demo_config` 策略；
3. 内核记录审计事件，但允许写入；
4. TSA 接收两类事件，去重、限速、扣临时风险分；
5. 看板显示完整证据链。

策略改成 `enforce` 后，第 3 步会返回 `-EPERM`，写入被内核拒绝。

## 4. 当前实现

- Falco（modern eBPF 主机版驱动；已测版本和范围见 [验证报告](docs/VM_VALIDATION.md)）；
- 检测规则默认来自仓库 `falco/official-rules/` 的 93 条官方定义（SHA256 锁定）和 `falco/rules.d/` 的项目规则；添加规则从 `91-custom-rules.yaml` 开始。安装至独立版本目录，不依赖本机已有官方规则数量，不覆盖本机额外规则；定义数量不等于全部启用，详见 [规则指南](docs/FALCO_RULES.md)；
- BPF 策略用 YAML 配置，默认 `audit` 模式；
- TSA 用 SQLite 持久化，支持去重、限速、风险过期、重启恢复；
- Web 看板每 2 秒刷新服务状态、策略、评分和事件证据链；
- 服务由 systemd 管理，日志由 logrotate 轮转。

## 5. 快速使用

默认分支 `main` 已包含安全加固、规则部署和四组件集成功能，直接克隆即可取得完整代码及规则，无需切换开发分支：

```bash
git clone https://github.com/rrenziho333-bot/linux-runtime-security-stack.git
cd linux-runtime-security-stack
```

官方规则在 `falco/official-rules/`，自定义规则在 `falco/rules.d/91-custom-rules.yaml`。克隆只下载文件；规则需要部署后才会加载，默认禁用的规则不会被强制启用。完整 BPF 功能还取决于主机内核能力。

从空白机器开始时，只需按 [Ubuntu 复现指南](docs/INSTALL.md) 准备依赖、内核与基线，再部署验收。

```bash
sudo GO_BIN="$HOME/.local/lib/lrss-go1.26.8/go/bin/go" ./deploy-security-stack.sh
systemctl is-active falco-modern-bpf bpf-lsm-controller tsa-fusion tsa-dashboard
# 完整模式四项 active；降级模式 bpf-lsm-controller 为 inactive（正常，见文档）
```

部署脚本按当前 `SUDO_USER` 和目录生成 systemd unit。目录使用英文字符、数字、`/`、`_`、`-`、`.`，例如 `/home/alice/linux-runtime-security-stack`。用部署用户执行 sudo，详见 [复现指南](docs/INSTALL.md)。

脚本会探测内核是否支持 BPF LSM：支持就部署完整模式（四个服务，策略默认 audit）；不支持就通过运行参数关闭 TSA 的 BPF 日志源，保留 Falco + TSA + 看板，不修改源 YAML。纯检测不等于完成内核阻断复现。

判断当前是哪种模式：

```bash
grep -w bpf /sys/kernel/security/lsm   # 输出含 bpf = 完整模式；无输出 = 降级模式
```

看板地址：

```text
http://127.0.0.1:8766/   （别的主机通过 SSH 转发访问）
```

服务只绑定 `127.0.0.1:8766`，部署不自动开防火墙端口。远程访问先运行 `ssh -N -L 127.0.0.1:8766:127.0.0.1:8766 user@linux-host`。

### 对外接口：查询实时风险分值

外部系统（如零信任管理系统）可用 HTTP GET 查询监测机的实时风险分，响应遵循《零信任管理系统接口文档》统一信封 `{code, status, message, data}`：

```bash
# 在监测机本机，或已建立 SSH 转发的访问端查询
curl http://127.0.0.1:8766/systemManage/risk/score
# → {"code":20000,"status":true,"message":"操作成功",
#    "data":{"final":100.0,"posture":100.0,"runtime":100.0,"generated_time":"..."}}
```

`final` 是最终风险分（满分 100，越低越危险）。上例只适用于基线和采集就绪；否则 HTTP 503、`code:50000`、`data:null`。看板显示未知值，具体条件见本文第 8 节。

部署和验收只需按 [INSTALL.md](docs/INSTALL.md) 操作；规则维护查 [FALCO_RULES.md](docs/FALCO_RULES.md)，实测范围查 [VM_VALIDATION.md](docs/VM_VALIDATION.md)。

## 6. 核心代码

```text
<项目根目录>（部署脚本所在目录）
├── bpf/lsm_block_write.c       # 内核 BPF LSM 程序
├── main.go                     # BPF 加载、挂载和事件输出
├── policy.go                   # 策略校验及 BPF Map 写入
├── policy.yaml                 # 当前保护对象与 audit/enforce 模式
├── falco/
│   ├── rules.d/                # 自定义 Falco 规则与例外
│   ├── official-rules/         # 默认部署的固定官方规则（93 条定义）
│   ├── rules.lock.json         # 官方规则校验和与数量
│   ├── manage_rules.py         # 校验、安装版本化规则包
│   └── fetch-official-rules.sh # 维护者更新官方规则来源
├── tsa/
│   ├── tsa_core.py             # 事件融合、去重、评分和持久化
│   ├── tsa_fusion.py           # TSA 服务入口
│   ├── tsa_dashboard.py        # 只读 Web 看板
│   ├── policy_config.yaml      # TSA 评分策略
│   └── tests/                  # Python 单元与集成测试
├── docs/                       # INSTALL、FALCO_RULES、VM_VALIDATION
├── deploy-security-stack.sh    # 测试、安装和启动入口
└── systemd/                    # 服务定义（模板，部署时渲染）
```

`lsmbpf_x86_bpfel.go/.o` 是 `bpf2go` 生成文件，`bpf-lsm-controller` 是构建产物，不是手写核心逻辑。

## 7. 文件保留依据

| 类别 | 为什么保留 |
|---|---|
| `falco/official-rules/*.yaml`、`rules.d/*.yaml`、`rules.lock.json` | 固定官方规则、自定义入口、必要例外与完整性校验；三份官方规则不是版本备份 |
| `falco/manage_rules.py`、`deploy-host-falco.sh` | 前者校验并安装规则包，后者配置日志权限和 Falco 服务；总部署调用它们 |
| `falco/fetch-official-rules.sh`、`extract_rule_snapshot.py`、`official-rules/VERSION.txt` | 规则更新、安全归档读取与来源追溯；不是日常启动步骤，也不是遗留副本 |
| BPF C、`vmlinux.h`、生成的 `.go/.o`、Go 源码与 `go.mod/go.sum` | 支持重新生成、离线构建和实际内核加载；删除对象文件会使 Go embed 编译失败 |
| TSA 源码与策略、`systemd/`、`logrotate/` | 采集、评分、看板、开机启动、权限及日志轮转均在部署链路内 |
| Go/Python 测试、`.github/workflows/tests.yml` | 总部署和 CI 的回归检查；减少文件不能以去掉安全测试为代价 |
| 本 README、`docs/INSTALL.md`、`docs/FALCO_RULES.md`、`docs/VM_VALIDATION.md` | 分别承担项目总览与技术边界、唯一安装流程、规则维护、实测证据；不再单独保留安全设计文档 |

本仓库只保留一套主机部署链路和一套 CI 测试入口。日志、数据库、工具链下载与控制器可执行文件属于本地产物，不提交 Git；不要清理已部署机器的历史证据或规则回滚备份。

## 8. 安全设计与边界

### 权限与阻断

- Falco 只检测；TSA 和看板以普通用户运行，只读采集结果，不写 BPF Map、不修改内核策略。root 控制器负责校验 YAML、写 Map 和挂载程序，评分不会自动切换 `enforce`。
- 控制器将绝对路径解析为 `device + inode`，映射到策略 ID、模式和过期时间。未命中、已过期或 UID 在允许名单中时，本项目不阻断；否则 `audit` 记录放行，`enforce` 记录并返回 `-EPERM`。
- 六个 hooks：`file_permission`（写入）、`inode_unlink`（删除）、`inode_rename`（重命名或覆盖）、`inode_setattr`（属性）、`mmap_file`（新建共享可写映射）、`file_mprotect`（共享映射升级为可写）。ring buffer 只传递事件证据，阻断决策在内核完成。
- 文件删除后以新 inode 重建，需要重启控制器刷新策略；未实现按父目录和文件名拦截新建。`allowed_uids` 仅按 UID 放行，不校验可执行文件签名或 cgroup。
- 已存在的共享可写映射不会被后加载的策略撤销。应先在 audit 中验证正常访问和回滚，再切换 enforce，并重新启动相关工作负载。
- BPF links 未 pin，控制器停止或重启存在保护空窗；root 能改变主机安全配置。

### 评分与证据

- `final = posture * 0.4 + runtime * 0.6`。`posture` 是本项目从 Lynis 报告计算的基线分，不等于 Lynis hardening index；`runtime` 根据未过期风险事件计算。权重仍需实验校准，不是安全认证。
- 事件支持指纹去重、每规则每分钟限速、每规则风险上限及有效期；部署维护窗口不计分。两个事件源可分别扣分，日志轮转和历史清理不代表无限吞吐或磁盘保护。
- 事件、去重、限速和日志位置在同一 SQLite 事务中提交，失败后重放未确认事件；已有日志首次接入默认从末尾读取，首次部署不能代替历史日志取证。
- 看板在 3 秒窗口内优先按 PID 关联；Falco 缺少 PID 时按进程名与受保护路径匹配，并展示依据。关联只用于展示，不改变评分，也不是内核级唯一事务关联。
- 基线需含 `report_version_major`、`finish=true`，默认一天有效；TSA 每 300 秒刷新，只读取报告。无基线不会自动给 100 分，显式禁用基线仅适用于运行时单项实验。
- TSA 心跳超过 30 秒、启用的采集服务停止、日志不可读或基线无效时，健康与评分接口返回 HTTP 503、评分 `data:null`。服务 active 不足以证明采集正常。

### 访问与升级

- 看板只提供状态读取，拒绝非回环绑定并校验 Host，但仍信任本机用户。远程访问使用 SSH 或有鉴权的 TLS 代理，代理上游 Host 设为 `127.0.0.1:8766`；旧版遗留的防火墙开放规则需自行检查。
- 升级按 [复现指南](docs/INSTALL.md) 重新部署，不要只替换 Python 文件。部署以普通用户构建、root 安装，通过 systemd 参数选择完整或纯检测模式，不重写源 YAML。
- Falco 计分白名单位于 `runtime_rules.whitelist`，不支持旧的 `bpf_lsm.whitelist`。优先按精确规则条件设置例外，不要仅凭可伪造的进程名豁免风险。

实际测试范围见 [验证记录](docs/VM_VALIDATION.md)，历史修复可查 Git 历史；上述设计不是无漏洞保证。

## 9. 修改内核代码后构建

标准构建链为 cilium/ebpf `bpf2go`。普通部署使用已提交的 `lsmbpf_x86_bpfel.go/.o`；修改内核 C 后才需重新生成。先安装 clang、llvm、libbpf-dev，将所选 Go 工具链加入 PATH，再在 Ubuntu 项目根目录依次执行：

**命令 9.1：重新生成 BPF 对象与 Go 绑定。**
```bash
go generate ./...
```

**命令 9.2：运行 Go 竞态测试。**
```bash
go test -race ./...
```

**命令 9.3：运行 Go 静态检查。**
```bash
go vet ./...
```
