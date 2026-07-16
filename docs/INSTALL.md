# 空白 Linux 从零到可运行

本手册面向一台全新安装、未做任何安全栈配置的 Linux 主机，把环境从零带到
`sudo ./deploy-security-stack.sh` 可成功执行、检测流水线生效的状态。

部署脚本本身不含硬编码路径，能在任意目录运行。真正可能卡住你的是两类**环境前提**：
Falco、Go 工具链。内核 BPF LSM 是**可选**的——有它则启用内核级阻断，没有它则自动
降级为纯检测（见第 9 节）。本文依次解决。

> 操作系统示例以 Fedora / Ubuntu 为主。其他发行版请按等价命令替换包管理器。

## 0. 适用平台与权限

- x86_64 Linux 内核 ≥ 5.7（BPF LSM 引入版本），建议 ≥ 5.13（LSM hook 更全）。
- 全程需要 root（`sudo`）。部署脚本会以 `SUDO_USER` 作为运行/构建账户。
- 不支持在 macOS / WSL1 / 无 BPF LSM 的内核上端到端运行（TSA 纯软件部分可在任意平台跑单测）。

## 1. 开启内核 BPF LSM（最关键的门槛）

BPF LSM 是 内核 编译期选项 `CONFIG_BPF_LSM=y` + 引导期 `lsm=` 参数，**两者都要满足**。
项目代码无法绕过这一步：未启用时 `bpf-lsm-controller` 挂载 LSM 程序会直接失败。

### 难度拆解（三层，从易到难）

1. **引导参数 `lsm=` 含 `bpf`** —— 容易。改 grub 一行重启即可（见 1.2）。
2. **内核编译了 `CONFIG_BPF_LSM=y`** —— **真门槛**。`CONFIG_BPF_LSM` 在内核里
   是默认 `n` 的选项，开不开完全取决于发行版内核配置（见 1.4 现状说明）。
3. **`CONFIG_DEBUG_INFO_BTF=y`** —— modern eBPF / Falco 强依赖，缺它 Falco 也起不来。

> 结论：**门槛真实存在，且无法靠版本号一刀切判断**。必须在这台机器上用 1.1 的两条命令
> 实测。达不到时的降级运行方案见第 9 节。

### 1.1 先确认当前状态

```bash
# 1) 内核是否编译了 BPF LSM
grep CONFIG_BPF_LSM /boot/config-$(uname -r) 2>/dev/null \
  || zgrep CONFIG_BPF_LSM /proc/config.gz 2>/dev/null \
  || echo "未找到内核配置，可能需要安装 kernel-devel 或开启 CONFIG_IKCONFIG_PROC"

# 2) 引导期是否加载了 bpf LSM
grep -w bpf /sys/kernel/security/lsm
```

- 1) 输出 `CONFIG_BPF_LSM=y` 才算编译支持。若是 `# not set` 或 `=n`，**必须换内核**（见 1.3）。
- 2) 输出列表里含 `bpf` 才算已加载。不含则只需改引导参数（见 1.2），无需换内核。

### 1.2 已编译支持但未加载：改引导参数

把 `bpf` 追加到 `lsm=` 启动参数。顺序要求：`lsm=` 是逗号分隔，`bpf` 必须在
`integrity`（若启用）之后；一般放最后即可。

**Fedora / RHEL（grub2）：**

```bash
# 查看当前默认内核行
sudo grubby --info=ALL | grep -E 'kernel|args'
# 追加 lsm 参数（grubby 会自动处理多内核条目）
sudo grubby --update-kernel=ALL --args="lsm=lockdown,y,integrity,apparmor,bpf"
sudo reboot
```

**Ubuntu / Debian（grub）：**

```bash
# 编辑 /etc/default/grub，在 GRUB_CMDLINE_LINUX_DEFAULT 末尾加 lsm 参数
# 例如：GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=lockdown,y,integrity,apparmor,bpf"
sudo nano /etc/default/grub
sudo update-grub          # EFI: sudo grub-mkconfig -o /boot/efi/EFI/.../grub.cfg
sudo reboot
```

重启后再次 `grep -w bpf /sys/kernel/security/lsm`，含 `bpf` 即成功。

### 1.3 内核没编译支持：换内核

多数发行版的官方内核**默认不开** `CONFIG_BPF_LSM`。选择：

- **Fedora**：`sudo dnf install kernel-edge` 或确认 `kernel-core` 的 config；Fedora 近年默认通常已开。
- **Ubuntu**：主线 `linux-generic` 有时未开，可换 `linux-generic-hwe`；仍不行需自行编译。
- **Arch**：官方 `linux` 内核通常已开 `CONFIG_BPF_LSM=y`，只需补引导参数。
- **自编译**：在内核 config 里设 `CONFIG_BPF_LSM=y`（位于 `Security options → BPF LSM`），重编安装。

确认命令同 1.1。

### 1.4 各发行版现状实测（不要靠版本号一刀切）

`CONFIG_BPF_LSM` 在内核是默认 `n` 的选项，**开不开完全取决于发行版内核配置**，
且 Ubuntu 不同版本/变种之间有差异，不能凭"22.04 一定开"或"Ubuntu 都不开"判断。
**唯一可靠做法是在目标机上实测**：

```bash
grep CONFIG_BPF_LSM /boot/config-$(uname -r)   # =y 才算编译支持
grep -w bpf /sys/kernel/security/lsm            # 含 bpf 才算已加载
```

经验性参考（以实测为准）：

- **Ubuntu**：标准 `linux-generic` 内核历史上开 BPF LSM 的情况不稳定；`linux-generic-hwe`
  / `linux-generic-edge` 开启概率更高。很多 Ubuntu 实测达不到——这正是本项目提供降级方案
  （第 9 节）的原因。Ubuntu 通常**已开** `CONFIG_DEBUG_INFO_BTF`。
- **Fedora / 较新 RHEL 系**：官方内核开 `CONFIG_BPF_LSM` 的概率较高。
- **Arch**：官方 `linux` 内核通常已开 `CONFIG_BPF_LSM=y`，往往只需补引导参数。

实测结果对应处理：

| `CONFIG_BPF_LSM` | `lsm=` 含 bpf | 处理 |
|---|---|---|
| `=y` | 是 | 完整运行（检测+阻断） |
| `=y` | 否 | 改 grub 引导参数（1.2），重启即完整运行 |
| `not set`/`=n` | — | 换内核/自编译（1.3），或走降级方案（第 9 节） |

### 1.5 常见坑

- 改了 `lsm=` 不生效：EFI 系统检查是否更新了正确的 grub.cfg；部分系统用 `systemd-boot`，改 `/etc/kernel/cmdline` 后 `sudo bootctl update`。
- `/sys/kernel/security/lsm` 不存在：内核未编 `CONFIG_SECURITY`，需换内核。
- 容器/VM 内看不到：LSM 是宿主机内核能力，容器里跑本工具需宿主机内核满足且容器特权/挂载 securityfs，建议直接在宿主机裸跑。

## 2. 安装 Falco（modern eBPF 驱动）

项目用的是 Falco 0.42+ 的 **modern eBPF** 驱动（不依赖旧 Kmodule/legacy 驱动），服务名为
`falco-modern-bpf.service`。部署脚本里的 `falco/deploy-host-falco.sh` 只往
`/etc/falco/falco.yaml` 塞规则并重启服务，**不负责安装 Falco 本体**，所以必须先装好。

### 2.1 官方源安装（推荐）

```bash
# Fedora / RHEL / Rocky
sudo rpm --import https://falco.org/repo/falcosecurity-packages.asc
sudo curl -s -o /etc/yum.repos.d/falcosecurity.repo \
  https://falco.org/repo/falcosecurity-rpm.repo
sudo dnf install -y falco

# Ubuntu / Debian
sudo mkdir -p /etc/apt/keyrings
curl -s https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /etc/apt/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update && sudo apt-get install -y falco
```

### 2.2 验证

```bash
falco --version
# modern eBPF 驱动需要内核 BTF（CONFIG_DEBUG_INFO_BTF=y），确认：
ls /sys/kernel/btf/vmlinux   # 存在即可
```

> 若 `/sys/kernel/btf/vmlinux` 不存在，需内核开 `CONFIG_DEBUG_INFO_BTF=y`（modern eBPF 强依赖）。
> 这也是 1.3 之外第二个"可能要换内核"的点。

## 3. 安装 Go 工具链

部署脚本写死 `/usr/local/go/bin/go`，需 Go 1.23。

```bash
GO_VERSION=1.23.10
wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
/usr/local/go/bin/go version    # 应输出 go1.23.x
```

项目依赖已在 `go.sum` 锁定；部署脚本用 `GOPROXY=off` 离线构建，所以**第一次需先在有网环境把依赖拉到模块缓存**：

```bash
# 用部署用户拉取依赖到其模块缓存（只需一次）；sudo 下 $(whoami) 是 root，应显式用 SUDO_USER
runuser -u "${SUDO_USER:-$USER}" -- /usr/local/go/bin/go mod download
# 或全员缓存：sudo /usr/local/go/bin/go env -w GOMODCACHE=/usr/local/go/pkg/mod
```

> 不联网的离线机器：在联网同架构机器上 `go mod download` 后，把 `$(go env GOMODCACHE)`
> 整目录拷到目标机同路径，再跑部署脚本。

## 4. 安装 Lynis（可选，仅基线分）

不装则 TSA 的 `posture`（静态基线）分恒为满分；装了才能按 Lynis 报告扣分。

```bash
sudo dnf install -y lynis      # Fedora
sudo apt-get install -y lynis  # Ubuntu
lynis show version
```

TSA 配置默认 `run_lynis: false`，即只读 Lynis 报告、不主动执行。若要让 TSA 周期跑 Lynis，
改 `tsa/policy_config.yaml` 的 `baseline_lynis.run_lynis: true`（需 TSA 进程有 root，注意与
当前以普通用户运行的设计冲突，一般保持 false、由 cron 单独跑 Lynis 生成报告更稳）。

报告路径默认 `reports/lynis-report.dat`（相对 `tsa/` 目录解析）。

## 5. 克隆并部署

```bash
# 任意目录、任意有 sudo 权限的用户
git clone <仓库地址> ~/linux-runtime-security-stack
cd ~/linux-runtime-security-stack
sudo ./deploy-security-stack.sh
```

部署脚本依次：建维护标记 → 跑 Go/Python 测试 → 校验 BPF 策略 → 创建演示文件
`/etc/tsa-protected-demo`（如不存在）→ 部署 Falco 规则 → 探测内核 BPF LSM：
有则装 BPF 控制器并启动四个服务；无则自动降级、启动 Falco+TSA+看板三个服务 → 清维护标记。

## 6. 验证

```bash
systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard
# 以上三项均 active 即检测流水线正常运行（完整模式另见下行的 bpf-lsm-controller）

# 完整模式（内核有 BPF LSM）额外确认：
systemctl is-active bpf-lsm-controller   # active = 完整；inactive = 已降级为纯检测（见第 9 节，非故障）

# 触发一次当前 audit 模式的检测
echo "demo" | sudo tee -a /etc/tsa-protected-demo >/dev/null
sleep 2
sudo tail -n 3 /var/log/bpf-lsm/events.jsonl | jq     # 完整模式应有 BPF 审计事件；降级模式无此文件
journalctl -u tsa-fusion -n 10 --no-pager             # 应有评分日志
curl -s http://127.0.0.1:8766/healthz                 # {"status":"ok"}
```

实时监测、看板、持续盯日志的命令见 [DEPLOYMENT.md](DEPLOYMENT.md) 第 2.2 节。

## 7. 关于 Falco 规则数量

项目自带的检测规则只有 **1 条**：`falco/rules.d/90-local-file-monitoring.yaml`
（盯 `/etc/tsa-protected-demo` 的 open）。但实际生效的检测规则远不止此——部署时
`deploy-host-falco.sh` 会加载 **Falco 官方规则集**（`falco_rules.yaml` +
`falco-sandbox_rules.yaml` + `falco-incubating_rules.yaml`，共 93 条，覆盖提权、容器逃逸、
挖矿、反弹 shell、敏感文件读写等）。官方规则快照**已入库** `falco/official-rules/`，
clone 后即可直接阅读分析；要与本机已装 Falco 版本对齐，用 `falco/fetch-official-rules.sh`
重新拉取，见第 10 节。

TSA 的 `tsa/policy_config.yaml` 里 `specific_rules` 为这 93 条官方规则中的 **86 条**配了
扣分权重（其余走优先级兜底），这是评分映射，不是新增检测规则。
`95-security-stack-exceptions.yaml` 是给官方规则打白名单补丁的 list/macro，也不算新增规则。

因此实际保护覆盖：**官方规则广域检测 + 1 条自定义文件监控 + BPF LSM 内核级精确决策（若有 BPF LSM）或 Falco 纯检测（降级）**。

## 8. 一览检查清单

**必选（检测流水线，对应完整或降级模式）：**
- [ ] `/sys/kernel/btf/vmlinux` 存在（modern eBPF，Falco 强依赖）
- [ ] `falco --version` 可用
- [ ] `/usr/local/go/bin/go version` 输出 1.23.x，依赖已缓存
- [ ] （可选）`lynis` 已安装
- [ ] `sudo ./deploy-security-stack.sh` 全程无错
- [ ] `falco-modern-bpf`、`tsa-fusion`、`tsa-dashboard` 三项 `active`

**完整模式额外（启用内核级阻断时）：**
- [ ] `grep CONFIG_BPF_LSM /boot/config-$(uname -r)` 输出 `=y`
- [ ] `grep -w bpf /sys/kernel/security/lsm` 含 `bpf`
- [ ] `bpf-lsm-controller` `active`（inactive 则为降级，非故障，见第 9 节）

## 9. 内核达不到 BPF LSM 时的降级运行

当 1.1 实测确认内核**没有** `CONFIG_BPF_LSM=y`（很多 Ubuntu 即如此），且不便换内核时，
项目**自动降级为纯检测模式**：失去 BPF LSM 内核级阻断，但保留 Falco 检测 + TSA 评分 + 看板证据链。

降级依据：BPF LSM 是本项目**独立组件**，TSA 只读 Falco 日志即可工作，不依赖 BPF LSM。
Falco 的 modern eBPF 驱动基于 tracepoint/kprobe，**只需要 BTF + CAP_BPF，不需要 BPF LSM**。

### 9.1 自动降级（默认）

`deploy-security-stack.sh` 会在开头探测 `/sys/kernel/security/lsm` 是否含 `bpf`：

- **含 `bpf`** → 完整部署（检测 + 阻断，四个服务全部 active）。
- **不含 `bpf`** → 自动降级：
  - 跳过 `bpf-lsm-controller` 的安装与启动；
  - 自动把 `tsa/policy_config.yaml` 的 `bpf_lsm.enabled` 置为 `false`，避免 TSA 盯不存在的日志；
  - 仍安装并启动 Falco + TSA + 看板；结尾打印 `DETECTION-ONLY mode` 提示。

因此**一条 `sudo ./deploy-security-stack.sh` 即自动适配**：无需人工判断、不会因缺 BPF LSM 而
中断。降级后 `systemctl is-active bpf-lsm-controller` 显示 `inactive` 是预期，不是故障。

### 9.2 手动确认 / 回到完整模式

```bash
# 确认当前模式
grep -w bpf /sys/kernel/security/lsm && echo "完整模式可用" || echo "当前为降级模式"

# 若内核后来补上了 BPF LSM（换内核/改 lsm= 引导参数后），重新部署即自动切回完整模式
sudo ./deploy-security-stack.sh
```

### 9.3 降级后的能力对比

降级后的能力对比：

| 能力 | 完整模式（有 BPF LSM） | 降级模式（无 BPF LSM） |
|---|---|---|
| 行为检测 | Falco + BPF LSM | 仅 Falco |
| 内核级阻断 | `enforce` 返回 -EPERM | ✗ 无（Falco 本身只报警） |
| 风险评分 | TSA（posture + runtime） | 同左（runtime 只来自 Falco） |
| 证据链看板 | Falco↔BPF 关联 | 仅 Falco 事件链 |
| 内核门槛 | BPF LSM + BTF | 仅 BTF |

> 需要保留阻断能力的替代方案：用 Falco 的响应引擎（`falcoctl` / Falcosecurity 的
> `priority` 动作 / 事件驱动脚本）在用户态对接 auditd 或自定义处置，但这偏离本项目
> "内核 LSM 决策"的定位，需额外开发，不在当前范围内。

## 10. 分析 Falco 官方规则

本仓库在 `falco/official-rules/` **默认入库一份官方规则快照**（93 条，带 `VERSION.txt`
标注版本来源），clone 后即可直接阅读。若想与已装 Falco 版本对齐，用
`fetch-official-rules.sh` 重新拉取后再提交即可更新快照。**推荐：从本机已装的 Falco 拷贝**——
那正是实际部署用的同一份。

```bash
# 推荐：从本机已装 falco 拷贝（/etc/falco 下的官方规则文件）
./falco/fetch-official-rules.sh

# 没装 falco 时：从官方 release 下载 tarball（URL 自行从 release 页复制）
./falco/fetch-official-rules.sh --remote-url \
  https://github.com/falcosecurity/rules/releases/download/<tag>/falco_rules.tar.gz

# 或只下载单个规则文件
./falco/fetch-official-rules.sh --remote-url-file <url> falco_rules.yaml
# 查看 help
./falco/fetch-official-rules.sh --help
```

拉取到的三个 yaml 会覆盖 `falco/official-rules/` 中已入库的快照，并更新 `VERSION.txt`
记录来源。重新拉取后 `git add falco/official-rules/` 提交即可更新仓库快照。

> remote 模式不硬编码 URL：`falcosecurity/rules` 各 release 的 asset 命名不一致，故需从
> https://github.com/falcosecurity/rules/releases 复制实际 asset 地址传入。

分析示例：

```bash
# 官方规则总数（三个文件合计，未去重）
grep -c '^- rule:' falco/official-rules/*.yaml
# 找提权相关规则
grep -B1 -A6 'privilege\|escalat' falco/official-rules/*.yaml | head -40
# 看 TSA 评分映射覆盖了多少官方规则
grep '^- rule:' falco/official-rules/*.yaml | sed 's/.*- rule: //' \
  | sort -u | while read r; do grep -q "\"$r\"" tsa/policy_config.yaml && echo "已配权重: $r"; done | wc -l
```

> 注意：拉取到的规则版本应与**实际安装的 falco 版本**一致，分析结论才能套用到线上。
> 生产部署用的仍是 falco 包自带的规则，`deploy-host-falco.sh` 只追加本项目的
> 自定义规则与例外。