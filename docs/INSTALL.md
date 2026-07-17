# 空白 Linux 从零到可运行

本手册面向一台全新安装、未做任何安全栈配置的 Linux 主机，把环境从零带到
`sudo ./deploy-security-stack.sh` 可成功执行、检测流水线生效的状态。

部署脚本本身不含硬编码路径，能在任意目录运行。真正可能卡住你的是两类**环境前提**：
Falco、Go 工具链。内核 BPF LSM 是**可选**的——有它则启用内核级阻断，没有它则自动
降级为纯检测（见第 9 节）。本文依次解决。

> 支持两个发行版系列：**Ubuntu / Debian**（apt）与 **CentOS**（dnf/yum）。每个安装步骤同时给出两者的命令，任选其一。其他发行版请按等价命令替换包管理器。

## 0. 适用平台与权限

- x86_64 Linux 内核 ≥ 5.7（BPF LSM 引入版本），建议 ≥ 5.13（LSM hook 更全）。
- 全程需要 root（`sudo`）。部署脚本会以 `SUDO_USER` 作为运行/构建账户。
- 不支持在 macOS / WSL1 / 无 BPF LSM 的内核上端到端运行（TSA 纯软件部分可在任意平台跑单测）。

## 1. （可选）开启内核 BPF LSM，启用内核级阻断

> **先读这段，决定要不要折腾。** BPF LSM 是本项目"内核级阻断"的依赖，**但不是检测的依赖**。
> 没有它，项目自动降级为"Falco 检测 + TSA 评分 + 看板"（见第 9 节），照样能跑、能看报警和评分，
> 只差"在内核里直接拒绝非法操作"这一项。所以：
>
> - 如果你只想要**检测 + 评分 + 看板** → 跳过本节，直接装 Falco/Go（第 2、3 节）即可。
> - 如果你还要**内核级阻断**（enforce 模式返回 -EPERM）→ 按本节确认内核是否支持。
>
> BPF LSM 需要**两个条件都满足**：内核编译时开了 `CONFIG_BPF_LSM=y`，且引导参数 `lsm=` 含 `bpf`。
> 它和 `CONFIG_DEBUG_INFO_BTF=y`（Falco modern eBPF 强依赖）都是内核编译期选项，**无法靠 Ubuntu
> 版本号一刀切判断**，必须在目标机上用下面两条命令实测。

### 1.1 两条命令判断当前状态

```bash
# 1) 内核是否编译了 BPF LSM（=y 才算支持）
grep CONFIG_BPF_LSM /boot/config-$(uname -r) 2>/dev/null \
  || zgrep CONFIG_BPF_LSM /proc/config.gz 2>/dev/null \
  || echo "未找到内核配置，可能需要安装 kernel-devel 或开启 CONFIG_IKCONFIG_PROC"

# 2) 引导期是否加载了 bpf LSM（输出列表里含 bpf 才算已启用）
grep -w bpf /sys/kernel/security/lsm
```

根据结果对照下表，决定下一步：

| 第 1 条结果 | 第 2 条结果 | 含义 | 下一步 |
|---|---|---|---|
| `CONFIG_BPF_LSM=y` | 含 `bpf` | 内核级阻断**可用** | 直接部署，完整模式（检测+阻断） |
| `CONFIG_BPF_LSM=y` | 不含 `bpf` | 编译了但没加载 | 改 grub 引导参数（1.2），重启即完整模式 |
| `not set` 或 `=n` | — | 内核没编译支持 | 换内核/自编译（1.3），**或直接走降级方案（第 9 节）** |

> **大多数 Ubuntu 标准内核落在第三行。** 对很多人来说，换内核代价高于收益——
> 直接走降级方案是最务实的选择（检测链路俱全，只少内核阻断）。

### 1.2 编译了但没加载：改 grub 引导参数

这种情况说明内核**有能力**（编译了 `CONFIG_BPF_LSM=y`），但启动时**没被启用**——
LSM 要不要加载由内核启动参数 `lsm=` 决定，所以得把 `bpf` 加进这个参数。

需要两步：先改 grub 源文件，再重新生成实际生效的 grub 配置（**两步缺一不可**，
只改源文件不重新生成不会生效）。

**第 1 步：编辑 grub 源文件，在启动参数里加 bpf**

```bash
sudo nano /etc/default/grub
```
找到 `GRUB_CMDLINE_LINUX_DEFAULT=...` 这一行，在末尾的引号内追加
`lsm=...bpf`（`lsm=` 是逗号分隔，`bpf` 放最后即可）。例如改为：
```text
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=lockdown,y,integrity,apparmor,bpf"
```
（CentOS 上原有参数可能不含 `splash`，照你机器原本的来，只在末尾加 `lsm=...,bpf`。）

**第 2 步：重新生成 grub 配置并重启**

先确认你的启动方式（BIOS 还是 EFI），这决定下面用哪条命令：

```bash
ls /sys/firmware/efi 2>/dev/null && echo "EFI 启动" || echo "BIOS 启动"
```

然后按发行版 + 启动方式选一条命令，执行后重启：

```bash
# Ubuntu / Debian
sudo update-grub                    # BIOS 启动
# EFI 启动若 update-grub 报错，改用：
#   sudo grub-mkconfig -o /boot/efi/EFI/ubuntu/grub.cfg

# CentOS（没有 update-grub，用 grub2-mkconfig；按 BIOS/EFI 选一条）
sudo grub2-mkconfig -o /boot/grub2/grub.cfg              # BIOS 启动
sudo grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg     # EFI 启动

sudo reboot
```

> **CentOS EFI 用户：确认 grub.cfg 实际路径。** 上面写的是常见路径 `/boot/efi/EFI/centos/grub.cfg`，
> 但不同安装方式目录名可能不同（`centos` / `centos-stream` / `rhel` 等）。先查实际目录：
> ```bash
> ls /boot/efi/EFI/
> ```
> 找到里面的 `<目录名>/grub.cfg`，把命令里的 `centos` 换成实际目录名即可。
> Ubuntu EFI 同理，目录名一般是 `ubuntu`，若不是用 `ls /boot/efi/EFI/` 确认。

重启后再次 `grep -w bpf /sys/kernel/security/lsm`，输出列表里含 `bpf` 即成功。

### 1.3 没编译支持：换内核或自编译（可选，代价较高）

> **CentOS 用户先看这条：** CentOS 7 内核太旧（3.x），**根本没有 BPF LSM**（需内核 ≥5.7），
> 必须先升级到 CentOS 8 / Stream 9 或以上，否则本节其余内容都无从谈起。

如果内核已是较新版本、但仍没开 `CONFIG_BPF_LSM`，又想保留内核级阻断：

- **Ubuntu**：官方 `linux-generic` 通常未开，可试 `linux-generic-hwe`；仍不行自行编译内核。
- **CentOS 8 / Stream 9**：官方内核较新但默认常未开 `CONFIG_BPF_LSM`；可装 ELRepo 的较新内核
  （`dnf install elrepo-release && dnf install kernel-ml`）或自行编译。
- **自编译内核**：在内核 config 里设 `CONFIG_BPF_LSM=y`（位于 `Security options → BPF LSM`），重编安装。

> 不愿换内核就跳过本节，直接用降级方案（第 9 节）——检测功能照样完整运行，只少内核阻断。
> 确认命令同 1.1。

### 1.4 发行版现状参考

**Ubuntu：**

- 标准 `linux-generic` 内核历史上开 BPF LSM 的情况不稳定；`linux-generic-hwe` /
  `linux-generic-edge` 开启概率更高。**很多 Ubuntu 实测达不到**——这正是本项目提供降级方案的原因。
- Ubuntu 通常**已开** `CONFIG_DEBUG_INFO_BTF`（Falco modern eBPF 需要它，这个一般不缺）。

**CentOS：**

- 需 CentOS 8 / Stream 9 或以上（CentOS 7 内核太旧，见 1.3）。
- 官方内核较新，但 `CONFIG_BPF_LSM` 仍可能未开——以 1.1 实测为准。
- 通常**已开** `CONFIG_DEBUG_INFO_BTF`（Falco modern eBPF 需要）。

### 1.5 常见坑

- 改了 `lsm=` 不生效：EFI 系统确认更新的是正确的 grub.cfg；少数系统用 `systemd-boot`，改 `/etc/kernel/cmdline` 后 `sudo bootctl update`。
- `/sys/kernel/security/lsm` 不存在：内核未编 `CONFIG_SECURITY`，需换内核。
- 容器/VM 内看不到：LSM 是宿主机内核能力，建议直接在宿主机裸跑。

## 2. 安装 Falco（modern eBPF 驱动）

项目用的是 Falco 0.42+ 的 **modern eBPF** 驱动（不依赖旧 Kmodule/legacy 驱动），服务名为
`falco-modern-bpf.service`。部署脚本里的 `falco/deploy-host-falco.sh` 只往
`/etc/falco/falco.yaml` 塞规则并重启服务，**不负责安装 Falco 本体**，所以必须先装好。

### 2.1 官方源安装（推荐）

```bash
# Ubuntu / Debian
sudo mkdir -p /etc/apt/keyrings
curl -s https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /etc/apt/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update && sudo apt-get install -y falco
```

```bash
# CentOS 8 / Stream 9（dnf；CentOS 7 用 yum 同理）
sudo rpm --import https://falco.org/repo/falcosecurity-packages.asc
sudo curl -s -o /etc/yum.repos.d/falcosecurity.repo \
  https://falco.org/repo/falcosecurity-rpm.repo
sudo dnf install -y falco
```

### 2.2 验证

```bash
falco --version
# modern eBPF 驱动需要内核 BTF（CONFIG_DEBUG_INFO_BTF=y），确认：
ls /sys/kernel/btf/vmlinux   # 存在即可
```

> 若 `/sys/kernel/btf/vmlinux` 不存在，需内核开 `CONFIG_DEBUG_INFO_BTF=y`（modern eBPF 强依赖）。
> 这也是 1.3 之外第二个"可能要换内核"的点。

## 3. 安装 Go 工具链（仅完整模式需要）

> **降级模式可跳过本节。** Go 只用来编译 BPF LSM 控制器（`bpf-lsm-controller`）。
> 若你的内核没有 BPF LSM、走降级模式，部署脚本会自动跳过 Go 编译，**无需安装 Go**。
> 若你要完整模式（内核级阻断），则必须装 Go。

部署脚本写死 `/usr/local/go/bin/go`，需 Go 1.23。

```bash
GO_VERSION=1.23.10
wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
/usr/local/go/bin/go version    # 应输出 go1.23.x
```

项目依赖已在 `go.sum` 锁定；部署脚本用 `GOPROXY=off` 离线构建，所以**第一次需先在有网环境把依赖拉到模块缓存**。

要点：依赖缓存是**按用户**存的（默认在 `~/.cache` / `~/go/pkg/mod`）。部署脚本稍后是以你的登录用户（`SUDO_USER`）来编译的，所以这里也要用**同一个用户**来拉依赖，否则编译时缓存对不上、又因 `GOPROXY=off` 无法补下而失败：

```bash
# 用部署用户（sudo 下的 SUDO_USER）拉依赖；只在有网的机器上做一次
runuser -u "${SUDO_USER:-$USER}" -- /usr/local/go/bin/go env -w GOTOOLCHAIN=auto
runuser -u "${SUDO_USER:-$USER}" -- /usr/local/go/bin/go mod download

# 或全员缓存到固定路径（更省心）
sudo mkdir -p /usr/local/go/pkg/mod && sudo chown "${SUDO_USER:-$USER}" /usr/local/go/pkg/mod
runuser -u "${SUDO_USER:-$USER}" -- /usr/local/go/bin/go env -w GOMODCACHE=/usr/local/go/pkg/mod
runuser -u "${SUDO_USER:-$USER}" -- /usr/local/go/bin/go mod download
```

> 不联网的离线机器：在联网同架构机器上 `go mod download` 后，把 `$(go env GOMODCACHE)`
> 整目录拷到目标机同路径，再跑部署脚本。

## 4. 安装 Lynis（可选，仅基线分）

不装则 TSA 的 `posture`（静态基线）分恒为满分；装了才能按 Lynis 报告扣分。

```bash
sudo apt-get install -y lynis  # Ubuntu / Debian
# CentOS（Lynis 在 EPEL 源，需先启用 EPEL）
sudo dnf install -y epel-release && sudo dnf install -y lynis
lynis show version
```

TSA 配置默认 `run_lynis: false`，即只读 Lynis 报告、不主动执行。若要让 TSA 周期跑 Lynis，
改 `tsa/policy_config.yaml` 的 `baseline_lynis.run_lynis: true`（需 TSA 进程有 root，注意与
当前以普通用户运行的设计冲突，一般保持 false、由 cron 单独跑 Lynis 生成报告更稳）。

报告路径默认 `reports/lynis-report.dat`（相对 `tsa/` 目录解析）。

## 5. 克隆并部署

```bash
# 任意目录、任意有 sudo 权限的用户；Ubuntu / CentOS 命令一致
git clone https://github.com/rrenziho333-bot/linux-runtime-security-stack.git ~/linux-runtime-security-stack
cd ~/linux-runtime-security-stack
sudo ./deploy-security-stack.sh
```

部署脚本依次：建维护标记 → 创建演示文件 `/etc/tsa-protected-demo`（如不存在）→ 部署 Falco 规则 →
探测内核 BPF LSM：有则跑 Go 测试、编译并校验 BPF 策略、装 `bpf-lsm-controller`、启动四个服务；
无则跳过 Go 编译、自动降级、只起 Falco+TSA+看板三个服务 → 跑 Python 测试 → 清维护标记。

## 6. 验证

部署成功的判据分四步：服务存活 → 触发检测 → 三组件各自确认 → 看板端到端。

### 6.1 服务存活（基础门槛）

```bash
# 检测流水线三项（完整与降级模式都应为 active）
systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard
# 期望输出三行 active

# 完整模式额外（内核有 BPF LSM）：
systemctl is-active bpf-lsm-controller
# active = 完整检测+阻断；inactive = 已降级为纯检测（见第 9 节，非故障）
```

预期输出样例：

```text
$ systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard
active
active
active

$ systemctl is-active bpf-lsm-controller    # 完整模式
active
# 降级模式此处是 inactive（属正常，非故障）
```

**成功判据①**：`falco-modern-bpf`、`tsa-fusion`、`tsa-dashboard` 三项必须 `active`。
完整模式另要求 `bpf-lsm-controller` 为 `active`（降级模式为 `inactive` 属正常）。

### 6.2 触发一次检测（audit 模式，不阻断）

```bash
echo "demo" | sudo tee -a /etc/tsa-protected-demo >/dev/null
sleep 2
```

### 6.3 三组件分别确认各自检测生效

**Falco 侧（广域检测，必有）：**

```bash
sudo tail -n 5 /var/log/falco/falco.json | jq
# 期望：能看到针对 /etc/tsa-protected-demo 的报警。具体规则名取决于哪个先匹配：
#   - 多数情况是自定义规则 "Monitor specific file access"（专门盯这个文件）
#   - 也可能是官方规则 "Write below etc"（写 /etc 下文件就触发）
# 两者出现任意一个即说明 Falco 检测链路生效。
```

预期输出样例（节选关键字段，实际命令行可能一行排开）：

```json
{
  "rule": "Monitor specific file access",
  "priority": "Warning",
  "output": "Sensitive file opened (file=/etc/tsa-protected-demo access=openat user=root process=tee command=tee -a /etc/tsa-protected-demo)",
  "output_fields": { "proc.name": "tee", "user.name": "root", "fd.name": "/etc/tsa-protected-demo" }
}
```

**BPF LSM 侧（内核级决策，仅完整模式）：**

```bash
sudo tail -n 3 /var/log/bpf-lsm/events.jsonl | jq
# 期望：含 policy_name=protect_demo_config、operation=write、action=audit 的事件
# 降级模式没有此文件（bpf-lsm-controller 本就未启动，不是故障，见第 9 节）
```

预期输出样例：

```json
{
  "source": "bpf_lsm",
  "policy_id": 1001,
  "policy_name": "protect_demo_config",
  "action": "audit",
  "operation": "write",
  "result": 0,
  "pid": 12345,
  "uid": 0,
  "command": "tee",
  "device": "65024",
  "inode": 1234567
}
```

> `action=audit` 表示内核记录了这次写但允许它通过（audit 模式）；若策略是 enforce，
> 这里会是 `action=deny` 且 `result=-1`，写操作被内核拒绝。

**TSA 侧（融合评分，必有）：**

```bash
journalctl -u tsa-fusion -n 10 --no-pager
# 期望：出现 Falco rule=... status=scored points=-N runtime=NN 的日志，
#       表明事件已被 TSA 接收并计入风险评分
curl -s http://127.0.0.1:8766/healthz
# 期望：{"status":"ok"}
```

预期输出样例：

```text
$ journalctl -u tsa-fusion -n 10 --no-pager
... INFO ... Watching security event sources: falco=/var/log/falco/falco.json, ...
... WARNING ... Falco rule=Monitor specific file access status=scored points=-5 runtime=95.00

$ curl -s http://127.0.0.1:8766/healthz
{"status":"ok"}
```

> `status=scored points=-5 runtime=95.00` 表示事件被计入风险，运行时分从 100 降到 95；
> 若是 `status=duplicate` / `rate_limited` 则是去重/限速命中（也属正常工作）。

### 6.4 看板端到端确认

浏览器打开 `http://127.0.0.1:8766/`，确认：

- 顶部"组件流水线"中 Falco / BPF LSM / TSA 三项显示 `active`（绿色）；
- "风险评分"区有数值（posture/runtime/final）；
- "最近操作与证据链"出现刚才 `tee` 写 `/etc/tsa-protected-demo` 的事件——
  完整模式为 Falco↔BPF 双侧证据链，降级模式为仅 Falco 侧证据。

### 6.5 一句话成功判据

满足以下全部即运行成功：

- ✅ `falco-modern-bpf` / `tsa-fusion` / `tsa-dashboard` 三服务 `active`；
- ✅ 写 `/etc/tsa-protected-demo` 后：Falco 日志有报警、TSA 日志有 `scored` 评分、看板"证据链"出现该事件；
- ✅（完整模式）`bpf-lsm-controller` `active` 且 `/var/log/bpf-lsm/events.jsonl` 有 `action=audit` 事件；
- ✅（降级模式）BPF 两项可缺省，Falco + TSA + 看板三件成立即算纯检测成功。

实时持续监测、盯日志命令见 [DEPLOYMENT.md](DEPLOYMENT.md) 第 2.2 节。

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

因此实际保护覆盖：**官方规则广域检测 + 1 条自定义文件监控**，加上：

- **完整模式（有 BPF LSM）**：再叠加 BPF LSM 内核级精确决策/阻断；
- **降级模式（无 BPF LSM）**：仅 Falco 纯检测（无内核阻断）。

## 8. 一览检查清单

**必选（检测流水线，对应完整或降级模式）：**
- [ ] `/sys/kernel/btf/vmlinux` 存在（modern eBPF，Falco 强依赖）
- [ ] `falco --version` 可用
- [ ] （可选）`lynis` 已安装
- [ ] `sudo ./deploy-security-stack.sh` 全程无错
- [ ] `falco-modern-bpf`、`tsa-fusion`、`tsa-dashboard` 三项 `active`

**完整模式额外（启用内核级阻断时）：**
- [ ] `/usr/local/go/bin/go version` 输出 1.23.x，依赖已缓存（降级模式无需 Go）
- [ ] `grep CONFIG_BPF_LSM /boot/config-$(uname -r)` 输出 `=y`
- [ ] `grep -w bpf /sys/kernel/security/lsm` 含 `bpf`
- [ ] `bpf-lsm-controller` `active`（inactive 则为降级，非故障，见第 9 节）

## 9. 内核达不到 BPF LSM 时的降级运行

当 1.1 实测确认内核**没有** `CONFIG_BPF_LSM=y`（很多 Ubuntu 及 CentOS 8/Stream 即如此），且不便换内核时，
项目**自动降级为纯检测模式**：失去 BPF LSM 内核级阻断，但保留 Falco 检测 + TSA 评分 + 看板证据链。

降级依据：BPF LSM 是本项目**独立组件**，TSA 只读 Falco 日志即可工作，不依赖 BPF LSM。
Falco 的 modern eBPF 驱动基于 tracepoint/kprobe，**只需要 BTF + CAP_BPF，不需要 BPF LSM**。

### 9.1 自动降级（默认）

`deploy-security-stack.sh` 会在开头探测 `/sys/kernel/security/lsm` 是否含 `bpf`：

- **含 `bpf`** → 完整部署（检测 + 阻断，四个服务全部 active）。
- **不含 `bpf`** → 自动降级：
  - 跳过 Go 编译与 `bpf-lsm-controller` 的安装、启动（**无需安装 Go 工具链**）；
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