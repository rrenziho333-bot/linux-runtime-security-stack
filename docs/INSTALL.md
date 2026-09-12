# Ubuntu 复现指南

适用：Ubuntu 22.04 LTS x86_64、systemd、可 sudo 的普通用户；实验虚拟机建议 2 核、4 GB 内存、30 GB 磁盘，先做快照。终端和 APT 都需要能访问软件源、GitHub、Go 下载站与模块代理；受限网络先配置可用代理，只有浏览器能联网还不够。命令报错时先解决，再从失败命令继续，不要跳过校验或重新克隆覆盖已有目录。

已在干净 Ubuntu 22.04.5 虚拟机实测：6.8 HWE 内核、Falco 0.44.1、Go 1.26.8。默认 **audit（记录、放行）**；**enforce（拒绝操作）也已验证**，切换方法见第 4 节。

## 1. 准备系统与内核

在 Ubuntu 终端用普通用户操作，**先执行 1.6～1.9 检查**。1.7 显示 `BTF OK`、1.8 显示 `CONFIG_BPF_LSM=y`，即内核检查通过。

| 检查结果 | 接下来做什么 |
|---|---|
| 内核通过，1.9 含 `bpf` | 不改内核，跳到 1.14 |
| 内核通过，1.9 不含 `bpf` | 执行 1.10～1.14，启用 BPF LSM |
| 内核未通过 | 执行 1.3、1.4B、1.5，重启后重新检查 |

**依赖另行确认**：内核通过但依赖未装齐或不确定时，先执行 1.3、1.4A；都已齐全才可跳过 1.1～1.5。原软件源可用时，无需执行 1.1、1.2。

**命令 1.1（可选）：备份软件源。**
```bash
sudo cp -n /etc/apt/sources.list /etc/apt/sources.list.lrss-backup
```

**命令 1.2（可选）：切换镜像源。**
```bash
sudo sed -i -E 's@https?://([a-z.]*archive|security)\.ubuntu\.com/ubuntu/?@https://mirrors.aliyun.com/ubuntu/@g' /etc/apt/sources.list
```

**命令 1.3：更新软件包索引。**
```bash
sudo apt-get -o APT::Update::Error-Mode=any update
```

**命令 1.4A（与 1.4B 二选一）：内核检查通过时，仅安装软件依赖。**
```bash
sudo apt-get install -y ca-certificates curl gnupg git python3-yaml jq lynis logrotate
```

**命令 1.4B（与 1.4A 二选一）：内核检查未通过时，安装依赖与 HWE 内核。**
```bash
sudo apt-get install -y ca-certificates curl gnupg git python3-yaml jq lynis logrotate linux-generic-hwe-22.04
```

**命令 1.5（安装内核后执行）：重启；重新登录后再执行 1.6。**
```bash
sudo reboot
```

以下检查可在安装前执行；若安装了内核，则重启后重新执行。先确认内核能力，再决定是否启用 BPF LSM（保留当前启用的其他 LSM）：

**命令 1.6：查看当前内核。**
```bash
uname -r
```

**命令 1.7：检查 BTF；必须输出 `BTF OK`。**
```bash
test -r /sys/kernel/btf/vmlinux && echo "BTF OK" || echo "BTF MISSING"
```

**命令 1.8：必须输出 `CONFIG_BPF_LSM=y`。**
```bash
grep '^CONFIG_BPF_LSM=y' /boot/config-"$(uname -r)"
```

**命令 1.9：查看已启用的安全模块。**
```bash
sudo cat /sys/kernel/security/lsm
```

如果 1.7 或 1.8 检查失败，先解决内核问题，不要继续。1.9 输出含 `bpf` 时，跳过 1.10 至 1.13，直接执行 1.14；不含时，在同一个终端依次执行 1.10 至 1.13。以下引导修改仅用于 Ubuntu GRUB。

**命令 1.10（条件执行）：保存当前安全模块列表。**
```bash
LSM="$(sudo cat /sys/kernel/security/lsm)"
```

**命令 1.11（多行，共 2 行，条件执行）：写入启用 BPF LSM 的启动配置。**
```bash
printf 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=%s,bpf"\n' "$LSM" \
  | sudo tee /etc/default/grub.d/99-lrss-bpf.cfg
```

**命令 1.12（条件执行）：更新 GRUB 配置。**
```bash
sudo update-grub
```

**命令 1.13（条件执行）：重启；重新登录后再执行 1.14。**
```bash
sudo reboot
```

**命令 1.14：必须输出包含 `bpf` 的模块列表。**
```bash
sudo grep -w bpf /sys/kernel/security/lsm
```

无 BPF LSM 的部署会降级为纯检测，不能算完整复现。

## 2. 安装 Falco 和 Go

Falco 使用官方签名软件源、modern eBPF；关闭系统规则自动更新，项目使用自己的锁定规则包：

**命令 2.1：下载 Falco 软件源公钥。**
```bash
curl -fL --retry 3 https://falco.org/repo/falcosecurity-packages.asc -o /tmp/falcosecurity.asc
```

**命令 2.2：安装软件源公钥。**
```bash
sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg /tmp/falcosecurity.asc
```

**命令 2.3（多行，共 2 行）：添加 Falco 软件源。**
```bash
echo 'deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main' \
  | sudo tee /etc/apt/sources.list.d/falcosecurity.list
```

**命令 2.4：更新软件包索引。**
```bash
sudo apt-get -o APT::Update::Error-Mode=any update
```

**命令 2.5：安装指定版本的 Falco。**
```bash
sudo env FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf FALCOCTL_ENABLED=no apt-get install -y falco=0.44.1
```

**命令 2.6：确认 Falco 版本。**
```bash
falco --version
```

Go 安装到用户独立目录，不删除系统原有工具链；解压前必须看到校验 `OK`：

**命令 2.7：创建 Go 安装目录。**
```bash
mkdir -p "$HOME/.local/lib/lrss-go1.26.8"
```

**命令 2.8：下载 Go。**
```bash
curl -fL --retry 3 https://go.dev/dl/go1.26.8.linux-amd64.tar.gz -o /tmp/lrss-go1.26.8.tar.gz
```

**命令 2.9：校验下载文件；必须看到 `OK` 才能继续。**
```bash
echo 'd0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b  /tmp/lrss-go1.26.8.tar.gz' | sha256sum -c -
```

**命令 2.10：解压 Go。**
```bash
tar -xzf /tmp/lrss-go1.26.8.tar.gz -C "$HOME/.local/lib/lrss-go1.26.8"
```

**命令 2.11：确认 Go 版本。**
```bash
"$HOME/.local/lib/lrss-go1.26.8/go/bin/go" version
```

## 3. 克隆、准备基线并部署

以下命令在同一个终端中按顺序执行。路径不要含空格或中文；已有同名目录时使用新的目录，不要覆盖原项目。

**命令 3.1：查看 UTC 时间，确认日期和时间正确。**
```bash
date -u
```

**命令 3.2：确认系统时间已同步。**
```bash
timedatectl
```

VMware 时间反复跳动时才执行 3.3、3.4，然后重新执行 3.1、3.2；开机/恢复后也要检查。时间正确且同步完成后才能继续生成基线。

**命令 3.3（可选）：关闭 VMware Tools 周期时间同步。**
```bash
sudo vmware-toolbox-cmd timesync disable
```

**命令 3.4（可选）：启用系统 NTP 时间同步。**
```bash
sudo timedatectl set-ntp true
```

**命令 3.5：克隆项目。**
```bash
git clone https://github.com/rrenziho333-bot/linux-runtime-security-stack.git
```

**命令 3.6：进入项目目录；后续项目命令均在这里执行。**
```bash
cd linux-runtime-security-stack
```

**命令 3.7：设置当前终端使用的 Go 路径。**
```bash
GO_BIN="$HOME/.local/lib/lrss-go1.26.8/go/bin/go"
```

**命令 3.8：下载 Go 模块。**
```bash
"$GO_BIN" mod download
```

**命令 3.9（可选）：仅在 3.8 因模块代理直连失败时，用此命令重试下载。**
```bash
GOPROXY=https://goproxy.cn,direct "$GO_BIN" mod download
```

保留默认校验和验证。其他下载超时需先配置可用网络；不要关闭 TLS 或 APT 签名验证。下载成功后继续：

**命令 3.10：验证 Go 模块。**
```bash
"$GO_BIN" mod verify
```

**命令 3.11：创建基线报告目录。**
```bash
mkdir -p tsa/reports
```

**命令 3.12：运行 Lynis，生成系统安全基线。**
```bash
sudo lynis audit system --quick --quiet --report-file "$PWD/tsa/reports/lynis-report.dat"
```

**命令 3.13：设置报告所属用户。**
```bash
sudo chown "$(id -un):$(id -gn)" tsa/reports/lynis-report.dat
```

**命令 3.14：设置报告读取权限。**
```bash
sudo chmod 0640 tsa/reports/lynis-report.dat
```

**命令 3.15：部署项目。**
```bash
sudo GO_BIN="$GO_BIN" ./deploy-security-stack.sh
```

没有完整、新鲜的基线报告时评分为不可用，不会当成 100 分。

## 4. 验收

等待约 10 秒后，在 Ubuntu 内部执行：

**命令 4.1：检查四个服务。**
```bash
systemctl is-active falco-modern-bpf bpf-lsm-controller tsa-fusion tsa-dashboard
```

**命令 4.2：检查健康接口。**
```bash
curl --fail http://127.0.0.1:8766/healthz
```

**命令 4.3：写入演示文件，触发事件。**
```bash
echo verify | sudo tee -a /etc/tsa-protected-demo >/dev/null
```

**命令 4.4：等待事件处理。**
```bash
sleep 3
```

**命令 4.5：查看 Falco 告警。**
```bash
sudo tail -n 10 /var/log/falco/falco.json
```

**命令 4.6：查看 BPF 事件。**
```bash
sudo tail -n 10 /var/log/bpf-lsm/events.jsonl
```

**命令 4.7：读取风险评分。**
```bash
curl --fail http://127.0.0.1:8766/systemManage/risk/score
```

**成功判据**：四行 `active`；健康为 `{"status":"ok"}`；Falco 有演示文件告警，BPF 有 `action:audit`；评分接口 HTTP 200 且 `data` 非空。在 Ubuntu 浏览器打开 `http://127.0.0.1:8766/` 看事件；此地址不是 Windows 宿主机的地址。规则名可能是官方 `Write below etc`，不要求一定命中项目规则名。

**命令 4.8（可选，在自己的电脑执行）：通过已有、经过认证的 SSH 连接转发看板。**

先替换命令中的用户名和 Ubuntu 地址；连接期间保留此终端，再在自己的电脑浏览器访问 `http://127.0.0.1:18766/`。不要为此把看板开放到 `0.0.0.0`。
```bash
ssh -N -L 127.0.0.1:18766:127.0.0.1:8766 用户名@Ubuntu地址
```

**阻断验收（可选，已实测）**：在 Ubuntu 的项目目录中，仅将 `policy.yaml` 中 `id: 1001` 的 `mode` 改成 `enforce`，再执行 4.9。只测试演示文件，不要直接对系统关键文件启用阻断。

**命令 4.9（可选）：重新部署修改后的策略。**
```bash
sudo GO_BIN="$HOME/.local/lib/lrss-go1.26.8/go/bin/go" ./deploy-security-stack.sh
```

等待约 10 秒，再运行命令 4.3。预期写入失败（`Operation not permitted` / `EPERM`），命令 4.6 的 BPF 日志有 `action:deny`、`result:-1`，看板显示“已拦截”。**完成后将 `mode` 改回 `audit`，再次执行 4.9，恢复默认模式。**

**命令 4.10（可选）：服务失败或接口 503 时查看日志。**
```bash
journalctl -u falco-modern-bpf -u bpf-lsm-controller -u tsa-fusion -u tsa-dashboard -n 80 --no-pager
```

首次启动可能尚未开始采集，等待后再触发一次写入；服务 active 本身不等于检测成功。

## 5. 规则与日常修改

- 官方规则：`falco/official-rules/`，当前 93 条定义；默认禁用的规则不会被强制启用。
- 添加自定义规则：`falco/rules.d/91-custom-rules.yaml`，将占位 `[]` 替换为规则列表；或在同目录增加 `*.yaml`。修改后执行 5.1、5.2。
- 实际加载：`/etc/falco/falco.yaml` 指向 `/etc/falco/security-stack/rules/<规则包ID>/`；详细示例见 [FALCO_RULES.md](FALCO_RULES.md)。
- 风险分配置：`tsa/policy_config.yaml`；修改后执行 5.3。默认总分为 `0.4 * posture + 0.6 * runtime`，分数越低风险越高，不是安全认证。
- 日志与数据：Falco `/var/log/falco/falco.json`，BPF `/var/log/bpf-lsm/events.jsonl`，SQLite `tsa/state/tsa.db`，最新评分报告 `tsa/reports/last_scan.json`。
- Lynis 基线默认一天后过期；重新执行命令 3.12 至 3.14，再执行 5.3。TSA 默认只读取报告，不会自动执行 Lynis。

以下为日常维护命令，不是首次安装的必做步骤；在 Ubuntu 的项目目录中执行。

**命令 5.1（可选）：校验修改后的规则；通过后才能执行 5.2。**
```bash
python3 falco/manage_rules.py check
```

**命令 5.2（可选）：部署规则。**
```bash
sudo ./falco/deploy-host-falco.sh
```

**命令 5.3（可选）：重启评分服务，读取更新后的配置或基线。**
```bash
sudo systemctl restart tsa-fusion
```

规则随 main 克隆提供，但依赖、内核能力和基线仍需上述准备。控制器重启存在保护空窗；复现成功不等于生产环境已经完成补丁加固或全面安全验收。

安装来源：[Ubuntu 镜像说明](https://developer.aliyun.com/mirror/ubuntu)、[Falco 官方包安装](https://falco.org/docs/setup/packages/)、[Go 官方下载](https://go.dev/dl/)。
