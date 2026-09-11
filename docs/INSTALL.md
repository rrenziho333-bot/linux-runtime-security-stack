# Ubuntu 复现指南

安装与快速指南已合并。按顺序执行本文件即可，不必再看另一份安装文档。

适用：Ubuntu 22.04 LTS x86_64、systemd、可 sudo 的普通用户；实验虚拟机建议 2 核、4 GB 内存、30 GB 磁盘，先做快照。终端和 APT 都需要能访问软件源、GitHub、Go 下载站与模块代理；受限网络先配置可用代理，只有浏览器能联网还不够。命令报错时先解决，再从失败命令继续，不要跳过校验或重新克隆覆盖已有目录。

本路线已在新建官方 Ubuntu 22.04.5 镜像虚拟机实测，使用 6.8 HWE 内核、Falco 0.44.1、Go 1.26.8，默认完整模式但策略为 **audit（记录、放行）**。验证记录与限制见 [VM_VALIDATION.md 第 8 节](VM_VALIDATION.md#8-干净-ubuntu-从-main-复现)。

## 1. 准备系统与内核

在 Ubuntu 终端执行，不要使用 root 登录后直接部署。本机访问 Ubuntu 主源不稳定，以下使用阿里云 Ubuntu HTTPS 镜像，仍由 Ubuntu 签名验证软件包；保留原源文件备份（仅针对 22.04 的传统源文件）。已有可用源时可跳过前两条命令：

```bash
sudo cp -n /etc/apt/sources.list /etc/apt/sources.list.lrss-backup
sudo sed -i -E 's@https?://([a-z.]*archive|security)\.ubuntu\.com/ubuntu/?@https://mirrors.aliyun.com/ubuntu/@g' /etc/apt/sources.list
sudo apt-get -o APT::Update::Error-Mode=any update
sudo apt-get install -y ca-certificates curl gnupg git python3-yaml jq lynis logrotate linux-generic-hwe-22.04
sudo reboot
```

重新登录后检查内核，并启用 BPF LSM（保留当前启用的其他 LSM）：

```bash
uname -r
test -r /sys/kernel/btf/vmlinux
grep '^CONFIG_BPF_LSM=y' /boot/config-"$(uname -r)"
sudo cat /sys/kernel/security/lsm
```

最后一条含 `bpf` 就跳过下面这个代码块；不含时执行并再次登录：

```bash
LSM="$(sudo cat /sys/kernel/security/lsm)"
printf 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT lsm=%s,bpf"\n' "$LSM" \
  | sudo tee /etc/default/grub.d/99-lrss-bpf.cfg
sudo update-grub
sudo reboot
```

重启后 `sudo grep -w bpf /sys/kernel/security/lsm` 必须成功。若内核配置或 BTF 检查失败，先解决内核问题；无 BPF LSM 的部署会降级为纯检测，不能算完整复现。以上引导步骤仅用于 Ubuntu GRUB。

## 2. 安装 Falco 和 Go

Falco 使用官方签名软件源、modern eBPF；关闭系统规则自动更新，项目使用自己的锁定规则包：

```bash
curl -fL --retry 3 https://falco.org/repo/falcosecurity-packages.asc -o /tmp/falcosecurity.asc
sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg /tmp/falcosecurity.asc
echo 'deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main' \
  | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get -o APT::Update::Error-Mode=any update
sudo env FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf FALCOCTL_ENABLED=no apt-get install -y falco=0.44.1
falco --version
```

Go 安装到用户独立目录，不删除系统原有工具链；解压前必须看到校验 `OK`：

```bash
mkdir -p "$HOME/.local/lib/lrss-go1.26.8"
curl -fL --retry 3 https://go.dev/dl/go1.26.8.linux-amd64.tar.gz -o /tmp/lrss-go1.26.8.tar.gz
echo 'd0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b  /tmp/lrss-go1.26.8.tar.gz' | sha256sum -c -
tar -xzf /tmp/lrss-go1.26.8.tar.gz -C "$HOME/.local/lib/lrss-go1.26.8"
"$HOME/.local/lib/lrss-go1.26.8/go/bin/go" version
```

## 3. 克隆、准备基线并部署

以下命令在同一个终端中按顺序执行。路径不要含空格或中文；已有同名目录时使用新的目录，不要覆盖原项目。

生成基线前确认 `date -u` 时间正确、`timedatectl` 已同步。VMware 时间反复跳动时可用 `sudo vmware-toolbox-cmd timesync disable` 关闭 Tools 周期同步，并用 `sudo timedatectl set-ntp true` 保留系统 NTP；开机/恢复后的时间也要检查，同步完成后再继续。

```bash
git clone https://github.com/rrenziho333-bot/linux-runtime-security-stack.git
cd linux-runtime-security-stack
GO_BIN="$HOME/.local/lib/lrss-go1.26.8/go/bin/go"
"$GO_BIN" mod download
"$GO_BIN" mod verify
mkdir -p tsa/reports
sudo lynis audit system --quick --quiet --report-file "$PWD/tsa/reports/lynis-report.dat"
sudo chown "$(id -un):$(id -gn)" tsa/reports/lynis-report.dat
sudo chmod 0640 tsa/reports/lynis-report.dat
sudo GO_BIN="$GO_BIN" ./deploy-security-stack.sh
```

Go 模块代理直连失败时，只对下载命令指定 `GOPROXY=https://goproxy.cn,direct "$GO_BIN" mod download`，保留默认校验和验证。其他下载超时需先配置可用网络；不要关闭 TLS 或 APT 签名验证。没有完整、新鲜的基线报告时评分为不可用，不会当成 100 分。

## 4. 验收

等待约 10 秒后，在 Ubuntu 内部执行：

```bash
systemctl is-active falco-modern-bpf bpf-lsm-controller tsa-fusion tsa-dashboard
curl --fail http://127.0.0.1:8766/healthz
echo verify | sudo tee -a /etc/tsa-protected-demo >/dev/null
sleep 3
sudo tail -n 10 /var/log/falco/falco.json
sudo tail -n 10 /var/log/bpf-lsm/events.jsonl
curl --fail http://127.0.0.1:8766/systemManage/risk/score
```

**成功判据**：四行 `active`；健康为 `{"status":"ok"}`；Falco 有演示文件告警，BPF 有 `action:audit`；评分接口 HTTP 200 且 `data` 非空。在 Ubuntu 浏览器打开 `http://127.0.0.1:8766/` 看事件；此地址不是 Windows 宿主机的地址。规则名可能是官方 `Write below etc`，不要求一定命中项目规则名。

无桌面的服务器可通过已有、经过认证的 SSH 连接转发：在自己的电脑执行 `ssh -N -L 127.0.0.1:18766:127.0.0.1:8766 用户名@Ubuntu地址`，再访问 `http://127.0.0.1:18766/`；不要为此把看板开放到 `0.0.0.0`。

需要验证阻断时，只将仓库 `policy.yaml` 中演示文件策略的 `mode: audit` 改成 `mode: enforce`，重新部署后再次写入，应得到 `Operation not permitted`，BPF 日志出现 `deny`。完成后改回 `audit` 并重新部署。只操作演示文件，不要拿系统关键文件做阻断实验。

服务失败或接口 503 时先看 `journalctl -u falco-modern-bpf -u bpf-lsm-controller -u tsa-fusion -u tsa-dashboard -n 80 --no-pager`。首次启动可能尚未开始采集，等待后再触发一次写入；服务 active 本身不等于检测成功。

## 5. 规则与日常修改

- 官方规则：`falco/official-rules/`，当前 93 条定义；默认禁用的规则不会被强制启用。
- 添加自定义规则：`falco/rules.d/91-custom-rules.yaml`，将占位 `[]` 替换为规则列表；或在同目录增加 `*.yaml`。
- 生效：`python3 falco/manage_rules.py check`，通过后执行 `sudo ./falco/deploy-host-falco.sh`。
- 实际加载：`/etc/falco/falco.yaml` 指向 `/etc/falco/security-stack/rules/<规则包ID>/`；详细示例见 [FALCO_RULES.md](FALCO_RULES.md)。
- 风险分配置：`tsa/policy_config.yaml`；修改后 `sudo systemctl restart tsa-fusion`。默认总分为 `0.4 * posture + 0.6 * runtime`，分数越低风险越高，不是安全认证。

规则随 main 克隆提供，但依赖、内核能力和基线仍需上述准备。控制器重启存在保护空窗；复现成功不等于生产环境已经完成补丁加固或全面安全验收。

安装来源：[Ubuntu 镜像说明](https://developer.aliyun.com/mirror/ubuntu)、[Falco 官方包安装](https://falco.org/docs/setup/packages/)、[Go 官方下载](https://go.dev/dl/)。
