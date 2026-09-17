# Ubuntu 复现指南

适用 Ubuntu 22.04 x86_64、systemd、可 sudo 的普通用户。建议虚拟机 2 核、4 GB 内存，操作前做快照。
本项目只做 **Lynis 基线检测 + Falco 告警 + TSA 评分**，不阻断、不终止进程；无需安装 Go 或启用 BPF LSM。

2026-09-17 已在 iie-os 的 Ubuntu 22.04、6.8 内核、Falco 0.44.1 上验证旧版迁移、62 项回归测试及真实告警入库。这是已有虚拟机上的部署验证，不是本轮新装裸机或全部规则攻击实测。

## 1. 准备依赖

**命令 1.1：更新软件包索引。**
```bash
sudo apt-get -o APT::Update::Error-Mode=any update
```

**命令 1.2：安装依赖。**
```bash
sudo apt-get install -y ca-certificates curl gnupg git python3-yaml jq lynis logrotate
```

**命令 1.3：检查 Falco 采集所需的 BTF，预期输出 BTF OK。**
```bash
test -r /sys/kernel/btf/vmlinux && echo "BTF OK" || echo "BTF MISSING"
```

Ubuntu 22.04 通常已有可用内核。BTF 缺失或 Falco 提示内核不支持时，安装 `linux-generic-hwe-22.04` 并重启后重试；**不修改 GRUB 的 LSM 配置**。

APT 出现 403 时先修复对应软件源；第三方源握手失败应修复网络或临时禁用该源，不要关闭签名或 TLS 验证。

## 2. 安装 Falco

已安装 Falco 0.44.1 时可跳过本节。以下使用[官方签名软件源](https://falco.org/docs/setup/packages/)与 modern eBPF 驱动。

**命令 2.1：下载公钥。**
```bash
curl -fL --retry 3 https://falco.org/repo/falcosecurity-packages.asc -o /tmp/falcosecurity.asc
```

**命令 2.2：安装公钥。**
```bash
sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg /tmp/falcosecurity.asc
```

**命令 2.3：添加软件源。**
```bash
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main' | sudo tee /etc/apt/sources.list.d/falcosecurity.list
```

**命令 2.4：更新索引。**
```bash
sudo apt-get -o APT::Update::Error-Mode=any update
```

**命令 2.5：安装 Falco。**
```bash
sudo env FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf FALCOCTL_ENABLED=no apt-get install -y falco=0.44.1
```

若指定版本不可用，先查明软件源及可用版本，不要跳过版本兼容验证。Falco 使用 eBPF 采集系统调用，这不是被移除的 BPF LSM 阻断组件。

## 3. 克隆、生成基线并部署

**命令 3.1：克隆。已有本仓库时使用第 5 节更新，不覆盖原目录。**
```bash
git clone https://github.com/rrenziho333-bot/linux-runtime-security-stack.git
```

**命令 3.2：进入项目；后续命令在此目录运行。**
```bash
cd linux-runtime-security-stack
```

**命令 3.3：确认日期和时间正确，否则先校时。**
```bash
timedatectl
```

**命令 3.4：创建报告目录。**
```bash
mkdir -p tsa/reports
```

**命令 3.5：生成真实基线报告；等待命令返回。**
```bash
sudo lynis audit system --quick --quiet --report-file "$PWD/tsa/reports/lynis-report.dat"
```

`--quiet` 会减少终端输出；`long execution` 表示某项检查耗时较长，不等于审计失败。

**命令 3.6：确认报告完成，应包含 finish=true。**
```bash
sudo grep -E '^(report_version_major|finish|hardening_index)=' tsa/reports/lynis-report.dat
```

**命令 3.7：允许当前用户的 TSA 服务读取报告。**
```bash
sudo chown "$(id -un):$(id -gn)" tsa/reports/lynis-report.dat
```

**命令 3.8：限制报告权限。**
```bash
sudo chmod 0640 tsa/reports/lynis-report.dat
```

**命令 3.9：部署。**
```bash
sudo ./deploy-security-stack.sh
```

部署会运行测试、安装仓库规则并启动服务。Lynis 不是常驻服务，TSA 默认只读报告；报告一天后过期，重新执行 3.5～3.8 并重启 TSA。

## 4. 验收

部署返回后等待约 10 秒，在同一个终端继续即可。

**命令 4.1：三个服务均应输出 active。**
```bash
systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard
```

**命令 4.2：健康接口应返回 {"status":"ok"}。**
```bash
curl --fail --noproxy '*' http://127.0.0.1:8766/healthz
```

**命令 4.3：真实触发一次文件写入告警。**
```bash
python3 tsa/verify_runtime.py
```

脚本仅向已有 `/etc/tsa-protected-demo` 追加一行测试编号，核对写入成功以及同 PID、同路径的 Falco 写入证据。预期 `PASS`，并给出本次事件链接。文件名沿用历史名称，现在没有保护或拒绝含义；匹配规则可能是 `Write below etc`。

**命令 4.4：读取评分，预期 HTTP 200、data 非空。**
```bash
curl --fail --noproxy '*' http://127.0.0.1:8766/systemManage/risk/score
```

在 **Ubuntu 浏览器**打开 `http://127.0.0.1:8766/`。Windows 访问需通过已有 SSH 连接转发，勿直接开放看板端口。

**命令 4.5（排障）：查看日志。**
```bash
journalctl -u falco-modern-bpf -u tsa-fusion -u tsa-dashboard -n 80 --no-pager
```

服务 active 不是完整验收；还要看到本次 Falco 告警入库与有效评分。此测试不代表所有规则逐条攻击验证。

## 5. 更新与配置

在原 Ubuntu 项目目录内：

**命令 5.1：更新源码。**
```bash
git pull --ff-only
```

**命令 5.2：重新部署，不是只刷新网页。**
```bash
sudo ./deploy-security-stack.sh
```

从旧版升级会备份并停用、移除原 BPF LSM 控制器；备份在 `/var/backups/lrss-legacy-*`。历史日志和数据库保留，但旧 BPF 事件不再计分或出现在当前看板。旧 GRUB 配置不自动修改，避免影响其他安全模块。

| 修改内容 | 文件 / 操作 |
|---|---|
| Falco 自定义规则 | `falco/rules.d/91-custom-rules.yaml`，见 [规则指南](FALCO_RULES.md) |
| 基线扣分、告警扣分、权重 | `tsa/policy_config.yaml`，修改后 `sudo systemctl restart tsa-fusion tsa-dashboard` |
| Lynis 检查内容 | 系统安装的 Lynis 测试与 profile；TSA 的 `include_controls` 只筛选计分项，不改变 Lynis 检查 |
| 告警、数据库、评分报告 | `/var/log/falco/falco.json`、`tsa/state/tsa.db`、`tsa/reports/last_scan.json` |

默认综合分 = 基线分 × 40% + 运行时分 × 60%，分数越低风险越高。基线分按选定 Lynis 检查项扣分，**不是原始 hardening_index**；运行时按未过期 Falco 事件扣分，支持去重、限额和每规则封顶。同类汇总不删除证据，历史扣分之和不等于当前分数变化。缺少有效基线或采集异常时评分不可用，不以 100 分替代。
