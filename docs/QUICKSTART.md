# 快速部署与验证

本指南适用于安全加固后的版本。已部署旧版本时先读 [升级说明](SECURITY_REVIEW.md)。看板仅监听回环地址；没有真实基线输入时不会默认给出安全满分。

## 1. 准备 Linux

在 x86_64 Linux 上按 [INSTALL.md](INSTALL.md) 安装 Falco、Python 3、PyYAML；完整 BPF 模式还需要 `/usr/local/go/bin/go`，版本满足 go.mod（至少 1.25，使用受支持版本的安全补丁）。修改 BPF C 时额外准备 clang、llvm、libbpf 头文件。

```bash
uname -r
ls /sys/kernel/btf/vmlinux
sudo cat /sys/kernel/security/lsm
```

Falco modern eBPF 需要 BTF。LSM 列表包含 `bpf` 才部署内核保护组件，否则运行检测模式。版本号不能代替实际能力检查，第一次完整实验建议使用可恢复的 Linux 虚拟机。

## 2. 获取代码与准备基线

```bash
git clone https://github.com/rrenziho333-bot/linux-runtime-security-stack.git
cd linux-runtime-security-stack
```

完整模式先以随后执行 sudo 的同一普通用户下载 Go 模块：

```bash
/usr/local/go/bin/go mod download
```

安装 Lynis 后，在项目根目录准备基线：

```bash
mkdir -p tsa/reports
sudo lynis audit system --quick --quiet --report-file "$PWD/tsa/reports/lynis-report.dat"
sudo chown "$(id -un):$(id -gn)" tsa/reports/lynis-report.dat
sudo chmod 0640 tsa/reports/lynis-report.dat
```

如果明确只做运行时演示，可以在 `tsa/policy_config.yaml` 将 `baseline_lynis.enabled` 设为 `false`。界面状态会注明基线被禁用；不能将此模式声称为已完成基线审计。

## 3. 部署与检查

```bash
sudo ./deploy-security-stack.sh
systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard
systemctl is-active bpf-lsm-controller
```

前三项应 active；完整模式第四项也 active。检测模式没有 BPF 控制器是正常现象。部署现在通过服务启动参数选择 TSA 的 BPF 输入，不修改源 YAML。

服务启动约五秒后查询：

```bash
curl -s http://127.0.0.1:8766/api/status | jq '.availability, .scores'
curl -s http://127.0.0.1:8766/systemManage/risk/score | jq
```

就绪时接口返回 `code:20000`。基线不可用、服务停止、日志未打开或心跳过期时返回 HTTP 503、`code:50000`、`data:null`，需要按 availability 和 journal 排查。

## 4. 触发一次审计

默认 `policy.yaml` 是 audit。执行：

```bash
echo verify | sudo tee -a /etc/tsa-protected-demo >/dev/null
sleep 3
sudo tail -n 5 /var/log/falco/falco.json
sudo tail -n 5 /var/log/bpf-lsm/events.jsonl
journalctl -u tsa-fusion -n 15 --no-pager
curl -s http://127.0.0.1:8766/systemManage/risk/score | jq
```

检测模式没有 BPF 日志；完整模式应看到演示策略的 audit 事件。Falco 和 BPF 的事件分别计分；重复事件、已有风险和实际启用规则会影响数值，不保证每次固定扣 7 分。浏览器打开 `http://127.0.0.1:8766/` 查看证据。

## 5. 另一台电脑访问

在访问端保持 SSH 转发运行，替换成监测机的账户与地址：

```bash
ssh -N -L 127.0.0.1:8766:127.0.0.1:8766 user@linux-host
```

然后在访问端浏览器打开 `http://127.0.0.1:8766/`，或另一个终端执行同样的 curl。不要开放 8766 端口。多用户系统集成应使用有鉴权的 TLS 代理，详见升级说明。

## 6. 确认规则与阻断边界

自定义规则在 `falco/rules.d/`，部署后复制到 `/etc/falco/rules.d/`。官方规则实际由 Falco 配置加载；仓库 `falco/official-rules/` 的 93 条是阅读快照，不能当作本机已启用数量。

`audit` 不阻断；必须加载 `enforce` 策略才能拒绝操作。第一次只对演示文件测试，同时核对操作失败、BPF deny 事件和看板结果。新增 mmap/mprotect hooks 不会撤销加载策略前已有的共享可写映射，切换模式后应重启相关实验进程。

问题按以下顺序排查：服务状态 -> 原始日志 -> TSA journal -> `/api/status` 的 availability -> 评分 API。`/healthz` 现在也检查数据可用性，不再是无条件成功。
