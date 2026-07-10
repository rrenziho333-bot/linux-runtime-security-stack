# 部署与演示

本文档针对当前实验主机，所有命令均可直接复制执行。

## 1. 部署前确认

```bash
/usr/local/go/bin/go version
/usr/bin/falco --version
grep -w bpf /sys/kernel/security/lsm
test -f /home/zhaoren/ebpf/tsa/policy_config.yaml
```

要求：

- Falco 已安装，并支持 modern eBPF；
- 内核启用了 BPF LSM；
- Go 1.23.10 工具链及项目依赖已经缓存；
- TSA 源码位于 `/home/zhaoren/ebpf/tsa`。

部署脚本使用 `GOPROXY=off`，不会在 root 构建阶段联网下载依赖。

## 2. 一键部署

```bash
sudo /home/zhaoren/ebpf/deploy-security-stack.sh
```

脚本依次执行：

1. 创建 TSA 维护标记，避免部署行为污染评分；
2. 运行 Go 和 Python 测试；
3. 校验 BPF 策略；
4. 部署并校验 Falco 规则；
5. 安装 BPF 控制器、策略、systemd 和 logrotate 配置；
6. 启动四个服务；
7. 删除维护标记。

## 3. 验证服务

```bash
systemctl is-active \
  falco-modern-bpf \
  bpf-lsm-controller \
  tsa-fusion \
  tsa-dashboard

systemctl is-enabled \
  falco-modern-bpf \
  bpf-lsm-controller \
  tsa-fusion \
  tsa-dashboard
```

四项都应返回 `active` 和 `enabled`。

查看启动日志：

```bash
journalctl -u bpf-lsm-controller -u tsa-fusion -u tsa-dashboard -n 30 --no-pager
```

## 4. 演示一次完整检测

当前保护对象：

```text
/etc/tmp_rzh
```

当前模式：

```text
AUDIT：记录并报警，但不阻止操作
```

执行：

```bash
echo "security-demo" | sudo tee -a /etc/tmp_rzh >/dev/null
sleep 2
```

检查 BPF LSM 证据：

```bash
sudo tail -n 3 /var/log/bpf-lsm/events.jsonl | jq
```

检查 TSA：

```bash
journalctl -u tsa-fusion -n 10 --no-pager
```

打开看板：

```text
http://127.0.0.1:8766/
```

预期证据链：

```text
tee 请求 write
→ Falco 匹配 Write below etc
→ BPF LSM 命中 protect_tmp_rzh
→ AUDIT，内核允许操作
→ TSA 接收并计算临时风险
```

## 5. 修改检测规则

项目自定义 Falco 规则位于：

```text
/home/zhaoren/ebpf/falco/rules.d/
```

修改后执行部署脚本。脚本会加载官方规则、自定义规则和例外进行完整校验，
校验通过后才重启 Falco：

```bash
sudo /home/zhaoren/ebpf/deploy-security-stack.sh
```

Falco 负责报警，不承担阻断。

## 6. 修改 BPF LSM 策略

源策略：

```text
/home/zhaoren/ebpf/policy.yaml
```

新增保护对象时，为每条策略提供唯一 ID、名称、模式和绝对路径：

```yaml
- id: 1002
  name: protect_example
  mode: audit
  paths:
    - /absolute/path
  allowed_uids: []
  expires_after: ""
```

先保持 `audit`，观察正常访问并完善 `allowed_uids`。只有完成回滚测试后，
才能逐条改为 `enforce`。

重新部署：

```bash
sudo /home/zhaoren/ebpf/deploy-security-stack.sh
```

## 7. 日志与数据位置

| 内容 | 路径 |
|---|---|
| Falco JSON 事件 | `/var/log/falco/falco.json` |
| BPF LSM JSONL 事件 | `/var/log/bpf-lsm/events.jsonl` |
| TSA SQLite 状态 | `/home/zhaoren/ebpf/tsa/state/tsa.db` |
| TSA 最新报告 | `/home/zhaoren/ebpf/tsa/reports/last_scan.json` |
| 已部署 BPF 策略 | `/etc/bpf-lsm/policy.yaml` |

## 8. 常见故障

看板无法访问：

```bash
systemctl status tsa-dashboard --no-pager
curl http://127.0.0.1:8766/healthz
```

BPF 没有事件：

```bash
systemctl status bpf-lsm-controller --no-pager
sudo stat /etc/tmp_rzh
sudo tail -n 20 /var/log/bpf-lsm/events.jsonl
```

Falco 规则错误：

```bash
sudo falco -V /etc/falco/falco_rules.yaml \
  -V /etc/falco/falco-sandbox_rules.yaml \
  -V /etc/falco/falco-incubating_rules.yaml \
  -V /etc/falco/rules.d
sudo falco --dry-run
journalctl -u falco-modern-bpf -n 30 --no-pager
```
