# 部署与演示

> 升级前先读 [SECURITY_REVIEW.md](SECURITY_REVIEW.md)。当前仅回环监听，不自动开端口；基线与采集未就绪时评分 API 返回 503。

> 首次部署只需按 [Ubuntu 复现指南](INSTALL.md) 完成安装与验收。本文是已有部署的运行参考，不是另一份必读安装指南。
>
> 适用于已装好前置的 Linux 主机（有 BPF LSM 才能完整运行，否则自动降级为纯检测）。命令以项目根目录为当前路径；使用独立 Go 时须传入绝对路径 `GO_BIN`。

## 1. 部署前确认

```bash
/usr/local/go/bin/go version
/usr/bin/falco --version
grep -w bpf /sys/kernel/security/lsm   # 输出含 bpf = 完整模式；不含 = 降级模式（两者都可部署）
test -f ./tsa/policy_config.yaml
```

要求：

- Falco 已安装，支持 modern eBPF；
- （完整模式才需要）内核启用了 BPF LSM；缺失时脚本自动降级，不阻断部署；
- Go 1.25 工具链和项目依赖已缓存；
- TSA 源码在项目根目录下的 `tsa/`。

部署脚本用 `GOPROXY=off`，root 构建阶段不联网下载依赖。脚本会按 `SUDO_USER`（运行 sudo 的用户）和脚本所在目录自动渲染 systemd unit，不用手改路径。

## 2. 一键部署

```bash
sudo ./deploy-security-stack.sh
```

脚本依次执行：

1. 创建 TSA 维护标记，避免部署行为污染评分；
2. 创建演示文件 `/etc/tsa-protected-demo`（如不存在）；
3. 部署并校验 Falco 规则；
4. 探测内核 BPF LSM：完整模式则跑 Go 测试、编译并校验 BPF 策略、装 BPF 控制器；降级模式跳过 Go 编译；
5. 跑 Python 测试；
6. 启动服务（完整模式四个，降级模式三个——Falco + TSA + 看板）；
7. 删除维护标记。

### 2.1 移植到新主机

部署脚本没有硬编码用户名或绝对路径，移植步骤：

1. 使用仅含英文字符、数字、`/`、`_`、`-`、`.` 的目录（如 `/opt/security-stack`），确保部署用户有读写权限；
2. 确认该部署用户存在、有家目录、能 `sudo`（脚本以 `SUDO_USER` 作为运行态账户和构建账户）；
3. 装前置：Falco（modern eBPF）、Go 1.25、Lynis（可选）；内核 BPF LSM 可选（有则完整，无则自动降级，见 INSTALL）；
4. `cd <仓库目录> && sudo ./deploy-security-stack.sh`。

脚本会以 `SUDO_USER` 和脚本所在目录渲染 `systemd/*.service` 里的 `__RUNTIME_USER__` / `__SRC_DIR__` 占位符，再装到 `/etc/systemd/system/`。渲染后会校验无占位符残留，有残留就中断部署。

### 2.2 运行与实时检测

部署完成后，服务常驻由 systemd 管理。实时检测有三条观察通道：

触发一次检测（默认 audit 模式，不阻断）：

```bash
echo "demo" | sudo tee -a /etc/tsa-protected-demo >/dev/null   # policy.yaml 默认保护该文件
sleep 2
sudo tail -n 3 /var/log/bpf-lsm/events.jsonl | jq   # BPF LSM 审计事件（仅完整模式有此文件）
journalctl -u tsa-fusion -n 10 --no-pager           # TSA 评分日志（两种模式都有）
```

> 降级模式（无 BPF LSM）：`/var/log/bpf-lsm/events.jsonl` 不存在属正常，跳过那条 tail；看 Falco 报警用 `sudo tail -n 5 /var/log/falco/falco.json | jq`，TSA 评分日志照常查看。

实时看板（每 2 秒自动刷新）：

```text
http://127.0.0.1:8766/
```

看板展示流水线状态、保护策略、评分与证据，只读且仅绑定 `127.0.0.1:8766`，不会自动开防火墙。远程通过第 9 节的 SSH 转发或鉴权 TLS 代理访问。评分接口仅在数据就绪时提供分值，否则返回 503。

持续跟随日志（实时）：

```bash
journalctl -u bpf-lsm-controller -u tsa-fusion -u falco-modern-bpf -f   # -f 实时跟随（降级模式去掉 -u bpf-lsm-controller）
tail -f /var/log/bpf-lsm/events.jsonl | jq                              # 仅完整模式存在此文件
tail -f /var/log/falco/falco.json | jq
```

## 3. 验证服务

```bash
# 检测流水线三项（完整与降级模式都应为 active）
systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard

# 完整模式额外：BPF 控制器（降级模式未启动，不能视为完整复现）
systemctl is-active bpf-lsm-controller
systemctl is-enabled bpf-lsm-controller
```

- `falco-modern-bpf`、`tsa-fusion`、`tsa-dashboard` 应为 `active`/`enabled`；
- `bpf-lsm-controller`：完整模式 `active`/`enabled`；降级模式 `inactive`/`disabled`（脚本没装它）。

查看启动日志：

```bash
journalctl -u bpf-lsm-controller -u tsa-fusion -u tsa-dashboard -n 30 --no-pager
```

## 4. 演示一次完整检测

> 本节的"完整证据链"需要完整模式（内核有 BPF LSM）。降级模式下没有 BPF 侧事件，只能验证 Falco 报警 + TSA 评分，可跳过下文带 `bpf-lsm` 字样的步骤。

当前保护对象：

```text
/etc/tsa-protected-demo
```

当前模式：

```text
AUDIT：记录并报警，但不阻止操作
```

执行（文件不存在时部署脚本会自动创建；也可手动 `sudo install -m 0640 /dev/null /etc/tsa-protected-demo`）：

```bash
echo "security-demo" | sudo tee -a /etc/tsa-protected-demo >/dev/null
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
→ BPF LSM 命中 protect_demo_config
→ AUDIT，内核允许操作
→ TSA 接收并计算临时风险
```

## 5. 修改检测规则

项目自定义 Falco 规则位于：

```text
./falco/rules.d/
```

从 `91-custom-rules.yaml` 添加自己的规则；官方规则固定在仓库 `falco/official-rules/`，由 `rules.lock.json` 校验。先校验，再只更新 Falco：

```bash
python3 falco/manage_rules.py check
sudo ./falco/deploy-host-falco.sh
```

规则安装至 `/etc/falco/security-stack/rules/<规则包ID>/`，不是覆盖系统包文件；本机额外规则保留。完整位置说明及可复制示例见 [FALCO_RULES.md](FALCO_RULES.md)。Falco 只负责报警，不承担阻断。

## 6. 修改 BPF LSM 策略

源策略：

```text
./policy.yaml
```

新增保护对象时，每条策略要有唯一 ID、名称、模式和绝对路径：

```yaml
- id: 1002
  name: protect_example
  mode: audit
  paths:
    - /absolute/path
  allowed_uids: []
  expires_after: ""
```

先保持 `audit`，观察正常访问、完善 `allowed_uids`。只有完成回滚测试后，才能逐条改为 `enforce`。

重新部署：

```bash
sudo ./deploy-security-stack.sh
```

## 7. 日志与数据位置

| 内容 | 路径 |
|---|---|
| Falco JSON 事件 | `/var/log/falco/falco.json` |
| BPF LSM JSONL 事件 | `/var/log/bpf-lsm/events.jsonl` |
| TSA SQLite 状态 | `<项目根>/tsa/state/tsa.db` |
| TSA 最新报告 | `<项目根>/tsa/reports/last_scan.json` |
| 已部署 BPF 策略 | `/etc/bpf-lsm/policy.yaml` |

## 8. 常见故障

看板无法访问：

```bash
systemctl status tsa-dashboard --no-pager
curl http://127.0.0.1:8766/healthz
```

BPF 没有事件（仅完整模式适用；降级模式本来就没有 bpf-lsm-controller）：

```bash
systemctl status bpf-lsm-controller --no-pager
sudo stat /etc/tsa-protected-demo
sudo tail -n 20 /var/log/bpf-lsm/events.jsonl
```

Falco 规则错误：

```bash
sudo python3 falco/manage_rules.py check
sudo falco --dry-run
journalctl -u falco-modern-bpf -n 30 --no-pager
```

## 9. 对外接口：查询实时风险分值

看板服务绑定 `127.0.0.1:8766`，提供只读 HTTP 接口与 `{code, status, message, data}` 响应信封。外部系统须经过 SSH 转发或有鉴权的 TLS 代理。

### 9.1 接口规格

| 项 | 值 |
|---|---|
| 协议 | HTTP |
| 方法 | GET |
| 路径 | `/systemManage/risk/score` |
| 端口 | 8766 |
| 本机访问 | `http://127.0.0.1:8766/systemManage/risk/score` |
| 他机访问 | SSH 转发后的本机端口，或已部署的鉴权 TLS 代理 |
| 认证 | 回环接口信任本机用户；远程认证由 SSH 或代理提供 |

### 9.2 验证接口（本机）

```bash
curl -s http://127.0.0.1:8766/systemManage/risk/score | jq
```

预期返回（成功）：

```json
{
  "code": 20000,
  "status": true,
  "message": "操作成功",
  "data": {
    "final": 100.0,
    "posture": 100.0,
    "runtime": 100.0,
    "generated_time": "2026-07-17T04:47:19.988646+00:00"
  }
}
```

- `final`：最终风险分（`posture×0.4 + runtime×0.6`），满分 100，越低越危险。
- `posture`：Lynis 静态基线分。
- `runtime`：运行时分（来自 Falco/BPF 实时事件，随风险过期自动回升）。

状态库未就绪、TSA 心跳过期、采集服务停止、日志不可读或基线不可用时，返回 HTTP 503、`code=50000, status=false, data=null`。上面的满分响应只适用于全部数据就绪且没有有效风险的情况。

### 9.3 验证接口（别的主机访问）

前提：监测机已部署，访问端具有 SSH 登录权限。无需向网络开放 8766。

在另一台主机上执行：

```bash
# 在访问端保持 SSH 转发运行
ssh -N -L 127.0.0.1:8766:127.0.0.1:8766 user@linux-host
# 在访问端另一个终端查询
curl -s http://127.0.0.1:8766/systemManage/risk/score | jq
```

能拿到上面的统一信封分值，就说明他机可访问监测主机的实时分数。

也可在访问端浏览器打开 `http://127.0.0.1:8766/`。

### 9.4 他机访问不通的排查

```bash
# 监测机上应仅监听回环地址
ss -ltnp | grep 8766
# 监测机上检查数据就绪情况
curl -s http://127.0.0.1:8766/api/status
```

本机正常而转发不通时，检查 SSH 连接及访问端端口占用；不应改为公开监听来绕过访问控制。
