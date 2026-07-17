# 部署与演示

本文档适用于任意已装好 Falco 与 Go 的 Linux 主机（内核是否有 BPF LSM 均可：
有则完整运行，无则自动降级为纯检测，见下文及 INSTALL 第 9 节）。命令以项目根目录为当前路径。

## 1. 部署前确认

```bash
/usr/local/go/bin/go version
/usr/bin/falco --version
grep -w bpf /sys/kernel/security/lsm   # 输出含 bpf = 完整模式；不含 = 降级模式（两者都可部署）
test -f ./tsa/policy_config.yaml
```

要求：

- Falco 已安装，并支持 modern eBPF；
- （完整模式才需要）内核启用了 BPF LSM；缺失时脚本自动降级，不阻断部署；
- Go 1.23.10 工具链及项目依赖已经缓存；
- TSA 源码位于项目根目录下的 `tsa/`。

部署脚本使用 `GOPROXY=off`，不会在 root 构建阶段联网下载依赖。
脚本会自动按 `SUDO_USER`（运行 sudo 的用户）和脚本所在目录渲染 systemd unit，
无需手改任何路径。

## 2. 一键部署

```bash
sudo ./deploy-security-stack.sh
```

脚本依次执行：

1. 创建 TSA 维护标记，避免部署行为污染评分；
2. 运行 Go 和 Python 测试；
3. 校验 BPF 策略；
4. 部署并校验 Falco 规则；
5. 探测内核 BPF LSM：有则安装 BPF 控制器、策略、systemd 和 logrotate 配置；无则跳过；
6. 启动服务（完整模式四个，降级模式三个——Falco + TSA + 看板）；
7. 删除维护标记。

### 2.1 移植到新主机

部署脚本不含任何硬编码用户名或绝对路径，移植步骤：

1. 把仓库放在任意目录（如 `/opt/security-stack`），确保部署用户对其有读写权限；
2. 确认该部署用户存在、有家目录、能 `sudo`（脚本以 `SUDO_USER` 作为运行态账户与构建账户）；
3. 安装前置：Falco（modern eBPF）、Go 1.23、Lynis（可选）；内核 BPF LSM 可选（有则完整，无则自动降级，见 INSTALL）；
4. `cd <仓库目录> && sudo ./deploy-security-stack.sh`。

脚本会以 `SUDO_USER` 和脚本所在目录渲染 `systemd/*.service` 中的
`__RUNTIME_USER__` / `__SRC_DIR__` 占位符，再装到 `/etc/systemd/system/`。
渲染后会校验无占位符残留，残留则中断部署。

### 2.2 运行与实时检测

部署完成后，服务常驻由 systemd 管理。实时检测有三条观察通道：

**触发一次检测（默认 audit 模式，不阻断）：**

```bash
echo "demo" | sudo tee -a /etc/tsa-protected-demo >/dev/null   # policy.yaml 默认保护该文件
sleep 2
sudo tail -n 3 /var/log/bpf-lsm/events.jsonl | jq   # BPF LSM 审计事件
journalctl -u tsa-fusion -n 10 --no-pager           # TSA 评分日志
```

**实时看板（每 2 秒自动刷新）：**

```text
http://127.0.0.1:8766/
```

看板展示流水线状态、BPF 策略、风险评分与 Falco/BPF 证据链，只读。
服务绑定 `0.0.0.0:8766`，**可被别的主机访问**（本机用 `http://127.0.0.1:8766/`，
别的主机用 `http://<监测机IP>:8766/`）；需在监测机防火墙放行 8766 端口。
公开接口 `GET /systemManage/risk/score` 供外部系统程序化查询实时风险分值（统一响应信封）。

**持续跟随日志（实时）：**

```bash
journalctl -u bpf-lsm-controller -u tsa-fusion -u falco-modern-bpf -f   # -f 实时跟随（降级模式去掉 -u bpf-lsm-controller）
tail -f /var/log/bpf-lsm/events.jsonl | jq                              # 仅完整模式存在此文件
tail -f /var/log/falco/falco.json | jq
```

## 3. 验证服务

```bash
# 检测流水线三项（完整与降级模式都应为 active）
systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard

# 完整模式额外：BPF 控制器（降级模式此为 inactive/disabled，属正常，见 INSTALL 第 9 节）
systemctl is-active bpf-lsm-controller
systemctl is-enabled bpf-lsm-controller
```

- `falco-modern-bpf`、`tsa-fusion`、`tsa-dashboard` 应为 `active`/`enabled`；
- `bpf-lsm-controller`：完整模式 `active`/`enabled`；降级模式 `inactive`/`disabled`（脚本未安装它）。

查看启动日志：

```bash
journalctl -u bpf-lsm-controller -u tsa-fusion -u tsa-dashboard -n 30 --no-pager
```

## 4. 演示一次完整检测

> 本节的“完整证据链”需**完整模式**（内核有 BPF LSM）。降级模式下没有 BPF 侧事件，
> 只能验证 Falco 报警 + TSA 评分，可跳过下文带 `bpf-lsm` 字样的步骤。

当前保护对象：

```text
/etc/tsa-protected-demo
```

当前模式：

```text
AUDIT：记录并报警，但不阻止操作
```

执行（若文件不存在，部署脚本会自动创建；也可手动 `sudo install -m 0640 /dev/null /etc/tsa-protected-demo`）：

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

修改后执行部署脚本。脚本会加载官方规则、自定义规则和例外进行完整校验，
校验通过后才重启 Falco：

```bash
sudo ./deploy-security-stack.sh
```

Falco 负责报警，不承担阻断。

## 6. 修改 BPF LSM 策略

源策略：

```text
./policy.yaml
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
sudo falco -V /etc/falco/falco_rules.yaml \
  -V /etc/falco/falco-sandbox_rules.yaml \
  -V /etc/falco/falco-incubating_rules.yaml \
  -V /etc/falco/rules.d
sudo falco --dry-run
journalctl -u falco-modern-bpf -n 30 --no-pager
```

## 9. 对外接口：查询实时风险分值

看板服务（`tsa-dashboard`，绑 `0.0.0.0:8766`）对外暴露一个只读 HTTP 接口，
遵循《零信任管理系统接口文档》地面系统 HTTP 接口规范的统一响应信封
`{code, status, message, data}`。外部系统（如零信任管理系统）可用它程序化查询
监测主机的实时风险分值。

### 9.1 接口规格

| 项 | 值 |
|---|---|
| 协议 | HTTP |
| 方法 | GET |
| 路径 | `/systemManage/risk/score` |
| 端口 | 8766 |
| 本机访问 | `http://127.0.0.1:8766/systemManage/risk/score` |
| 他机访问 | `http://<监测机IP>:8766/systemManage/risk/score` |
| 认证 | 暂无（内网/可信环境；对外暴露建议后续加 token） |

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

失败时返回 `code=50000, status=false`（如 TSA 状态库未就绪），属信封规范内的错误响应。

### 9.3 验证接口（别的主机访问）

前提：监测机已部署、防火墙已放行 8766（部署脚本自动放行；云主机还需在云控制台安全组放行）。

在**另一台主机**上执行：

```bash
# 把 <监测机IP> 换成监测主机的实际 IP
curl -s http://<监测机IP>:8766/systemManage/risk/score | jq
```

能拿到上面的统一信封分值，即说明他机可访问监测主机的实时分数。

也可用浏览器打开 `http://<监测机IP>:8766/` 看网页看板。

### 9.4 他机访问不通的排查

```bash
# 监测机上确认服务在监听 0.0.0.0:8766
ss -ltnp | grep 8766          # 应见 0.0.0.0:8766 或 *:8766
# 监测机上确认防火墙已放行（CentOS）
sudo firewall-cmd --list-ports | grep 8766
# 监测机上确认防火墙已放行（Ubuntu）
sudo ufw status | grep 8766
```

若都正常仍不通：监测机若是云主机，检查云平台**安全组**是否放行 8766 入站（系统防火墙之外的层）。
