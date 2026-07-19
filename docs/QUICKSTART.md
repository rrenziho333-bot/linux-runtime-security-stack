# 快速验证（5 步）

从空白 Linux 到"别人 curl 拿到分数"。只敲命令、看输出就行，原理看 [INSTALL.md](INSTALL.md)。

> 发行版：Ubuntu 22.04+ 或 CentOS 8/Stream 9+。CentOS 7 不行（内核太旧）。
> Go 要 1.25（不是 1.23）：项目的 `go.mod` 要求 `go 1.25`，直接装 1.25 最省事，部署时工具链不会再自动下载。

## 1. 装前置（监测机，一次性）

```bash
# 用到的工具：jq（下面查分数用，没有就装）
sudo apt install -y jq            # CentOS: sudo dnf install -y jq

# Falco（Ubuntu；CentOS 见 INSTALL §2）
sudo install -dm755 /etc/apt/keyrings
curl -s https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /etc/apt/keyrings/falco.gpg
echo "deb [signed-by=/etc/apt/keyrings/falco.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falco.list
sudo apt update && sudo apt install -y falco

# Go 1.25（go.dev 国内拉不动的话换镜像，见下方说明）
wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz
ls /sys/kernel/btf/vmlinux    # 必须存在（Falco modern eBPF 强依赖内核 BTF）
```

> `go.dev` 国内直连慢/超时：换阿里云镜像 `https://mirrors.aliyun.com/golang/go1.25.0.linux-amd64.tar.gz`。下完先 `ls -lh` 看大小（约 70MB）再解压。

## 2. 部署（监测机）

```bash
git clone https://github.com/rrenziho333-bot/linux-runtime-security-stack.git ~/linux-runtime-security-stack
cd ~/linux-runtime-security-stack
/usr/local/go/bin/go env -w GOPROXY=https://goproxy.cn,direct   # 国内拉 Go 模块走代理
/usr/local/go/bin/go mod download
sudo ./deploy-security-stack.sh
```

## 3. 看服务（监测机）

```bash
systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard
```
期望三行 `active`。

内核启用了 BPF LSM 时（`grep -w bpf /sys/kernel/security/lsm` 有 `bpf`），还会多一个 `bpf-lsm-controller`：

```bash
systemctl is-active bpf-lsm-controller   # 内核有 BPF LSM 时 active，没有则不装（见 INSTALL §1、§9）
```

## 4. 本机查分数（监测机）

```bash
curl -s http://127.0.0.1:8766/systemManage/risk/score | jq
```
没触发任何事件时，期望满分：
```json
{"code":20000,"status":true,"message":"操作成功","data":{"final":100.0,"posture":100.0,"runtime":100.0,"generated_time":"..."}}
```

触发一次检测会扣分（详见 [INSTALL.md](INSTALL.md) "风险评分怎么算"）：
```bash
echo test | sudo tee -a /etc/tsa-protected-demo >/dev/null   # 写受保护文件
sleep 3
journalctl -u tsa-fusion -n 5 --no-pager                     # 看到 status=scored points=-N runtime=NN
curl -s http://127.0.0.1:8766/systemManage/risk/score | jq   # runtime 从 100 掉下来
```

## 5. 别人查分数（另一台主机）

监测机查 IP：`ip a | grep "inet " | grep -v 127.0.0.1`，取局域网地址（如 192.168.1.50）。

另一台主机：
```bash
curl -s http://192.168.1.50:8766/systemManage/risk/score | jq
```
拿到和第 4 步一样的 JSON，就通了。

## 6. 一眼确认复现成功

部署完跑这一段，四层证据（服务 / 事件 / 分数 / 规则）一次看全。全部符合就是真复现成功。

```bash
echo "===== 服务 ====="
systemctl is-active falco-modern-bpf bpf-lsm-controller tsa-fusion tsa-dashboard
echo "===== 模式 ====="
grep -wq bpf /sys/kernel/security/lsm && echo "完整模式" || echo "降级模式"
echo "===== 触发检测 ====="
echo verify | sudo tee -a /etc/tsa-protected-demo >/dev/null
sleep 3
echo "--- Falco ---"
sudo tail -n 3 /var/log/falco/falco.json | jq -c '{rule, priority}'
echo "--- BPF LSM ---"
sudo tail -n 1 /var/log/bpf-lsm/events.jsonl 2>/dev/null | jq -c '{action, policy_name}' 2>/dev/null || echo "(无 = 降级模式正常)"
echo "--- TSA 评分 ---"
journalctl -u tsa-fusion -n 6 --no-pager | grep scored
echo "===== 分数 ====="
curl -s http://127.0.0.1:8766/systemManage/risk/score | jq '.data'
echo "===== 规则统计 ====="
echo "官方规则数: $(grep -c '^- rule:' /etc/falco/falco_rules.yaml)"
echo "自定义规则文件:"; ls /etc/falco/rules.d/
```

**期望看到什么：**

| 项 | 完整模式 | 降级模式 |
|---|---|---|
| 服务 | 4 行 `active` | `bpf-lsm-controller` 是 `inactive`，其余 3 行 `active` |
| 模式 | "完整模式" | "降级模式" |
| Falco | `{"rule":"Monitor specific file access","priority":"Warning"}` | 同左 |
| BPF LSM | `{"action":"audit","policy_name":"protect_demo_config"}` | "(无 = 降级模式正常)" |
| TSA 评分 | **两条** `scored`：Falco `points=-5` + BPF `points=-2` | **一条** `scored`：Falco `points=-5` |
| 分数 | `runtime` 低于 100（Falco 扣 5 + BPF 扣 2），`final = posture×0.4 + runtime×0.6` | `runtime` 低于 100（扣 5），`final` 同公式 |
| 规则统计 | 官方规则数有值；自定义文件含 `90-local-file-monitoring.yaml`、`95-security-stack-exceptions.yaml` | 同左 |

> "官方规则数"是本机 Falco 版本实际带的规则条数，Falco 0.44.x 主规则文件约 25 条；老版本算上 sandbox/incubating 可达 90+。**有数即可**，具体多少取决于你装的 Falco 版本（见 [INSTALL.md](INSTALL.md) §7）。

浏览器看板 `http://127.0.0.1:8766/`：流水线区 Falco/TSA 绿色 active、风险评分区有数值、证据链区出现刚才 `tee` 写 `/etc/tsa-protected-demo` 的事件——也齐了。

任一层不对，对照 [INSTALL.md](INSTALL.md) §6 的四步验证排。

## 不通？

- 别人访问不通：云主机要去云控制台安全组放行 8766；本机 `ss -ltnp | grep 8766` 应见 `0.0.0.0:8766`。
- 返回 `code:50000`：`systemctl status tsa-fusion` 看 active 没有。
- `bpf-lsm-controller` 反复 `activating` 不 `active`：看 `journalctl -u bpf-lsm-controller -n 10`，如果是 `load BTF for kmod ... string table is empty`，确认 Go 是 1.25 且 `go.mod` 用的是 `cilium/ebpf v0.22.0`（已修）；还报错回 INSTALL §3 的 Go 版本说明。
- 部署失败：多半是前置没装好，回 INSTALL §1–§3。