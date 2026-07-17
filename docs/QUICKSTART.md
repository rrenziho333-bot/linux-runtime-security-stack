# 新手一键验证清单

从一台空白 Linux 到"**别人 curl 拿到这台机器的风险分数**"，5 步。每步附期望输出，照着对答案。

> 这是最短路径。详细原理、降级说明、排障见 [INSTALL.md](INSTALL.md) 与 [DEPLOYMENT.md](DEPLOYMENT.md)。
> 支持发行版：Ubuntu/Debian、CentOS 8/Stream 9+。

## 第 1 步：装前置（监测机上，一次性）

```bash
# Falco（以 Ubuntu 为例；CentOS 用 dnf + rpm 源，见 INSTALL §2）
sudo mkdir -p /etc/apt/keyrings
curl -s https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /etc/apt/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update && sudo apt-get install -y falco

# Go 1.23（仅完整模式需要；不确定就先装上）
wget -q https://go.dev/dl/go1.23.10.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.10.linux-amd64.tar.gz
/usr/local/go/bin/go version    # 应输出 go1.23.x
```

> 内核需有 BTF：`ls /sys/kernel/btf/vmlinux` 存在即可（多数发行版默认有）。BPF LSM 可选——有则带阻断，无则自动降级为纯检测。

## 第 2 步：clone + 拉依赖 + 部署（监测机上）

```bash
git clone https://github.com/rrenziho333-bot/linux-runtime-security-stack.git ~/lrss
cd ~/lrss
/usr/local/go/bin/go mod download     # 拉一次 Go 依赖（需有网）；降级模式可跳过
sudo ./deploy-security-stack.sh       # 一键部署：探测内核、起服务、放行 8766
```

部署结尾会打印 `Dashboard: http://...8766/` 与 `Risk score API: ...`，即成功。
（降级模式会打印 `DETECTION-ONLY mode`，正常。）

## 第 3 步：确认服务在跑（监测机上）

```bash
systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard
# 期望三行 active（完整模式再加 bpf-lsm-controller 即四行 active）
```

## 第 4 步：本机自己查分数（监测机上）

```bash
curl -s http://127.0.0.1:8766/systemManage/risk/score | jq
```

期望：

```json
{
  "code": 20000,
  "status": true,
  "message": "操作成功",
  "data": { "final": 100.0, "posture": 100.0, "runtime": 100.0, "generated_time": "..." }
}
```

`final` 就是监测机当前风险分（满分 100，越低越危险）。能返回这个，部署就成功了。

## 第 5 步：别人访问端口拿分数（在另一台主机上）

先在监测机上查 IP：

```bash
ip a | grep "inet " | grep -v 127.0.0.1     # 取局域网地址，假设是 192.168.1.50
```

然后在**另一台主机**上：

```bash
curl -s http://192.168.1.50:8766/systemManage/risk/score | jq
```

拿到和第 4 步一样的分值 JSON，**就实现了"别人访问端口获得该机器的分数"**。

## 拿不到分数？

- **别人访问不通**：监测机若是云主机，去云控制台**安全组**放行 8766 入站（系统防火墙脚本已放，安全组是另一层）；监测机上 `ss -ltnp | grep 8766` 确认在监听 `0.0.0.0:8766`。
- **本机 curl 返回 50000**：TSA 状态库未就绪，`systemctl status tsa-fusion` 看是否 active。
- **部署失败**：通常前置没装好——回 INSTALL §1-§3 检查 Falco/Go/BTF。
- 更多排障见 [DEPLOYMENT.md](DEPLOYMENT.md) §8。

## 一次端到端 demo

```bash
# 监测机上触发一次检测（写受保护文件）
echo "demo" | sudo tee -a /etc/tsa-protected-demo >/dev/null; sleep 2
# 分数会从 100 下降（临时风险扣分），随后随风险过期回升
watch -n2 'curl -s http://127.0.0.1:8766/systemManage/risk/score | jq .data.final'
```