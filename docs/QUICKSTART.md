# 快速验证（5 步）

从空白 Linux 到"别人 curl 拿到分数"。只敲命令、看输出就行，原理看 [INSTALL.md](INSTALL.md)。

> 发行版：Ubuntu 22.04+ 或 CentOS 8/Stream 9+。CentOS 7 不行（内核太旧）。

## 1. 装前置（监测机，一次性）

```bash
# Falco（Ubuntu；CentOS 见 INSTALL §2）
sudo install -dm755 /etc/apt/keyrings
curl -s https://falco.org/repo/falcosecurity-packages.asc | sudo gpg --dearmor -o /etc/apt/keyrings/falco.gpg
echo "deb [signed-by=/etc/apt/keyrings/falco.gpg] https://download.falco.org/packages/deb stable main" | sudo tee /etc/apt/sources.list.d/falco.list
sudo apt update && sudo apt install -y falco

# Go
wget -q https://go.dev/dl/go1.23.10.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.23.10.linux-amd64.tar.gz
ls /sys/kernel/btf/vmlinux    # 必须存在
```

## 2. 部署（监测机）

```bash
git clone https://github.com/rrenziho333-bot/linux-runtime-security-stack.git ~/lrss
cd ~/lrss
/usr/local/go/bin/go mod download
sudo ./deploy-security-stack.sh
```

## 3. 看服务（监测机）

```bash
systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard
```
期望三行 `active`。

## 4. 本机查分数（监测机）

```bash
curl -s http://127.0.0.1:8766/systemManage/risk/score | jq
```
期望：
```json
{"code":20000,"status":true,"message":"操作成功","data":{"final":100.0,"posture":100.0,"runtime":100.0,"generated_time":"..."}}
```

## 5. 别人查分数（另一台主机）

监测机查 IP：`ip a | grep "inet " | grep -v 127.0.0.1`，取局域网地址（如 192.168.1.50）。

另一台主机：
```bash
curl -s http://192.168.1.50:8766/systemManage/risk/score | jq
```
拿到和第 4 步一样的 JSON，就通了。

## 不通？

- 别人访问不通：云主机要去云控制台安全组放行 8766；本机 `ss -ltnp | grep 8766` 应见 `0.0.0.0:8766`。
- 返回 `code:50000`：`systemctl status tsa-fusion` 看 active 没有。
- 部署失败：多半是前置没装好，回 INSTALL §1–§3。