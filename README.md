# 主机运行时安全检测与阻断系统

把 Falco、BPF LSM、TSA、Lynis 组合成一条主机安全流水线：Falco 发现可疑行为并报警，BPF LSM 在内核对敏感文件做审计或阻断，TSA 汇总事件算风险分，Lynis 给系统基线分。

- 从空白机器开始装前置：[docs/INSTALL.md](docs/INSTALL.md)
- 最快跑通（5 步，从 clone 到别人 curl 拿分）：[docs/QUICKSTART.md](docs/QUICKSTART.md)
- 已装好前置、只需部署和实时检测：[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- 风险分怎么算：[docs/INSTALL.md](docs/INSTALL.md) §6.6

> **验证环境**：Ubuntu 22.04（kernel 6.8）+ Falco 0.44.x + Go 1.25 上完整模式端到端跑通（Falco 检测 + BPF LSM 内核审计 + TSA 双源评分 + 看板 + 对外接口）。部署脚本已适配 Falco 多版本差异，新手照 QUICKSTART 可从空白机一次性复现。

## 30 秒速览

- 干什么的：在 Linux 主机上做运行时安全检测。Falco 按规则报警，BPF LSM 在内核对受保护文件做审计或阻断，TSA 融合事件算风险分，Lynis 给基线分。
- 怎么跑：装好 Falco + Go 前置 → `sudo ./deploy-security-stack.sh` 一键部署。脚本会探测内核：有 BPF LSM 就检测+阻断，没有就自动降级为纯检测。
- 怎么验：`systemctl is-active` 看服务 → 写 `/etc/tsa-protected-demo` 触发检测 → 看板 `http://127.0.0.1:8766/` 看证据。
- 怎么对接：外部系统 `GET http://<监测机IP>:8766/systemManage/risk/score` 拿实时风险分。
- 跑不起来先看：前置装了吗（INSTALL §2、§3）？内核够新吗？CentOS 7 不行，需要 8/Stream 9 以上。

## 1. 一张图理解项目

```text
用户/进程执行文件、提权或网络操作
                  │
          Linux 内核与系统调用
             ┌────┴────┐
             ▼         ▼
          Falco     BPF LSM
         广域检测    精确控制
         只报警      AUDIT / DENY
             └────┬────┘
                  ▼
                 TSA
       去重、限速、持久化、风险评分
                  ▲
                  │
                Lynis
              系统基线检查
                  │
                  ▼
       SQLite / JSON 报告 / Web 看板
```

## 2. 四个组件分别做什么

| 组件 | 作用 | 是否拦截 |
|---|---|---|
| Falco | 根据规则检测进程、文件、网络和容器行为 | 否，只报警 |
| BPF LSM | 在内核安全检查点匹配受保护文件 | `audit` 放行，`enforce` 拒绝 |
| TSA | 融合 Falco、BPF LSM 和 Lynis，去重并评分 | 否 |
| Lynis | 检查补丁、认证、SSH、防火墙等静态安全基线 | 否 |

TSA 不是 Falco 插件，是本项目自己写的独立融合服务。Falco 和 BPF LSM 也不重复：Falco 看得广，BPF LSM 管得准。

## 3. 一次敏感操作会发生什么

以写入 `/etc/tsa-protected-demo` 为例（部署脚本会在缺失时自动创建该文件）：

```bash
echo test | sudo tee -a /etc/tsa-protected-demo >/dev/null
```

当前策略是 `audit`，流程是：

1. Falco 匹配文件写入规则并报警；
2. BPF LSM 命中 `protect_demo_config` 策略；
3. 内核记录审计事件，但允许写入；
4. TSA 接收两类事件，去重、限速、扣临时风险分；
5. 看板显示完整证据链。

策略改成 `enforce` 后，第 3 步会返回 `-EPERM`，写入被内核拒绝。

## 4. 当前实现

- Falco（实测 0.44.x，modern eBPF 主机版驱动；部署脚本兼容会改 `rules_files`/输出配置的多个 Falco 版本，见 [docs/INSTALL.md](docs/INSTALL.md) §7）；
- 检测规则 = Falco 官方规则集 + 1 条自定义文件监控规则（`falco/rules.d/`）；官方规则快照已入库可直接读（`falco/official-rules/`）；TSA 为其中 86 条官方规则配了扣分权重；
- BPF 策略用 YAML 配置，默认 `audit` 模式；
- TSA 用 SQLite 持久化，支持去重、限速、风险过期、重启恢复；
- Web 看板每 2 秒刷新服务状态、策略、评分和事件证据链；
- 服务由 systemd 管理，日志由 logrotate 轮转。

## 5. 快速使用

跑下面的部署脚本前，先 clone 本仓库，装好 Falco（modern eBPF）和 Go 1.25。从空白机器开始的话，先看 [docs/INSTALL.md](docs/INSTALL.md) 从零装前置，否则部署会失败。

```bash
sudo ./deploy-security-stack.sh
systemctl is-active falco-modern-bpf bpf-lsm-controller tsa-fusion tsa-dashboard
# 完整模式四项 active；降级模式 bpf-lsm-controller 为 inactive（正常，见文档）
```

部署脚本会按当前 `SUDO_USER` 和脚本所在目录自动生成 systemd unit，不用手改路径。移植到新主机时把仓库放任意目录、用部署用户执行 `sudo` 即可，详见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)。

脚本会探测内核是否支持 BPF LSM：支持就部署完整模式（检测+阻断，四个服务都 active）；不支持就自动降级为纯检测（跳过 `bpf-lsm-controller`，关闭 TSA 的 BPF 日志源，对应 `is-active` 显示 inactive），Falco + TSA + 看板照常工作。降级细节见 [docs/INSTALL.md](docs/INSTALL.md) 第 9 节。

判断当前是哪种模式：

```bash
grep -w bpf /sys/kernel/security/lsm   # 输出含 bpf = 完整模式；无输出 = 降级模式
```

看板地址：

```text
http://127.0.0.1:8766/   （别的主机用 http://<监测机IP>:8766/）
```

不知道监测机 IP 的话，在监测机上执行 `ip a` 或 `hostname -I`，取局域网地址填进去。

服务绑 `0.0.0.0:8766`，可被别的主机访问（部署脚本自动放行防火墙 8766 端口）。

### 对外接口：查询实时风险分值

外部系统（如零信任管理系统）可用 HTTP GET 查询监测机的实时风险分，响应遵循《零信任管理系统接口文档》统一信封 `{code, status, message, data}`：

```bash
# 别的主机查询监测机实时分值
curl http://<监测机IP>:8766/systemManage/risk/score
# → {"code":20000,"status":true,"message":"操作成功",
#    "data":{"final":100.0,"posture":100.0,"runtime":100.0,"generated_time":"..."}}
```

`final` 是最终风险分（满分 100，越低越危险）。接口验证和他机访问排查见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) 第 9 节。

完整部署与验证步骤见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)。导师汇报提纲见 [docs/MENTOR_REPORT.md](docs/MENTOR_REPORT.md)。技术边界与安全设计见 [SECURITY_STACK.md](SECURITY_STACK.md)。

## 6. 核心代码

```text
<项目根目录>（部署脚本所在目录）
├── bpf/lsm_block_write.c       # 内核 BPF LSM 程序
├── main.go                     # BPF 加载、挂载和事件输出
├── policy.go                   # 策略校验及 BPF Map 写入
├── policy.yaml                 # 当前保护对象与 audit/enforce 模式
├── falco/
│   ├── rules.d/                # 自定义 Falco 规则与例外
│   ├── official-rules/         # 官方规则快照（93 条，供分析阅读）
│   └── fetch-official-rules.sh # 更新官方规则快照
├── tsa/
│   ├── tsa_core.py             # 事件融合、去重、评分和持久化
│   ├── tsa_fusion.py           # TSA 服务入口
│   ├── tsa_dashboard.py        # 只读 Web 看板
│   ├── policy_config.yaml      # TSA 评分策略
│   └── tests/                  # Python 单元与集成测试
├── docs/                       # INSTALL（从零安装）、DEPLOYMENT（部署演示）
├── deploy-security-stack.sh    # 测试、安装和启动入口
└── systemd/                    # 服务定义（模板，部署时渲染）
```

`lsmbpf_x86_bpfel.go/.o` 是 `bpf2go` 生成文件，`bpf-lsm-controller` 是构建产物，不是手写核心逻辑。