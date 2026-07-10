# 主机运行时安全检测与阻断系统

本项目把 **Falco、BPF LSM、TSA 和 Lynis** 组合成一条主机安全流水线：

> Falco 发现可疑行为，BPF LSM 对指定敏感对象审计或阻断，TSA 汇总事件并计算风险分，Lynis 提供系统基线分。

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

TSA 不是 Falco 插件，而是本项目实现的独立融合服务。Falco 和 BPF LSM
也不是重复功能：Falco 负责“看得广”，BPF LSM 负责“管得准”。

## 3. 一次敏感操作会发生什么

以写入 `/etc/tmp_rzh` 为例：

```bash
echo test | sudo tee -a /etc/tmp_rzh >/dev/null
```

当前策略是 `audit`，因此：

1. Falco 匹配文件写入规则并生成报警；
2. BPF LSM 命中 `protect_tmp_rzh` 策略；
3. 内核记录审计事件，但允许写入；
4. TSA 接收两类事件，执行去重、限速和临时风险扣分；
5. 看板显示完整证据链。

如果策略经过验证后改为 `enforce`，第 3 步会返回 `-EPERM`，写入被内核拒绝。

## 4. 当前实现

- Falco 0.42.1，使用主机版 modern eBPF 驱动；
- BPF LSM 覆盖写入、删除、重命名和属性修改；
- BPF 策略使用 YAML 配置，默认采用安全的 `audit` 模式；
- TSA 使用 SQLite 持久化，支持去重、限速、风险过期和重启恢复；
- Web 看板每 2 秒展示服务状态、策略、评分和事件证据链；
- 服务均由 systemd 管理，日志由 logrotate 轮转。

## 5. 快速使用

```bash
sudo /home/zhaoren/ebpf/deploy-security-stack.sh
systemctl is-active falco-modern-bpf bpf-lsm-controller tsa-fusion tsa-dashboard
```

看板地址：

```text
http://127.0.0.1:8766/
```

完整部署与验证步骤见 [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)。

导师汇报提纲见 [docs/MENTOR_REPORT.md](docs/MENTOR_REPORT.md)。

技术边界与安全设计见 [SECURITY_STACK.md](SECURITY_STACK.md)。

## 6. 核心代码

```text
/home/zhaoren/ebpf
├── bpf/lsm_block_write.c       # 内核 BPF LSM 程序
├── main.go                     # BPF 加载、挂载和事件输出
├── policy.go                   # 策略校验及 BPF Map 写入
├── policy.yaml                 # 当前保护对象与 audit/enforce 模式
├── falco/rules.d/              # 自定义 Falco 规则与例外
├── tsa/
│   ├── tsa_core.py             # 事件融合、去重、评分和持久化
│   ├── tsa_fusion.py           # TSA 服务入口
│   ├── tsa_dashboard.py        # 只读 Web 看板
│   ├── policy_config.yaml      # TSA 评分策略
│   └── tests/                  # Python 单元与集成测试
├── deploy-security-stack.sh    # 测试、安装和启动入口
└── systemd/                    # 服务定义
```

`lsmbpf_x86_bpfel.go/.o` 是 `bpf2go` 生成文件，`bpf-lsm-controller`
是构建产物，不是手写核心逻辑。
