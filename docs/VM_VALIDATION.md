# Ubuntu 验证记录

本文件回答“在哪个环境实际测过、阻断是否生效、还有哪些限制”，不是安装教程。复现步骤见 [INSTALL.md](INSTALL.md)。

## 验证环境

2026-09-11，新建 VMware 虚拟机 `LRSS-Clean-Ubuntu-22.04`，2 vCPU、4 GB 内存、30 GB 磁盘、NAT。使用官方 Ubuntu 22.04.5 Server cloud image，初始检查无 Falco、Go、Lynis 或项目服务，保存安装前快照；不是复用已部署项目的旧系统。

| 项目 | 实测值 |
|---|---|
| 源码 | GitHub 默认 clone main，提交 `72d09a3100384b9d23ac9dbab31a24451de57e72`；后续文档合并至 `21badc1`，产品代码未变 |
| 内核 | `6.8.0-138-generic`，BTF 可用，`CONFIG_BPF_LSM=y` |
| 已启用 LSM | `lockdown,capability,landlock,yama,apparmor,bpf` |
| 依赖 | Falco 0.44.1 modern eBPF、Go 1.26.8、Python 3.10、真实 Lynis 报告 |
| 镜像校验 | Ubuntu 20260829 构建；SHA256 `95553d7df39a2dfaee134036af10d9f8f253726f637e2fc84d0b8ac66a378e95`，与官方 HTTPS 清单一致 |

安装指南的 7 个 Bash 代码块经过语法检查和逐块实际执行。APT 下载失败后配置阿里云 HTTPS 源及临时 SSH 代理，从失败命令继续；Git/Go 实际联网下载，未使用旧机缓存，未关闭 TLS、软件包签名或模块校验。VMware Workstation 16 在本机使用虚拟硬件版本 10 启动；处理 Tools/NTP 冲突、确认 UTC 时间正确后才生成基线。

## 通过的检查

| 检查 | 实际结果 |
|---|---|
| 构建与部署 | Go 模块校验、Go 常规测试、53 项 Python 测试通过；总部署退出 0，四个服务 active/enabled |
| Falco 规则 | 新系统装入仓库锁定的 93 条官方定义及项目规则，实际引擎校验通过；定义数量不等于启用数量 |
| audit | 演示文件写入成功，Falco `Write below etc` 与 BPF `audit` 均有真实事件，进入 TSA 并关联 |
| 自定义规则 | 读取演示文件触发 `Monitor specific file access` 并入库 |
| enforce | 演示策略切到 enforce 后重新部署，写入被拒绝，返回 `EPERM`；BPF `deny` 入库，看板显示“已拦截” |
| 模式恢复 | 恢复原 audit 配置、重新部署，安装后的策略与原文件一致，源码 checkout 干净 |
| 内核集成 | 以 root 执行 `TestBPFEnforceIntegration`，不是 SKIP；六个 hooks 的阻断、audit 与允许 UID 路径通过 |
| 看板与数据库 | 页面可显示并展开原始证据，只有回环监听；SQLite `integrity_check=ok`，健康与评分 HTTP 200 |
| 整机冷启动 | 正常关机后再开机，boot ID 改变；四个服务自动恢复，之前 40 条事件 ID 全保留，新事件继续入库 |

### 不放行是什么效果

`audit` 只是演示的默认模式，不表示没有验证阻断。实际 enforce 检查执行了文件追加写入，得到 `errno=EPERM`；对应 BPF 日志的关键字段为：

```json
{"source":"bpf_lsm","policy_id":1001,"action":"deny","operation":"write","result":-1}
```

上述为事件字段节选。`deny` 表示内核拒绝操作，不是 Falco 报警后再删除文件内容。Falco 仍只负责检测；TSA 负责记录和计分。完成实验后已恢复 audit，没有长期对系统文件启用 enforce。

## 验证边界

- 新机 Lynis 原始 `hardening_index=57`，有软件包风险 `PKGS-7392` 与防火墙规则警告 `FIRE-4512`；本轮未做整机补丁升级或生产账户加固。
- 首次验收 `posture=85.0, runtime=86.0, final=85.6`；测试和 SSH/sudo 行为会触发规则并降低分数，没有清空历史事件以制造高分。分数和告警都不能直接当作安全认证或真实入侵结论。
- 已测试上述 Ubuntu/kernel/Falco 组合，不代表覆盖 Ubuntu 24.04、ARM、全部文件系统、长期压力或全部上游规则；完整模式仍需主机内核支持。
- 控制器重启有保护空窗，已有共享映射和 inode 重建存在限制；详见 [安全设计](../SECURITY_STACK.md)。
- 之前在另一台 Ubuntu 22.04.5 / `6.8.0-60-generic` / Falco 0.42.1 完成过 13 项故障检查、BPF 重新生成和竞态测试；未在本轮新机重做全部故障注入，不能混用测试范围。完整历史记录保留在 [Git 历史](https://github.com/rrenziho333-bot/linux-runtime-security-stack/blob/21badc19d97c5b7fbc9cc2136574b7fc5d140a9f/docs/VM_VALIDATION.md)。

**结论：上述干净 Ubuntu 路线的安装、检测、实际阻断、评分和冷启动恢复已验证通过；项目是可复现的安全实验系统，不是已完成生产安全准入的产品。**
