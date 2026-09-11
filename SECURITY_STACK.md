# 安全设计与技术边界

项目总览见 [README.md](README.md)，部署步骤见
[docs/INSTALL.md](docs/INSTALL.md)。

## 信任边界

- Falco 观察系统行为并产生检测事件，不负责阻断；
- TSA 以普通用户运行，只读 Falco、BPF LSM 和 Lynis 结果；
- TSA 不写 BPF Map，也不修改内核策略；
- BPF LSM 控制器由 root 运行，负责校验 YAML、写 Map 和挂载程序；
- 内核程序默认放行，只有通过校验的 `enforce` 策略才能返回 `-EPERM`；
- Web 看板只绑定 `127.0.0.1:8766`，只提供状态读取接口。

这使检测、评分和强制控制相互隔离。即使 TSA 或看板异常，也不能直接改变
内核放行策略。

## BPF LSM 策略模型

控制器启动时将绝对路径解析为：

```text
device + inode → policy_id + mode + expires_at
```

内核程序挂载六个 LSM hook：

| Hook | 操作 |
|---|---|
| `file_permission` | 写入 |
| `inode_unlink` | 删除 |
| `inode_rename` | 重命名或覆盖 |
| `inode_setattr` | 修改属性 |
| `mmap_file` | 新建共享可写文件映射 |
| `file_mprotect` | 共享文件映射升级为可写 |

决策顺序：

1. 不在保护 Map 中：放行；
2. 策略已过期：放行；
3. UID 在允许 Map 中：放行；
4. `audit`：输出事件并放行；
5. `enforce`：输出事件并返回 `-EPERM`。

BPF 事件通过 ring buffer 交给 Go 控制器，再写入 JSONL 日志。ring buffer
用于传递证据，不参与策略决策。

## TSA 评分

TSA 使用两个分数：

- `posture`：按项目配置从 Lynis 报告计算的基线分，不等于 Lynis 原始 hardening index；
- `runtime`：当前尚未过期的 Falco/BPF 风险事件分。

当前最终分：

```text
final = posture × 0.4 + runtime × 0.6
```

运行时事件支持：

- 事件指纹去重；
- 每条规则每分钟限速；
- 每条规则有效风险上限；
- 按优先级或动作设置风险有效期；
- SQLite 持久化与服务重启恢复；
- 部署维护窗口不计分。

评分用于展示风险趋势，不应直接触发 BPF `enforce`。

## Falco 与 BPF 事件关联

看板在 3 秒窗口内按以下顺序关联：

1. PID 相同；
2. Falco 未输出 PID 时，使用进程名和受保护路径。

页面会显示关联依据。该关联只用于证据展示，不改变 TSA 评分，也不声称是
内核级唯一事务关联。

## 当前限制

- device/inode 能稳定保护现有文件，但文件删除并以新 inode 重建后，需要
  重启控制器刷新策略；
- 还未实现基于父目录和文件名的新建拦截；
- `allowed_uids` 只能表达 UID 白名单，尚未细化到可执行文件签名或 cgroup；
- 强制模式必须先在 `audit` 中完成正常访问画像和回滚验证；
- 当前评分权重属于项目策略，需要通过实验数据继续校准。
- 已存在的共享可写映射不会被后加载的策略撤销，必须在相关进程启动前加载策略；从 audit 切到 enforce 时应重新启动相关工作负载。
- 控制器未 pin BPF links，停止或重启存在保护空窗；root 能改变主机安全配置。
- 两个事件源可分别扣分；日志轮转和历史清理不等于无限吞吐或无限磁盘保护。

## 安全与升级注意

- 看板拒绝非回环绑定并校验 Host。远程访问使用 SSH 或有鉴权的 TLS 代理；代理上游 Host 设为 `127.0.0.1:8766`。回环接口仍信任本机用户，旧版本遗留的防火墙开放规则需自行检查。
- 基线必须完整且新鲜：报告含 `report_version_major`、`finish=true`，默认有效期一天；TSA 默认只读取报告，每 300 秒刷新。没有基线不会自动给 100 分；显式禁用基线属于运行时单项实验，不代表完成审计。
- TSA 心跳超过 30 秒、启用的采集服务停止、日志不可读或基线无效时，健康与评分接口返回 HTTP 503，评分 `data:null`。服务 active 本身不足以证明采集正常。
- 事件、去重、限速与日志位置在同一 SQLite 事务中提交；失败时重放未确认事件。已有日志首次接入默认从末尾读取，不能用首次部署代替历史日志取证。
- 升级时按复现指南重新部署，不要只替换 Python 文件。部署以普通用户构建、由 root 安装，并通过 systemd 参数指定完整/纯检测模式，不重写源 YAML。
- Falco 计分白名单位于 `runtime_rules.whitelist`，不支持旧的 `bpf_lsm.whitelist`。优先用精确规则条件设置例外，不要仅凭可伪造的进程名豁免风险。

实际测试结果见 [验证记录](docs/VM_VALIDATION.md)；历史修复细节可从 Git 历史查阅，不是无漏洞认证。

## 构建说明

标准构建链为 cilium/ebpf `bpf2go`。仅修改内核 C 时需要重新生成；先安装 clang、llvm、libbpf-dev，并将所选 Go 工具链加入 PATH：

```bash
# 在项目根目录运行
go generate ./...
go test -race ./...
go vet ./...
```

`lsmbpf_x86_bpfel.go/.o` 是控制器使用的规范生成物。

