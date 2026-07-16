# 安全设计与技术边界

项目总览见 [README.md](README.md)，部署步骤见
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)。

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

内核程序挂载四个 LSM hook：

| Hook | 操作 |
|---|---|
| `file_permission` | 写入 |
| `inode_unlink` | 删除 |
| `inode_rename` | 重命名或覆盖 |
| `inode_setattr` | 修改属性 |

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

- `posture`：Lynis 静态基线分；
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

## 构建说明

标准构建链为 cilium/ebpf `bpf2go`：

```bash
cd <项目根目录>
/usr/local/go/bin/go generate ./...
/usr/local/go/bin/go test -v ./...
/usr/local/go/bin/go vet ./...
```

`lsmbpf_x86_bpfel.go/.o` 是控制器使用的规范生成物。

