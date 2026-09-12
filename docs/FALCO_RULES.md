# Falco 规则指南

## 1. clone 下来的规则在哪里

**git clone 只下载文件，不会启动检测。** 首次部署按 [INSTALL.md](INSTALL.md) 操作。

官方规则位于 `falco/official-rules/`。按当前仓库 YAML 的默认开关统计：

| 文件 | 规则总数 | 默认启用 | 默认关闭 |
|---|---:|---:|---:|
| `falco_rules.yaml` | 25 | 25 | 0 |
| `falco-sandbox_rules.yaml` | 37 | 25 | 12 |
| `falco-incubating_rules.yaml` | 31 | 31 | 0 |
| 合计 | 93 | 81 | 12 |

`enabled: false` 表示关闭；未写该字段时默认启用。12 条关闭规则都在 sandbox 文件中，其余官方规则默认启用。加上项目演示规则，共 **82 条默认启用的规则定义**；主机配置仍可覆盖开关或过滤优先级，容器规则也不会因普通主机操作而触发。规则存在不等于能覆盖所有攻击。

项目规则位于 `falco/rules.d/`：

| 文件 | 用途 | 是否必须 |
|---|---|---|
| `90-local-file-monitoring.yaml` | 检测打开 `/etc/tsa-protected-demo` 进行读写，只报警 | 当前演示与验收使用，保留 |
| `91-custom-rules.yaml` | 自定义入口，初始 `[]` 表示没有自定义规则 | 文件名非强制，也可新增其他 `*.yaml` |
| `95-security-stack-exceptions.yaml` | 为控制器加载 BPF、falcoctl 写入 `/root/.sigstore/` 设置告警例外 | 非启动必需；删除可能增加组件自身告警，建议保留 |

`95` 只调整相关检测条件，不关闭整套规则或放开 BPF 阻断。官方文件由 `falco/rules.lock.json` 校验；日常修改放在 `rules.d/`，不要直接改官方文件。现有快照来自 [falcosecurity/rules](https://github.com/falcosecurity/rules)，精确上游 tag 未知，校验和仅固定内容，不证明发布身份。

## 3. 安装后规则在哪里

部署后的副本位于：

```text
/etc/falco/security-stack/rules/<规则包ID>/
  official/      三份官方规则
  custom/        rules.d 下的项目规则
  manifest.json  文件清单与校验信息
```

`/etc/falco/falco.yaml` 的 `rules_files` 指向这些文件。系统原有的官方规则文件不删除，但不再作为项目默认来源；已有额外主机规则仍可能加载。配置冲突时部署会停止，旧配置和规则包保留供回滚。

**修改仓库文件后重新部署，不要直接修改上述副本。** Windows 修改需先同步到 Ubuntu；自定义服务参数 `-r` 可能覆盖加载路径。

## 4. 自定义规则怎么添加

在仓库 `falco/rules.d/91-custom-rules.yaml` 中，将 `[]` 替换为下面完整示例；也可在同目录新增 `*.yaml`。规则名不能重复。

```yaml
- rule: Project learning file opened
  desc: Detect cat opening the learning file for reading
  condition: >
    evt.type in (open, openat, openat2)
    and evt.is_open_read = true
    and fd.name = "/tmp/lrss-learning.txt"
    and proc.name = cat
  output: >
    Learning file opened
    (file=%fd.name process=%proc.name pid=%proc.pid user=%user.name)
  priority: WARNING
  source: syscall
  tags: [filesystem, host]
```

在 **Ubuntu 项目根目录** 按顺序执行，每个代码框是一条命令：

**命令 1：校验；失败时先修正规则，权限不足时用 sudo。**
```bash
python3 falco/manage_rules.py check
```

**命令 2：部署并重启 Falco。**
```bash
sudo ./falco/deploy-host-falco.sh
```

等待约 5 秒后测试：

**命令 3：准备测试文件。**
```bash
touch /tmp/lrss-learning.txt
```

**命令 4：触发读取检测。**
```bash
cat /tmp/lrss-learning.txt
```

**命令 5：查看告警中的规则名、文件和进程。**
```bash
sudo tail -n 20 /var/log/falco/falco.json
```

若无事件，稍等后再执行命令 4、5；更早的规则先匹配时，告警名称可能不同。这条规则只检测打开行为，不阻断。扣分配置在 `tsa/policy_config.yaml`，与 Falco 检测规则分开；删除自定义规则后也需重新部署。
