# Falco 规则指南

30 条默认规则的分值、触发条件与排查方法见 [规则解析](FALCO_RULES_README.md)。

## 1. clone 下来的规则在哪里

**git clone 只下载文件，不会启动检测。** 首次部署按 [INSTALL.md](INSTALL.md) 操作。

官方定义位于 `falco/official-rules/`。下表是原始快照开关，**不是本项目最终启用数量**：

| 文件 | 规则总数 | 默认启用 | 默认关闭 |
|---|---:|---:|---:|
| `falco_rules.yaml` | 25 | 25 | 0 |
| `falco-sandbox_rules.yaml` | 37 | 25 | 12 |
| `falco-incubating_rules.yaml` | 31 | 31 | 0 |
| 合计 | 93 | 81 | 12 |

项目通过 `89-host-profile.yaml` 覆盖开关，最终默认启用 **29 条官方规则 + 1 条演示规则 = 30 条**。其余 64 条定义关闭但保留，共享宏、列表不能随意删除。已有额外主机规则或用户自定义规则可能改变实际数量。

项目规则位于 `falco/rules.d/`：

| 文件 | 用途 | 是否必须 |
|---|---|---|
| `89-host-profile.yaml` | 选择默认 29 条官方主机规则，其余关闭 | 默认 30 条方案必需 |
| `90-local-file-monitoring.yaml` | 检测打开 `/etc/tsa-protected-demo` 进行读写，只报警 | 当前演示与验收使用，保留 |
| `91-custom-rules.yaml` | 自定义入口，初始 `[]` 表示没有自定义规则 | 文件名非强制，也可新增其他 `*.yaml` |
| `95-security-stack-exceptions.yaml` | 为 falcoctl 写入 `/root/.sigstore/` 设置告警例外 | 非启动必需；删除可能增加组件自身告警，建议保留 |

`95` 只调整相关告警条件，不关闭整套规则。官方文件由 `falco/rules.lock.json` 校验；日常修改放在 `rules.d/`，不要直接改官方文件。现有快照来自 [falcosecurity/rules](https://github.com/falcosecurity/rules)，精确上游 tag 未知，校验和仅固定内容，不证明发布身份。

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

若无事件，稍等后再执行命令 4、5；更早的规则先匹配时，告警名称可能不同。新规则默认只报警、不扣分；需要计分时，在 `tsa/policy_config.yaml` 的 `specific_rules` 添加同名规则的 `points`、`risk_ttl_seconds`、`reason`，再重启 `tsa-fusion tsa-dashboard`。删除或改变检测规则后需重新部署；不直接改官方快照。
