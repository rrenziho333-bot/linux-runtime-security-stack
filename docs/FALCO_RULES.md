# 新 Linux 机器的规则部署与自定义

## 1. clone 下来的规则在哪里

本项目现在默认部署仓库内的规则，而不是依赖目标机器碰巧安装了哪些官方规则。相同 Git 提交、相同自定义文件会生成相同规则包 ID；不需要部署时联网下载规则。

```text
linux-runtime-security-stack/
  falco/
    official-rules/
      falco_rules.yaml             官方 stable：当前 25 条
      falco-sandbox_rules.yaml     官方 sandbox：当前 37 条
      falco-incubating_rules.yaml  官方 incubating：当前 31 条
      VERSION.txt                  来源说明，原快照精确上游 tag 未知
    rules.lock.json                官方规则 SHA256 与定义数量
    rules.d/
      90-local-file-monitoring.yaml     项目演示文件检测
      91-custom-rules.yaml              你的自定义规则编辑入口
      95-security-stack-exceptions.yaml 项目例外，不是新的检测规则
    manage_rules.py                校验、安装和显示规则包信息
    deploy-host-falco.sh           安装规则并配置、重启 Falco
  tsa/policy_config.yaml           告警扣分配置，不负责定义检测行为
```

当前基准是 **93 条官方规则定义 + 1 条项目检测规则**。这不是“94 条全部启用”，也不是完整攻击覆盖保证：`enabled: false`、Falco 的 `rules` 开关、优先级、事件源、容器条件和例外仍然生效。sandbox/incubating 含实验性规则，生产环境应评估误报与性能。

SHA256 固定内容，不证明原快照的上游发布身份；历史文件没有可靠 release tag，因此不会把版权年份冒充版本。更新官方规则是维护工作，不是新用户必须做的安装步骤。

## 2. 在新机器部署

`git clone` 只下载代码，不会安装内核能力或启动软件。本项目支持 systemd Linux；已验证 Ubuntu 22.04.5、内核 6.8、Falco 0.42.1。不是所有 Linux 发行版都能无前置直接运行。

1. 按 [INSTALL.md](INSTALL.md) 安装 Falco、Python 3、PyYAML；完整阻断模式准备符合 `go.mod` 的 Go 和启用了 BPF LSM 的内核。
2. clone 包含本功能的分支/提交。若功能还在 PR 分支而未合并，普通 clone 默认分支不会自动取得它：

```bash
git clone --branch codex/security-hardening https://github.com/rrenziho333-bot/linux-runtime-security-stack.git
cd linux-runtime-security-stack
python3 falco/manage_rules.py check
```

`check` 使用本机 Falco 校验整个候选规则集，包含需要保留的主机规则；不会修改运行配置或重启服务。权限不足时用 sudo。缺文件、校验和不匹配、宏引用或引擎不兼容都会失败，不会悄悄回退为较少的系统规则。

3. 按 [QUICKSTART.md](QUICKSTART.md) 下载 Go 模块并准备 Lynis 基线，再部署整套服务：

```bash
sudo ./deploy-security-stack.sh
# 使用独立 Go 时：sudo GO_BIN=/绝对路径/go ./deploy-security-stack.sh
```

如果整套项目已经部署，只更新 Falco 规则即可：

```bash
sudo ./falco/deploy-host-falco.sh
```

## 3. 安装后规则在哪里

规则包复制到独立版本目录，`<规则包ID>` 是内容 SHA256：

```text
/etc/falco/security-stack/rules/<规则包ID>/
  official/     三份固定官方规则
  custom/       仓库 falco/rules.d/*.yaml 的副本
  manifest.json 每个文件的 SHA256 和规则定义数
```

部署器更新 `/etc/falco/falco.yaml` 的 `rules_files`，让它明确加载上述文件。系统包的 `/etc/falco/falco_rules*.yaml` 保留原样，不再作为本项目的默认官方来源；包管理器/falcoctl 更新那些文件不会改变本项目规则包。

现有 `/etc/falco/rules.d/` 中不与项目文件同名的规则，以及原配置中的其他规则路径会继续保留并加载，输出会列出 `Preserved host rule paths`。同名旧项目副本仍保留在磁盘，但不会重复加载。旧机器因此可能比全新机器多一些额外规则；要严格比较，应同时核对这些路径、Falco 版本和启用开关。

如果 `config.d` 中另有 `rules_files`，部署会指出冲突文件并停止，请先把需要的路径整理到主配置，不会擅自删除覆盖配置。自定义 systemd 启动参数 `-r` 可绕过 `rules_files`，应检查服务实际命令，避免与项目配置冲突。

```bash
sudo python3 -c 'import yaml; print("\n".join(yaml.safe_load(open("/etc/falco/falco.yaml"))["rules_files"]))'
systemctl show falco-modern-bpf -p ExecStart
sudo falco -L -o json_output=false
```

规则内容在切换配置前通过本机 Falco 校验。原配置备份为 `/etc/falco/falco.yaml.bak-rules-*`；配置通过 YAML 解析后重写，保留设置值但不保留原注释。旧规则包目录保留供回滚，不自动清理。上述保障针对规则安装，不代表整个服务部署的所有步骤都是原子事务。

## 4. 自定义规则怎么添加

**修改现有演示规则**：编辑 `falco/rules.d/90-local-file-monitoring.yaml`。

**添加你自己的规则**：编辑 `falco/rules.d/91-custom-rules.yaml`。删除占位的 `[]`，替换为下面的完整例子；也可以在同目录创建任意其他 `*.yaml` 文件。每个新规则使用唯一名称。

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

这条规则观察打开行为，不证明文件已读取完成，也不会阻断。规则语法参考 [Falco 自定义规则](https://falco.org/docs/concepts/rules/custom-ruleset/)。

在 **Ubuntu 项目根目录** 校验、部署并触发：

```bash
python3 falco/manage_rules.py check
sudo ./falco/deploy-host-falco.sh
sleep 5
touch /tmp/lrss-learning.txt
cat /tmp/lrss-learning.txt
sudo tail -n 20 /var/log/falco/falco.json
```

应检查事件对象、进程与规则名。systemd 的 active 只说明进程已启动，采集引擎初始化可能更慢；若重启后的首次读取没有事件，等几秒再执行只读的 `cat` 并检查日志。默认 `rule_matching: first`，若更早的规则已经匹配该事件，实际告警可能使用先匹配的名称。不要为了固定告警名盲目开启 `all` 或禁用官方规则。

需要指定扣分时，在 `tsa/policy_config.yaml` 的 `runtime_rules.specific_rules` 增加 `"Project learning file opened": 5`，重启 `tsa-fusion`。不配置专属分值时按现有 tags/priority 兜底；去重和限速可能使新告警不立即扣分。修改评分配置不会创建 Falco 检测规则，更不会自动添加 BPF 阻断策略。

删除自定义规则后重新部署即可，新配置不会引用旧规则包中的该文件。不要直接修改已安装的版本目录。Windows 上的修改需要提交/pull 或另行同步到 Ubuntu，不会自动生效。

## 5. 维护官方规则

普通使用者不用修改官方文件。维护者可用 `falco/fetch-official-rules.sh` 获取选定来源；它更新仓库文件和来源记录，但不会自动安装或刷新锁文件。审查差异和上游来源后显式执行：

```bash
python3 falco/manage_rules.py lock
python3 falco/manage_rules.py check
PYTHONPATH=tsa python3 -m unittest discover -s tsa/tests -v
```

将三份规则、`VERSION.txt`、`rules.lock.json` 和相关测试/评分调整一起提交。只改自定义规则不需要刷新官方锁。不能为了消除未知来源文件的校验失败而盲目重新生成锁。
