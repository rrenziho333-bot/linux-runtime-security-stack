# Falco 规则选择与逐条解析

本文解释 **linux-runtime-security-stack** 的规则快照。官方规则核对基准为提交 `f8ecaeb`，项目例外按当前纯检测版本更新，日期为 2026-09-17。依据 `condition`、引用的 `macro/list` 和项目例外进行源码分析；这不是逐条攻击实测报告。

## 先看结论

当前默认启用 **30 条：29 条官方规则 + 1 条项目验收规则**，其余定义保留但关闭。原始快照共有 94 条定义，最初启用 82 条。

## 默认保留的 30 条

适用普通 Ubuntu 主机，不是完整容器/云平台方案；Web 三条只在对应服务活动时触发。`89-host-profile.yaml` 控制检测开关，`tsa/policy_config.yaml` 控制分值。1 分为验收信号、5 分为需上下文的审计线索、10 分为敏感变更/可疑行为、15～20 分为较具体的高风险特征；都不是攻击成功判定。

| 规则名 | 当前风险值 | 有效期 | 选择与计分依据 |
|---|---:|---|---|
| `Directory traversal monitored file read` | 10 | 4 小时 | 路径穿越式敏感文件访问 |
| `Read sensitive file untrusted` | 5 | 1 小时 | 非预期敏感文件读取，需排查合法登录和虚拟机组件 |
| `Search Private Keys or Passwords` | 10 | 4 小时 | 搜索密钥或口令线索 |
| `Clear Log Activities` | 10 | 4 小时 | 日志清理，需核对维护任务 |
| `Create Symlink Over Sensitive Files` | 5 | 1 小时 | 敏感路径软链接变更 |
| `Create Hardlink Over Sensitive Files` | 5 | 1 小时 | 敏感路径硬链接变更 |
| `Linux Kernel Module Injection Detected` | 10 | 4 小时 | 内核模块加载，需核对驱动维护 |
| `PTRACE attached to process` | 5 | 1 小时 | 进程附加调试，可能为合法调试 |
| `Execution from /dev/shm` | 10 | 4 小时 | 共享内存目录执行 |
| `Fileless execution via memfd_create` | 15 | 4 小时 | 内存文件执行，仍需核对合法运行时 |
| `Update Package Repository` | 5 | 1 小时 | 软件源变更，需核对批准记录 |
| `Write below binary dir` | 10 | 4 小时 | 系统程序写打开 |
| `Write below monitored dir` | 10 | 4 小时 | 启动、库和关键目录写打开 |
| `Modify binary dirs` | 10 | 4 小时 | 系统程序删除或重命名 |
| `Detect crypto miners using the Stratum protocol` | 15 | 4 小时 | 挖矿地址参数特征，不代表已确认挖矿 |
| `Netcat/Socat Remote Code Execution on Host` | 15 | 4 小时 | 网络工具执行命令特征 |
| `Known Cryptominer Process Executed` | 15 | 4 小时 | 矿工名称特征，需核对程序来源 |
| `Modify Shell Configuration File` | 5 | 1 小时 | Shell 启动配置变更 |
| `Set Setuid or Setgid bit` | 10 | 4 小时 | SUID 或 SGID 权限变更 |
| `Adding ssh keys to authorized_keys` | 10 | 4 小时 | SSH 持久访问凭据变更 |
| `Run shell untrusted` | 10 | 4 小时 | 非预期进程启动 Shell |
| `Remove Bulk Data from Disk` | 10 | 4 小时 | 批量删除命令特征，需核对清理任务 |
| `Web Server Spawned Shell` | 15 | 4 小时 | Web 进程链启动 Shell |
| `Web Server Spawned Suspicious Child Process` | 10 | 4 小时 | Web 进程链启动可疑工具 |
| `Reverse Shell from Web Server` | 20 | 24 小时 | Web 进程链反向 Shell 字符串特征 |
| `Sudo Potential Privilege Escalation` | 15 | 4 小时 | sudo 可疑参数，不确认漏洞利用成功 |
| `Polkit Local Privilege Escalation Vulnerability (CVE-2021-4034)` | 10 | 4 小时 | pkexec 可疑启动形态，不检查补丁状态 |
| `Potential Local Privilege Escalation via Environment Variables Misuse` | 10 | 4 小时 | 提权相关环境变量特征 |
| `Delete or rename shell history` | 5 | 1 小时 | 历史记录删除或重命名 |
| `Monitor specific file access` | 1 | 15 分钟 | 演示文件验收信号，不代表真实入侵 |

同一规则当前只取未过期证据的最高风险值，重复报警只续期；不同规则分别计分，运行时分最低为 0。撤下的规则不再贡献当前风险，历史证据不删除。过期只代表离开观察窗口，不代表已完成处置。priority 和 MITRE 标签不再自动决定分值；未配置规则仅记录。

低噪声不等于全面安全：容器、Kubernetes、云元数据、RPM 场景默认关闭；代理环境、普通 UDP、用户管理、基础查询等宽泛行为也不纳入默认计分。正常驱动安装、调试、登录组件仍可能触发保留规则，需核对证据后设置窄范围例外，不按进程名整体放行。

## 原始快照参考目录

以下保留原编号，便于查历史报警；表内 82 条为精简前目录，**不代表现在启用 82 条**。

| 来源 | 定义数 | 原始启用 | 原始关闭 | 本文编号 |
|---|---:|---:|---:|---|
| [falco_rules.yaml](../falco/official-rules/falco_rules.yaml) | 25 | 25 | 0 | 01～25 |
| [falco-sandbox_rules.yaml](../falco/official-rules/falco-sandbox_rules.yaml) | 37 | 25 | 12 | 26～50 |
| [falco-incubating_rules.yaml](../falco/official-rules/falco-incubating_rules.yaml) | 31 | 31 | 0 | 51～81 |
| [90-local-file-monitoring.yaml](../falco/rules.d/90-local-file-monitoring.yaml) | 1 | 1 | 0 | 82 |
| 合计 | 94 | 82 | 12 | |

这些名字表示仓库内的固定文件，不代表当前上游最新版；精确上游 tag 未知，内容由 [rules.lock.json](../falco/rules.lock.json) 固定。sandbox/incubating 中的规则也会加载，不是只有第一个文件生效。

**全部 Falco 规则只报警，不阻断操作或终止进程。** TSA 根据告警与 Lynis 报告评分；规则的 `priority` 不等于固定扣分。

## 异常行为分类

以下分类统计精简前的 82 条参考规则，不是当前默认启用数。按主要行为归类，每条只计一次，不代表独立攻击种类或实际报警次数。当前保留范围以文首 30 条表为准。

| 类别 | 主要关注的行为 | 规则数 | 对应下文编号 |
|---|---|---:|---|
| 敏感信息与凭据访问 | 读取敏感配置、SSH 信息、进程环境，搜索私钥或云凭据 | 7 | 01～03、09、21、53、76 |
| 文件、软件与系统配置变更 | 修改软件源、系统目录、文件链接，运行容器包管理工具，访问项目演示文件 | 13 | 12～13、26～33、64、67、82 |
| 可疑程序与命令执行 | 应用启动 shell/工具、容器交互命令、内存或临时目录执行、Web 可疑子进程 | 18 | 04、06、08、17、22～23、25、37、41～44、46～48、54、68～69 |
| 网络通信与文件传输 | API/元数据访问、网络重定向、异常端口或代理环境、文件传输线索 | 13 | 07、14～15、24、59～61、65～66、72～73、75、77 |
| 容器权限、挂载与命名空间 | 特权/高能力容器、敏感挂载与设备路径、命名空间切换及逃逸相关线索 | 10 | 18、34～35、49～50、55～58、74 |
| 账号、权限与提权线索 | 系统账号交互、用户管理、身份切换、SUID/SGID、漏洞相关参数或环境变量 | 8 | 05、38～40、62～63、71、79 |
| 内核与进程完整性 | 内核模块加载、ptrace、可疑库文件访问、BPF 程序加载 | 5 | 16、19～20、80～81 |
| 持久化配置 | 修改 shell 启动配置、操作 cron、写打开 authorized_keys | 3 | 51～52、78 |
| 日志清理与数据破坏线索 | 截断日志、清理 shell 历史、执行数据清除工具 | 3 | 10～11、70 |
| 挖矿特征 | 矿工程序名、命令行中的 Stratum 地址特征 | 2 | 36、45 |
| **合计** | **81 条官方规则 + 1 条项目规则** | **82** | **01～82，无遗漏、无重复** |

例如，容器内执行网络工具也可能涉及网络风险，这里按“工具执行”归类；网络重定向则按“网络通信”归类。下文仍保留 YAML 文件顺序和原编号，方便从表格定位到具体规则及源码。

## 怎么阅读

- 在本文搜索告警中的英文 `rule` 名称。每条都给出中文含义、核心触发条件、正常业务场景和排查/调整入口；完整例外仍以链接中的 YAML 为准。
- `open_read/open_write` 要求以读/写方式打开，Falco 文件类型为 `f` 且描述符非负，**不证明已经读取内容或写入字节**。`f` 是 Falco 的文件描述符分类，不应当作磁盘 inode 文件类型鉴定；字段含义见 [官方字段参考](https://falco.org/docs/reference/rules/supported-fields/)。规则没有使用这两个宏时，不能套用其成功条件。
- `spawned_process` 在本快照中是 `execve/execveat` 事件条件，不是扫描所有存活进程，也没有在该宏中额外判断执行成功。需要结合原始事件的返回结果。
- `container` 要求 Falco 将事件识别为容器；Kubernetes 命名空间、镜像、挂载等条件还依赖相应元数据。只有普通 Ubuntu 主机、没有相关工作负载时，容器规则不会凭空触发。
- `outbound` 在此快照排除了部分回环/私网目的地址；`inbound_outbound` 主要观察 `accept/accept4/listen/connect`，不是逐包检查所有通信。下文的“连接”均受这些宏限制。
- `enabled` 省略时默认启用，但实际告警还取决于 `/etc/falco/falco.yaml` 的加载路径、优先级阈值、主机覆盖配置和字段可用性。旧版部署脚本没有强制 `rule_matching: all`；若主机使用 `first`，前面匹配的规则可能遮住后面的规则，见 [官方匹配说明](https://falco.org/docs/concepts/rules/style-guide/#rules-loading)。
- 按条件可分为行为审计、可疑特征和高风险能力检测。**报警不是攻击成功证明；没有报警也不是安全证明。** 文中的正常场景不是自动白名单，必须结合真实证据核实。

修改方式统一见文末及 [简明规则指南](FALCO_RULES.md)。不要直接修改带完整性校验的官方文件。

## 一、falco_rules.yaml：25 条

### 01. `Directory traversal monitored file read`

**中文：通过目录穿越访问受监控文件。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L318)

- **触发：** 读取或尝试打开 `/etc/`、指定 SSH 目录、名称含 `id_rsa` 的文件，原始路径满足至少两段 `../` 的匹配，且直接父进程不在 shell 名单中。
- **含义与边界：** 提示可能越过应用目录读取配置或凭据；本条包含失败打开，不代表数据已泄露。正常应用使用多层相对路径也可能命中，单段 `../` 不在本条件范围内。
- **排查/调整：** 对照 `fd.nameraw`、解析后的 `fd.name`、返回结果和父进程，确认是否来自非预期请求；重点理解 `directory_traversal`，不要把所有相对路径操作直接认定为攻击。

### 02. `Read sensitive file trusted after startup`

**中文：已启动一段时间的服务读取敏感文件。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L341)

- **触发：** `server_procs` 中的服务进程成功以读方式打开 `sensitive_files`，进程存在超过 5 秒，排除 `sshd` 和已知例外。
- **含义与边界：** 敏感文件包括 `/etc/shadow`、`/etc/sudoers`、PAM 配置等；规则假设部分服务只应在启动时读取它们。配置重载或合法重新认证也可能触发。
- **排查/调整：** 检查服务运行时间、目标文件及重载/认证记录；按真实用途收窄 `user_known_read_sensitive_files_activities`，不要把“trusted”理解为无需调查。

### 03. `Read sensitive file untrusted`

**中文：未列入例外的程序读取敏感文件。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L397)

- **触发：** 成功以读方式打开 `sensitive_files`，进程名存在，且不符合用户管理、包管理、shell、监控、配置管理等名单和宏例外。
- **含义与边界：** “untrusted”只表示未被本规则豁免，不是恶意软件鉴定。桌面认证进程、VMware Tools 或新增管理代理可能因读取 PAM、shadow 等文件产生多条正常业务报警。
- **排查/调整：** 查可执行文件来源、父进程、访问路径和发生时机；核实后按进程路径、用途及目标文件限定例外，不要仅凭名称全局放行。主要入口为 `user_known_read_sensitive_files_activities`。

### 04. `Run shell untrusted`

**中文：受监控应用进程链启动 shell。** 级别：NOTICE。[源码](../falco/official-rules/falco_rules.yaml#L564)

- **触发：** 出现 shell 执行事件，父进程存在，祖先进程或特定 Java/Node 场景符合 `protected_shell_spawner`，且未命中大量运维例外。
- **含义与边界：** Web、数据库等服务突然启动 shell 可能关联命令执行；但后台任务、健康检查和配置脚本也可合法调用 shell。不是任何程序执行 bash 都会报警。
- **排查/调整：** 检查完整父子链和命令行，结合应用请求日志；查看 `protected_shell_spawning_binaries`、`user_known_shell_spawn_binaries`，例外尽量限定到具体任务。

### 05. `System user interactive`

**中文：系统服务账号执行交互相关命令。** 级别：INFO。[源码](../falco/official-rules/falco_rules.yaml#L689)

- **触发：** `bin/daemon/nobody/www-data` 等 `system_users` 账号执行程序，并符合 `interactive`：SSH 祖先进程或指定 login/logind 进程条件，且未被豁免。
- **含义与边界：** 服务账号交互登录值得审计，也可能是管理员排障。当前宏不是简单的“有 TTY”，也没有自动纳入所有低 UID 或所有服务账号。
- **排查/调整：** 对照登录来源、操作者及账号职责；在 `system_users` 和 `user_known_system_user_login` 中维护实际账号范围。

### 06. `Terminal shell in container`

**中文：容器中启动带终端的入口 shell。** 级别：NOTICE。[源码](../falco/official-rules/falco_rules.yaml#L713)

- **触发：** 容器中的 shell 执行事件具有非零 TTY，父进程符合 `container_entrypoint`，且不在预期例外中。
- **含义与边界：** 常见于交互式容器排障，也可能是未授权进入容器；不是所有容器 shell，也不能仅凭本条确认操作者身份。
- **排查/调整：** 查容器、终端及平台 exec 审计记录；通过 `user_expected_terminal_shell_in_container_conditions` 限定批准的场景。

### 07. `Contact K8S API Server From Container`

**中文：容器连接 Kubernetes API 地址。** 级别：NOTICE。[源码](../falco/official-rules/falco_rules.yaml#L827)

- **触发：** 容器发起 IPv4/IPv6 `connect`，服务端 IP 名称匹配 `kubernetes.default.svc.cluster.local`，排除已知 Kubernetes 容器和用户例外。
- **含义与边界：** 控制器合法调用 API 和被入侵应用探测 API 都可能满足条件；没有判断请求内容、授权结果或攻击是否成功。
- **排查/调整：** 先确认集群域名解析、容器元数据和实际 API 地址，再查服务账号及 API 审计。普通无 Kubernetes 的 Ubuntu 不具备默认触发环境；相关入口为 `k8s_api_server`、`user_known_contact_k8s_api_server_activities`。

### 08. `Netcat Remote Code Execution in Container`

**中文：容器内 Netcat 带执行命令参数。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L846)

- **触发：** 容器内执行名称为 `nc` 或 `ncat` 的程序，命令行含规则列出的执行选项，例如 `-e`、`-c` 或 `--exec`。
- **含义与边界：** 提示网络工具可能执行外部命令；这是名称和参数匹配，未确认远程连接或命令执行成功，不覆盖所有工具及变体。
- **排查/调整：** 查程序真实路径、参数、父进程和连接证据；合法网络测试也可能触发，不能只凭工具名直接定性。

### 09. `Search Private Keys or Passwords`

**中文：命令行搜索私钥特征。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L889)

- **触发：** grep 类程序参数含私钥头部特征，或 `find` 参数含 `id_rsa/id_dsa/id_ed25519/id_ecdsa`。通过 `grep_more` 扩展的通用密码词匹配默认关闭。
- **含义与边界：** 可能在搜集凭据，也可能是资产检查；它检查搜索命令，不检查磁盘全部内容，也不证明搜索找到了密钥。
- **排查/调整：** 查搜索范围、发起人及用途；关注 `private_key_or_password` 和 `grep_more`，不要将其宣传为任意密码搜索检测。

### 10. `Clear Log Activities`

**中文：以截断方式打开受监控日志。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L934)

- **触发：** 成功写打开 `access_log_files`，带 `O_TRUNC`，排除容器运行时、可信日志镜像及允许活动。
- **含义与边界：** 截断日志可能用于清理痕迹，也可能是正常日志维护。范围由目录和文件名名单决定，不是所有日志删除、轮转和清理方式都覆盖。
- **排查/调整：** 查日志轮转任务、目标文件、操作者；维护 `log_directories/log_files` 与 `allowed_clear_log_files`，注意缺失的应用日志路径。

### 11. `Remove Bulk Data from Disk`

**中文：执行名单中的数据清除工具。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L960)

- **触发：** 执行进程名匹配 `data_remove_commands`；本快照列出 `shred`、`mkfs`、`mke2fs`，并排除用户已知活动。
- **含义与边界：** 可能清除文件或重建文件系统，也可能是合法磁盘初始化。规则不统计删除量，普通 `rm` 不在这个名单中，报警文字不证明数据已经删除。
- **排查/调整：** 查目标设备/文件和变更单，维护 `user_known_remove_data_activities`；不要用真实磁盘执行破坏性命令验证本条。

### 12. `Create Symlink Over Sensitive Files`

**中文：创建指向敏感目标的符号链接。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L973)

- **触发：** `symlink/symlinkat` 的目标参数等于 `sensitive_file_names` 或 `sensitive_directory_names` 中的值，例如 shadow 或 `/etc`。
- **含义与边界：** 可能为间接访问敏感资源做准备，也可能是正常管理链接；名称中的“Over”不表示规则已验证覆盖原文件。相对路径、其他目标表达也不等于必然匹配。
- **排查/调整：** 对照 `target/linkpath`、系统调用结果及链接归属；维护敏感目标名单，不要只看新链接文件名。

### 13. `Create Hardlink Over Sensitive Files`

**中文：为敏感文件创建硬链接。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L985)

- **触发：** `link/linkat` 的 `oldpath` 等于敏感文件名单中的路径。
- **含义与边界：** 可能建立绕开原路径管理的另一入口，也可能来自备份操作；没有证明创建成功，内核权限限制仍可能拒绝调用。
- **排查/调整：** 查 `oldpath/newpath`、返回结果和 inode；调整 `sensitive_file_names` 时兼顾本名单被其他规则复用的影响。

### 14. `Packet socket created in container`

**中文：容器尝试创建二层套接字。** 级别：NOTICE。[源码](../falco/official-rules/falco_rules.yaml#L1000)

- **触发：** 容器中出现 `socket` 事件，地址族含 `AF_PACKET`，进程不在 `user_known_packet_socket_binaries` 中。
- **含义与边界：** 可用于抓包、二层网络操作或后续攻击，合法网络诊断也会使用；条件本身没有检查返回成功，不能据此认定已抓到数据。
- **排查/调整：** 查套接字返回结果、容器网络权限和程序来源；仅将经核实的抓包/监控任务加入受限例外。

### 15. `Redirect STDOUT/STDIN to Network Connection in Container`

**中文：容器标准输入输出关联网络连接。** 级别：NOTICE。[源码](../falco/official-rules/falco_rules.yaml#L1029)

- **触发：** 容器内 `dup/dup2/dup3` 返回描述符 0、1 或 2，关联的文件描述符类型为 IPv4/IPv6，且不在已知例外中。
- **含义与边界：** 可能把输入、输出或错误输出连接到远端，是反向 shell 的行为线索；合法远程执行服务也可能使用相同机制。
- **排查/调整：** 查远端地址、描述符、进程链及登录行为；使用 `user_known_stand_streams_redirect_activities` 收窄业务例外，不凭本条认定完整反向 shell 已建立。

### 16. `Linux Kernel Module Injection Detected`

**中文：有模块能力的容器尝试加载内核模块。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L1050)

- **触发：** 容器调用 `init_module/finit_module`，有效能力包含 `SYS_MODULE`，镜像不在允许列表中。
- **含义与边界：** 容器影响宿主内核的高风险行为，也可能是批准的驱动部署；规则并不只限定 `insmod/modprobe` 程序名，也没有要求加载成功。
- **排查/调整：** 检查 `evt.res`、模块来源、容器能力及镜像用途；维护 `allowed_container_images_loading_kernel_module`，不在真实主机加载未知模块做演示。

### 17. `Debugfs Launched in Privileged Container`

**中文：特权容器启动 debugfs。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L1064)

- **触发：** 已标记为 privileged 的容器执行进程名为 `debugfs` 的程序。
- **含义与边界：** 文件系统调试工具可能用于直接访问磁盘，也可能是存储维护；只检测程序执行特征，不证明逃逸，也不扫描其他磁盘工具。
- **排查/调整：** 查容器为什么需要特权、实际设备映射及工具参数；优先减少非必要特权，而不是整体关闭告警。

### 18. `Detect release_agent File Container Escapes`

**中文：容器写打开 release_agent 且具备相关能力。** 级别：CRITICAL。[源码](../falco/official-rules/falco_rules.yaml#L1077)

- **触发：** 容器成功写打开名称以 `release_agent` 结尾的文件，UID 为 0 或具备 `CAP_DAC_OVERRIDE`，并具备 `CAP_SYS_ADMIN`。
- **含义与边界：** 关联容器逃逸风险；条件只检查文件名后缀及能力，不证明目标一定是真实 cgroup 控制文件，也不证明逃逸成功。
- **排查/调整：** 核对完整路径、挂载来源、cgroup 环境和容器能力；区分测试普通文件与真实控制文件，不对真实控制文件做写入演示。

### 19. `PTRACE attached to process`

**中文：尝试跟踪或修改其他进程。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L1110)

- **触发：** `ptrace` 请求含 `ATTACH/SEIZE/POKETEXT/POKEDATA/SETREGS` 等指定类型，进程名存在且不在 `known_ptrace_procs` 中。
- **含义与边界：** 可能用于进程注入或操控，也可能是调试器/诊断工具；不要求攻击载荷存在，需另外检查调用是否成功。
- **排查/调整：** 查调用方与目标进程、调试授权及返回值；维护 `known_ptrace_binaries`，避免为所有跟踪行为设置宽泛例外。

### 20. `PTRACE anti-debug attempt`

**中文：进程调用 PTRACE_TRACEME。** 级别：NOTICE。[源码](../falco/official-rules/falco_rules.yaml#L1124)

- **触发：** `ptrace` 请求含 `PTRACE_TRACEME`，且进程名存在。
- **含义与边界：** 可能用于反调试，也可由正常调试流程中的被调试程序使用；单次调用不能证明程序是恶意软件或正在躲避分析。
- **排查/调整：** 查父进程是否为批准的调试工具、可执行文件来源及结果；需要例外时将程序和调试上下文一起限定。

### 21. `Find AWS Credentials`

**中文：命令行搜索 AWS 凭据特征。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L1145)

- **触发：** grep 类命令参数含 `aws_access_key_id/aws_secret_access_key/aws_session_token` 等字段，或 `find` 参数以 `.aws/credentials` 结尾。
- **含义与边界：** 可能寻找云凭据，也可能是密钥盘点；这不是检测任意方式读取 AWS 密钥，未确认命令找到了有效凭据。
- **排查/调整：** 查命令来源、搜索路径与审计任务；理解 `private_aws_credentials`，不要在测试中使用真实云密钥。

### 22. `Execution from /dev/shm`

**中文：执行路径或 shell 参数指向 /dev/shm。** 级别：WARNING。[源码](../falco/official-rules/falco_rules.yaml#L1159)

- **触发：** 执行事件的程序路径、工作目录与相对路径组合，或指定 shell 参数模式指向 `/dev/shm`；排除可信镜像。
- **含义与边界：** 可能从共享内存目录运行临时载荷，也可能是合法测试；不会因为文件只存在于该目录就触发，不保证覆盖所有执行方式。
- **排查/调整：** 查完整路径、文件来源和父进程；审查 `trusted_images/falco_privileged_images` 的例外范围，不能仅凭使用该目录就认定失陷。

### 23. `Drop and execute new binary in container`

**中文：容器执行可写上层中的程序。** 级别：CRITICAL。[源码](../falco/official-rules/falco_rules.yaml#L1185)

- **触发：** 容器执行事件满足 `proc.is_exe_upper_layer=true`，且不在允许镜像/活动中。
- **含义与边界：** 可提示基础镜像之外新放入或改动后的可执行文件；容器内安装软件、编译、排障也可能触发。依赖 overlayfs 及字段支持，不能据此覆盖所有运行时文件系统。
- **排查/调整：** 查镜像摘要、文件创建时间和安装记录；维护 `known_drop_and_execute_containers/known_drop_and_execute_activities`，不要仅以“能正常执行”判断可信。

### 24. `Disallowed SSH Connection Non Standard Port`

**中文：SSH 程序连接指定非标准端口。** 级别：NOTICE。[源码](../falco/official-rules/falco_rules.yaml#L1224)

- **触发：** 满足 `outbound` 的 TCP 连接，`proc.exe` 以 `ssh` 结尾，服务端端口在 `ssh_non_standard_ports` 中。
- **含义与边界：** 当前只列出 80、8080、88、443、8443、53、4444，**不是所有非 22 端口**；宏还排除了部分私网目的地址。合法跳板机或自定义端口也可能命中。
- **排查/调整：** 查真实可执行文件、目标地址、端口及隧道用途；按实际 SSH 策略维护端口列表，不把命中解释为已发现反向连接攻击。

### 25. `Fileless execution via memfd_create`

**中文：执行来自 memfd 的程序。** 级别：CRITICAL。[源码](../falco/official-rules/falco_rules.yaml#L1253)

- **触发：** 执行事件满足 `proc.is_exe_from_memfd=true`，且不符合已知进程、父进程或运行时路径例外。
- **含义与边界：** 提示内存文件执行，不是只调用 `memfd_create` 就报警；可用于规避落盘，也可能是合法运行时行为，不能直接判定内存中一定是恶意代码。
- **排查/调整：** 查程序来源和进程链，理解 `known_memfd_execution_processes` 与其二进制列表；例外需具体到可信执行路径与用途。

## 二、falco-sandbox_rules.yaml：25 条启用

本文件另外 12 条默认关闭，列在附录中，不混入启用规则编号。

### 26. `Update Package Repository`

**中文：非预期程序修改软件源配置。** 级别：NOTICE。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L590)

- **触发：** 写打开符合 `access_repositories` 的文件，或重命名/删除类事件符合 `modify_repositories`；排除包管理程序及其祖先进程、Docker save 和用户例外。
- **含义与边界：** 主要涉及 `/etc/apt`、`sources.list.d`、`yum.repos.d` 等，可能改变软件下载来源。正常切换镜像源也会命中；不是运行一次 `apt update` 就必然触发。
- **排查/调整：** 查源文件差异、操作者和软件仓库签名设置；维护 `repository_directories/repository_files`、`user_known_update_package_registry`。删除分支仍受 `newpath` 字段条件限制，不保证检测所有删除方式。

### 27. `Write below binary dir`

**中文：非预期程序写打开系统二进制目录中的文件。** 级别：ERROR。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L611)

- **触发：** `open_write` 且 `fd.directory` 等于 `/bin`、`/sbin`、`/usr/bin`、`/usr/sbin`，排除包管理和已知安装活动。
- **含义与边界：** 可能替换系统程序，也可能手动安装软件。这里的 `bin_dir` 是父目录精确匹配，不能把名称中的 below 理解为任意深度递归，更不等于已写入内容。
- **排查/调整：** 核对文件所属软件包、校验值与安装任务；使用 `user_known_write_below_binary_dir_activities` 设置窄范围例外。

### 28. `Write below monitored dir`

**中文：写打开启动、库文件或 SSH 相关目录中的文件。** 级别：ERROR。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L663)

- **触发：** `open_write` 命中 `monitored_directories` 的父目录精确匹配或用户 SSH 目录模式，排除包管理、cloud-init 等已知活动。
- **含义与边界：** 名单含 `/boot`、`/lib`、`/usr/lib`、`/usr/local/bin`、`/root/.ssh` 等；不是全盘监控，也不是对所有名单目录无限递归。正常安装和密钥管理也可能命中。
- **排查/调整：** 查目标文件职责与变更记录；入口为 `monitored_directories`、`user_known_write_monitored_dir_conditions`，注意与其他文件规则的重叠。

### 29. `Write below etc`

**中文：非预期程序写打开 /etc 下的配置文件。** 级别：ERROR。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L975)

- **触发：** `write_etc_common`：成功写打开 `/etc/` 下文件，进程名存在，且未命中包管理、网络管理、证书、配置管理等大量例外。
- **含义与边界：** 是宽泛的配置变更审计，不是“修改 /etc 就是攻击”。项目对 `/etc/tsa-protected-demo` 的写入可能命中本条，也可能同时满足第 82 条；实际输出受匹配策略影响。
- **排查/调整：** 查 `fd.name`、实际命令、配置差异及批准记录；按 `user_known_write_etc_conditions` 或 `user_known_write_below_etc_activities` 定向调优，不直接豁免整个 `/etc`。

### 30. `Write below root`

**中文：写打开根目录直属文件或 /root 下文件。** 级别：ERROR。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1054)

- **触发：** `open_write` 且 `fd.directory=/` 或文件路径以 `/root/` 开头，未命中已知文件、目录和活动例外。
- **含义与边界：** 用于观察 root 家目录及根目录异常落地；缓存和运维工具也会产生正常报警。不是所有以 `/` 开头的文件都触发。
- **排查/调整：** 查文件来源与父进程；项目已通过 `95-security-stack-exceptions.yaml` 豁免 `falcoctl` 写 `/root/.sigstore/`，用户扩展入口为 `user_known_write_below_root_activities`。

### 31. `Write below rpm database`

**中文：非 RPM 管理程序写打开 RPM 数据库路径。** 级别：ERROR。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1099)

- **触发：** 成功写打开路径前缀为 `/var/lib/rpm` 的文件，排除 RPM 工具、部分自动化和用户例外。
- **含义与边界：** 可能篡改软件包记录，也可能是管理任务；Ubuntu 通常使用 dpkg，本条不自动覆盖 `/var/lib/dpkg`。路径前缀匹配也不是数据库内容解析。
- **排查/调整：** 查主机是否实际使用 RPM、写入程序和数据库完整性；使用 `user_known_write_rpm_database_activities`，不为验证而破坏包数据库。

### 32. `Modify binary dirs`

**中文：删除或重命名系统二进制目录中的路径。** 级别：ERROR。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1121)

- **触发：** `modify` 即 rename/remove 类调用，相关路径参数以 `/bin/`、`/sbin/`、`/usr/bin/`、`/usr/sbin/` 开头，排除包管理等例外。
- **含义与边界：** 与第 27 条“写打开”不同，本条看路径删除/重命名；可关联程序替换，也可能是升级清理。不是任意 chmod 或内容修改。
- **排查/调整：** 核对旧路径、新路径、调用结果和软件更新记录；使用 `user_known_modify_bin_dir_activities` 限定例外。

### 33. `Mkdir binary dirs`

**中文：在系统二进制路径下创建目录。** 级别：ERROR。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1140)

- **触发：** `mkdir/mkdirat` 目标路径符合指定二进制目录前缀，排除包管理、Docker save 和已知活动。
- **含义与边界：** 可能是异常软件落地，也可能是安装器创建目录；条件不等于已经放入恶意程序，也没有在 `mkdir` 宏中要求成功。
- **排查/调整：** 查返回结果、目录归属和安装来源；入口为 `user_known_mkdir_bin_dir_activities`，留意前缀范围与第 27 条并不完全相同。

### 34. `Launch Sensitive Mount Container`

**中文：带敏感主机挂载的容器启动。** 级别：INFO。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1259)

- **触发：** 容器 PID 1 执行程序，挂载元数据命中 `sensitive_mount`，并非可信例外容器；名单涉及主机 `/proc`、运行时 socket、`/etc`、kubelet、根目录等来源。
- **含义与边界：** 提示暴露了敏感主机资源，但不证明资源被读取或利用。监控、备份、存储组件可能有合法需求；依赖容器挂载元数据。
- **排查/调整：** 核实挂载源、容器内目标、只读标记和镜像用途；维护 `user_sensitive_mount_containers`，不只看容器是否能正常运行。

### 35. `Launch Disallowed Container`

**中文：启动不在允许范围内的容器。** 级别：WARNING。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1284)

- **触发：** 容器 PID 1 执行程序且不符合 `allowed_containers`。
- **含义与边界：** **默认 `allowed_containers` 是 `container.id exists`，正常识别到的容器都会被允许，本条虽然启用，默认通常不会报警。** 这不是自动维护的恶意镜像库。
- **排查/调整：** 先定义本环境允许的镜像/工作负载，再覆盖 `allowed_containers`；没有制定允许范围，就不能宣称已实现容器准入检测。

### 36. `Detect crypto miners using the Stratum protocol`

**中文：命令行出现指定 Stratum 地址前缀。** 级别：CRITICAL。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1488)

- **触发：** 执行事件的命令行含 `stratum+tcp`、`stratum2+tcp`、`stratum+ssl` 或 `stratum2+ssl`。
- **含义与边界：** 是挖矿软件常见启动特征，但不是网络协议解析，也没有验证实际挖矿。教程、测试或合法矿工都可能命中，换参数表达方式也可能漏报。
- **排查/调整：** 查可执行文件、资源占用、连接和工作负载用途；不能只因规则名含“protocol”就当成已抓到矿池协议流量。

### 37. `Kubernetes Client Tool Launched in Container`

**中文：容器执行 Kubernetes/容器管理客户端。** 级别：WARNING。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1525)

- **触发：** 容器执行 `k8s_client_binaries` 中的程序，如 docker、kubectl、crictl，且未命中已知父进程例外。
- **含义与边界：** 业务容器中出现管理工具值得调查，CI/CD 或管理容器也可能正常使用；仅检测执行，不证明访问集群成功或进行了越权操作。
- **排查/调整：** 查命令参数、凭据来源、父进程和镜像用途；查看 `k8s_client_binaries`、`user_known_k8s_client_container_parens`。

### 38. `Sudo Potential Privilege Escalation`

**中文：sudo/sudoedit 出现特定可疑参数组合。** 级别：CRITICAL。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1618)

- **触发：** 登录 UID 不为 0，程序名为 sudo/sudoedit，参数含指定 shell/login 选项和反斜杠形式。
- **含义与边界：** 针对一类 sudo 提权尝试的字符串特征；不检查已安装版本或补丁，也不确认提权成功，登录 UID 条件不等于当前有效 UID 判断。
- **排查/调整：** 查实际参数、sudo 软件包版本及认证日志；不要照着特征在真实机器执行漏洞利用，也不能以“没报警”替代补丁检查。

### 39. `Unprivileged Delegation of Page Faults Handling to a Userspace Process`

**中文：非 root 程序使用 userfaultfd。** 级别：CRITICAL。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1636)

- **触发：** `userfaultfd` 事件，`user.uid != 0`，满足原条件 `(evt.rawres >= 0 or evt.res != -1)`，且程序不在已知名单中。
- **含义与边界：** 该机制可用于正常内存管理，也可能成为其他漏洞利用的辅助能力。本快照使用上述 OR 条件，不能只凭描述中的“successful”断言成功，须核对真实返回字段。
- **排查/调整：** 查程序用途、内核配置与返回结果；通过 `user_known_userfaultfd_processes` 管理经确认的正常使用者，告警本身不是提权证据。

### 40. `Polkit Local Privilege Escalation Vulnerability (CVE-2021-4034)`

**中文：非 root 登录上下文执行无参数 pkexec。** 级别：CRITICAL。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1651)

- **触发：** 执行事件中 `user.loginuid != 0`、`proc.name=pkexec`、`proc.args` 为空。
- **含义与边界：** 是特定漏洞相关的可疑启动形态，不检查 Polkit 版本、内存状态或实际提权；无参数调用、帮助测试也可能触发。
- **排查/调整：** 查软件包补丁、父进程和身份变化，区别“特征匹配”与“确认漏洞利用”；不要把本条当成漏洞扫描器。

### 41. `Decoding Payload in Container`

**中文：容器命令行包含 Base64 解码形式。** 级别：INFO。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1709)

- **触发：** 容器执行事件命令行含 `base64` 且含 `--decode` 或 `-d`，镜像不在允许名单中。
- **含义与边界：** 解码可能用于还原载荷，也广泛用于普通配置和数据处理；这是字符串匹配，不要求进程名一定是 base64，更不分析解码结果是否恶意。
- **排查/调整：** 查调用任务、输入来源及后续执行；入口为 `known_decode_payload_containers`，仅在明确业务边界内豁免。

### 42. `Basic Interactive Reconnaissance`

**中文：终端中直接执行基础系统查询命令。** 级别：NOTICE。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1731)

- **触发：** 执行 `w/whoami/id/who/uname` 等名单程序，有 TTY，且 `proc.is_vpgid_leader=true`。
- **含义与边界：** 是交互式侦察线索，也极常见于管理员排障；不是任何 `uname` 都触发，不代表执行查询的人已经入侵系统。
- **排查/调整：** 查终端会话、登录来源和相邻告警；按需调整 `recon_binaries`，不把基础查询一律视为应终止行为。

### 43. `Netcat/Socat Remote Code Execution on Host`

**中文：主机网络工具带执行外部命令特征。** 级别：WARNING。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1749)

- **触发：** 非容器中执行 `nc/ncat` 且带规则列出的执行参数，或执行 `socat` 且参数含 `EXEC/SYSTEM`。
- **含义与边界：** 是网络远程执行线索，也可能为批准的测试或转发工具；条件不验证网络连接成功。它与第 08 条的容器条件和工具范围不同。
- **排查/调整：** 查真实程序、命令、连接和父进程；参数包含判断可能较宽，不能把所有命中都直接解释为反向 shell。

### 44. `Network Tool Executed During NPM Package Install`

**中文：容器中的包管理进程链启动网络工具。** 级别：WARNING。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1788)

- **触发：** 容器执行 `network_tool_binaries` 中的程序，前 1～5 层祖先命中 `npm/yarn/pnpm/bun`，且不在用户例外中。
- **含义与边界：** 可关联供应链脚本行为，也可能是合法构建。实际条件**没有核对 install 参数**，名单也不包含普通 curl/wget；不能只按规则名理解为监控全部 NPM 下载。
- **排查/调整：** 查进程链、软件包生命周期脚本、锁文件和网络目标；通过 `user_known_network_tool_in_npm_install_activities` 设置有依据的例外。

### 45. `Known Cryptominer Process Executed`

**中文：执行名称命中矿工程序名单。** 级别：CRITICAL。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1826)

- **触发：** 执行事件的 `proc.name` 在 `miner_binaries` 中，如 xmrig、minerd、ethminer 等。
- **含义与边界：** 是进程名称检测，不校验文件哈希、挖矿协议或运算行为；改名可能漏报，正常程序使用相同名称也可能误报。
- **排查/调整：** 查程序真实路径、哈希、来源、资源占用及连接；维护名单时，不把名称检测宣称为任意矿工识别。

### 46. `Web Server Spawned Shell`

**中文：Web 服务进程链启动 shell。** 级别：CRITICAL。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1858)

- **触发：** 前 1～3 层祖先匹配 `web_server_binaries`，执行程序名在 shell 名单中；排除命令行以 `sh -c /usr/bin` 开头、含 `healthcheck` 或用户例外的情况。
- **含义与边界：** 可能来自 Web 命令执行，也可能是 CGI 或应用任务。虽然描述提到 interactive，实际条件**不要求 TTY**；宽泛字符串例外也是检测边界。
- **排查/调整：** 对照请求、应用任务和进程链；使用 `user_known_web_server_shell_activities` 精确调整，不仅看直接父进程。

### 47. `Web Server Spawned Suspicious Child Process`

**中文：Web 服务进程链执行可疑工具或解释器。** 级别：WARNING。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1880)

- **触发：** 前 1～3 层祖先匹配 Web 服务，程序名在 `suspicious_web_children` 中且不是 shell；排除含 `healthcheck/status` 的命令行和用户例外。
- **含义与边界：** 名单包括 curl、wget、Python、网络工具和部分查询工具；合法应用生成文件、调用脚本也可能触发，不证明下载或外传成功。
- **排查/调整：** 查调用接口、业务需求和工具参数；维护 `user_known_web_server_child_activities`，留意字符串例外可能漏掉其他行为。

### 48. `Reverse Shell from Web Server`

**中文：Web 服务进程链出现常见反向 shell 字符串。** 级别：CRITICAL。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1900)

- **触发：** 符合 Web 祖先进程条件，命令行包含规则列出的网络 shell、解释器 socket 或临时管道组合特征。
- **含义与边界：** 比普通子进程审计更具体，但仍是命令行模式检测，不验证 socket 建立或远端控制；合法测试及作为文本参数传入的内容也可能命中。
- **排查/调整：** 关联网络连接、终端、应用请求和进程树，区别实际执行与文本传递；不依赖单一字符串规则覆盖所有反向连接方式。

### 49. `Privileged Container Device Access`

**中文：容器读写打开磁盘或内存设备路径。** 级别：CRITICAL。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1927)

- **触发：** 容器满足 `open_read/open_write`，路径前缀为 `/dev/sd`、`/dev/nvme`、`/dev/vd`、`/dev/xvd` 或等于 `/dev/mem`、`/dev/kmem`，且未被豁免。
- **含义与边界：** 名称虽有 Privileged，条件**没有要求 `container.privileged=true`**。open 宏检查 Falco 文件型描述符，但本条不核验设备主次编号或实际设备映射，同名前缀普通文件也可能命中；不能仅凭路径报警证明访问了宿主磁盘。
- **排查/调整：** 必须核对实际文件类型、设备映射、采集字段和返回结果，区分“路径匹配演示”与“真实设备访问检测”；调整入口为 `user_known_privileged_device_access`。

### 50. `Container Access to Host Sensitive Paths`

**中文：容器访问常见主机挂载前缀。** 级别：WARNING。[源码](../falco/official-rules/falco-sandbox_rules.yaml#L1957)

- **触发：** 容器成功读写打开 `/host/`、`/rootfs/`、`/hostfs/` 下符合 open 宏的文件，排除已知运行时程序及用户例外。
- **含义与边界：** 可提示容器接触主机资源，监控/备份容器也会使用。它按路径匹配，**没有验证该路径真的来自主机挂载**，也不会自动识别其他挂载别名。
- **排查/调整：** 对照挂载源和目标文件，查看 `known_container_runtime_host_access` 与 `user_known_host_path_access`；不要用一个普通 `/host` 测试目录证明已覆盖真实逃逸。

## 三、falco-incubating_rules.yaml：31 条

### 51. `Modify Shell Configuration File`

**中文：非 shell 程序写打开 shell 配置。** 级别：WARNING。[源码](../falco/official-rules/falco-incubating_rules.yaml#L258)

- **触发：** 写打开符合 `shell_config_filenames/files/directories` 的文件，排除 shell 程序、Docker save 和已知修改者。
- **含义与边界：** 可提示通过 shell 启动配置建立持久化，也可能是正常环境配置。**shell 自身写入被排除**，因此不能保证检测所有重定向修改；也不分析写入内容。
- **排查/调整：** 对照文件差异、修改程序及用户操作；查看 `user_known_shell_config_modifiers`，不要因文件名敏感就忽略正常安装上下文。

### 52. `Schedule Cron Jobs`

**中文：访问 cron 配置或执行 crontab。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L280)

- **触发：** 成功写打开路径前缀为 `/etc/cron` 的文件，或执行程序名为 `crontab`，排除 `user_known_cron_jobs`。
- **含义与边界：** 可能新增定时持久化，也可能只是查询或维护；规则没有区分 crontab 的查询与修改参数，也不是扫描所有定时任务机制。
- **排查/调整：** 核对实际命令、任务内容和变更单；读取列表不等于新增任务，systemd timer 等其他机制不在本条直接条件中。

### 53. `Read ssh information`

**中文：非 SSH 工具读取 SSH 目录信息。** 级别：ERROR。[源码](../falco/official-rules/falco-incubating_rules.yaml#L362)

- **触发：** 成功读打开文件或目录，路径符合 `/home/*/.ssh/*` 模式或以 `/root/.ssh` 开头，程序不在 `ssh_binaries` 和用户例外中。
- **含义与边界：** 可能搜集 SSH 密钥和配置，也可能是备份、索引或管理脚本；不是每个被读取文件都是私钥，自定义家目录也可能不在范围内。
- **排查/调整：** 查具体文件、程序来源和操作者；使用 `user_known_read_ssh_information_activities` 限定例外，不把整个 SSH 目录无条件放行。

### 54. `DB program spawned process`

**中文：数据库服务执行非数据库子程序。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L388)

- **触发：** 执行事件的直接父进程在 `db_server_binaries` 中，子进程不在同一名单，排除 PostgreSQL WAL-E 和用户例外。
- **含义与边界：** 可能由数据库命令执行或注入引起，也可能是备份/归档任务；没有分析 SQL，也不证明注入发生。
- **排查/调整：** 对照数据库任务、审计日志与子程序命令；入口为 `user_known_db_spawned_processes`，不要直接给数据库启动的所有程序放行。

### 55. `Change thread namespace`

**中文：非预期程序调用 setns。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L418)

- **触发：** 出现 `setns` 事件、进程名存在，且未命中容器运行时、网络插件、监控工具及用户例外。
- **含义与边界：** 可关联命名空间切换或逃逸尝试，也可来自正常容器管理。**主机上的 nsenter 在已有例外中**；本条不保证所有 nsenter 都报警，也没有确认进入了主机空间。
- **排查/调整：** 查调用返回结果、目标命名空间、进程所在容器和祖先进程；入口为 `user_known_change_thread_namespace_binaries/activities`。

### 56. `Change namespace privileges via unshare`

**中文：缺少 SYS_ADMIN 许可能力的容器调用 unshare。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L444)

- **触发：** 容器出现 `unshare` 事件，许可能力中不含 `CAP_SYS_ADMIN`。
- **含义与边界：** 可提示创建隔离环境或为后续行为准备权限上下文；正常沙箱也会调用。条件**没有检查具体 flags，也没有要求成功**，不能直接解释为已经获得新权限。
- **排查/调整：** 查请求 flags、返回结果、容器用途和用户命名空间配置；需要限制行为时另用相应内核策略，Falco 本条本身不会阻断。

### 57. `Launch Privileged Container`

**中文：启动特权容器。** 级别：INFO。[源码](../falco/official-rules/falco-incubating_rules.yaml#L603)

- **触发：** 容器 PID 1 执行程序，`container.privileged=true`，排除 Falco、用户指定可信容器和 `redhat_image` 例外。
- **含义与边界：** 记录高权限部署形态，不等于容器已经实施攻击；批准的宿主维护组件可能正常需要特权，识别依赖容器元数据。
- **排查/调整：** 查工作负载定义、部署人、挂载和能力，使用 `user_privileged_containers` 管理少量批准例外，优先去掉不必要的 privileged。

### 58. `Launch Excessively Capable Container`

**中文：容器启动时具备名单中的高风险能力。** 级别：INFO。[源码](../falco/official-rules/falco-incubating_rules.yaml#L632)

- **触发：** 容器 PID 1 执行程序，许可能力含 `SYS_ADMIN/SYS_MODULE/SYS_RAWIO/SYS_PTRACE/SYS_BOOT/SYSLOG/DAC_READ_SEARCH/NET_ADMIN/BPF` 中任意一种，排除可信容器。
- **含义与边界：** 不要求 `privileged=true`，只要具备其中一种能力即可；这是能力配置审计，不证明能力已被使用，也可能是正常网络/观测组件。
- **排查/调整：** 对照实际 capability 配置和职责；查看 `excessively_capable_container` 与 `user_privileged_containers`，以最小权限为目标调优。

### 59. `System procs network activity`

**中文：通常不应联网的系统程序出现连接活动。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L652)

- **触发：** 符合 `inbound_outbound`、IP 套接字，进程属于 `system_procs` 或 shell 名单，且未命中已知程序、登录 DNS 等例外。
- **含义与边界：** 可关联程序被滥用或异常网络操作，也可能是合法脚本；不是所有系统服务，也不是全量数据包监测。
- **排查/调整：** 查真实可执行文件、远端和命令，维护 `known_system_procs_network_activity_binaries`、`user_expected_system_procs_network_activity_conditions`。

### 60. `Program run with disallowed http proxy env`

**中文：curl/wget 执行时环境中出现 HTTP_PROXY 字样。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L693)

- **触发：** 执行 `http_proxy_binaries` 中的 curl/wget，`proc.env` 不区分大小写包含 `HTTP_PROXY`，且不符合 `allowed_ssh_proxy_env`；该例外默认不匹配。
- **含义与边界：** **不是已经发现恶意代理，也没有实际比较代理地址是否批准。** 合法网络代理环境同样会报警，即使本次命令访问本机接口或没有实际使用代理。
- **排查/调整：** 核对环境变量来源和值、实际目标和公司代理要求；对已批准场景收窄 `allowed_ssh_proxy_env`，不要因为报警就盲目取消正常联网配置。

### 61. `Unexpected UDP Traffic`

**中文：UDP 连接类事件使用名单外端口。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L735)

- **触发：** `inbound_outbound` 事件的传输协议为 UDP，端口不在 `expected_udp_ports` 中；允许列表包含 DNS 及若干 VPN、时间同步、指标端口。
- **含义与边界：** 可能是异常通信，也可能是应用使用自定义端口。这里的宏不等于捕获每次 UDP send/receive，不能保证发现所有 UDP 数据流。
- **排查/调整：** 查程序、双方端口、协议用途与实际事件类型；按业务维护 `expected_udp_ports`，不能把“名单外”直接等同恶意。

### 62. `Non sudo setuid`

**中文：非名单程序调用 setuid 切换身份。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L777)

- **触发：** `setuid` 事件，主机进程或用户可识别的容器进程，当前用户字段不是 root，且不属于已知用户切换工具、指定自切换和其他例外。
- **含义与边界：** 不等于 chmod 设置 SUID 位，也不一定是在提权；桌面认证、应用降权等合法身份切换可能命中。须结合事件中的用户和目标 UID 判断。
- **排查/调整：** 查 `evt.arg.uid`、返回结果、程序来源和认证日志；例如 `gdm-session-wor` 报警应先核实桌面登录，例外入口为 `user_known_non_sudo_setuid_conditions`。

### 63. `User mgmt binaries`

**中文：主机执行用户管理工具。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L805)

- **触发：** 非容器中执行 `user_mgmt_binaries` 的程序，排除 su/sudo、若干查询命令、系统任务及已知自动化。
- **含义与边界：** 是账号管理活动审计，可能新增账号或修改权限，也可能是正常运维；不是监控全部身份变化，容器启动时建用户被条件排除。
- **排查/调整：** 查命令、操作者和账号文件变化；使用 `user_known_user_management_activities`，不要把全部用户管理程序当作必须禁用的工具。

### 64. `Create files below dev`

**中文：非预期程序在 /dev 直属目录创建文件。** 级别：ERROR。[源码](../falco/official-rules/falco-incubating_rules.yaml#L842)

- **触发：** `creat/open/openat/openat2` 带 `O_CREAT`，`fd.directory=/dev`，排除设备管理程序、允许文件、`/dev/tty` 前缀及用户例外。
- **含义与边界：** 可能在设备目录藏普通文件，也可能是初始化；只限直属父目录，**不等于递归监控整个 `/dev`**，不能用它替代 `/dev/shm` 执行检测。
- **排查/调整：** 查文件类型、创建者、结果与启动任务；入口为 `allowed_dev_files` 和 `user_known_create_files_below_dev_activities`。

### 65. `Contact EC2 Instance Metadata Service From Container`

**中文：容器连接常见实例元数据地址。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L873)

- **触发：** 容器满足 `outbound`，服务端 IP 为 `169.254.169.254`，不属于 `ec2_metadata_containers` 例外。
- **含义与边界：** 可能访问实例身份或配置，也可为正常云代理；没有解析 HTTP 路径、身份令牌或响应，也没有证明目标确实是 EC2 服务。
- **排查/调整：** 确认运行环境、程序职责、请求记录和元数据访问策略；按需维护例外，并与下一条重复条件一起评估。

### 66. `Contact cloud metadata service from container`

**中文：容器连接通用元数据地址。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L893)

- **触发：** 容器满足 `outbound` 且服务端 IP 为 `169.254.169.254`，不符合 `user_known_metadata_access`。
- **含义与边界：** 与第 65 条的主条件基本相同，主要区别是例外宏；**不是两次独立攻击的证明**。first 匹配可能只输出其中一条，all 匹配可能出现两条证据。
- **排查/调整：** 查真实云环境及访问用途，统一审查两个例外范围；它不是覆盖所有云厂商、所有元数据域名的完整规则。

### 67. `Launch Package Management Process in Container`

**中文：容器执行包管理工具。** 级别：ERROR。[源码](../falco/official-rules/falco-incubating_rules.yaml#L928)

- **触发：** 容器执行包管理程序，用户不是 `_apt`，祖先不属于包管理程序链，且没有命中用户或 kube-proxy 等例外。
- **含义与边界：** 可能是在已入侵容器中安装工具，也可能是初始化或排障；不证明成功安装了新包，也不检查软件包是否恶意。
- **排查/调整：** 查镜像构建策略、任务和包管理日志；使用 `user_known_package_manager_in_container` 调优，优先通过镜像构建管理运行环境变化。

### 68. `Launch Suspicious Network Tool in Container`

**中文：容器执行名单中的网络工具。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L949)

- **触发：** 容器执行 `network_tool_binaries` 中的程序，如 nc、nmap、dig、tcpdump、socat，且未命中用户例外。
- **含义与边界：** 是较宽的工具执行审计，不要求危险参数或实际通信；普通 DNS 查询和抓包排障也会触发。
- **排查/调整：** 查命令、执行人和容器用途；使用 `user_known_network_tool_activities` 限定批准任务，不按 Suspicious 字样直接认定攻击。

### 69. `Launch Suspicious Network Tool on Host`

**中文：主机执行名单中的网络工具。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L963)

- **触发：** 与第 68 条相似，但要求 `not container`。
- **含义与边界：** 虽然原描述有容器措辞，**实际 condition 明确针对主机**。运维网络诊断是常见正常场景，不代表检测到了端口扫描或数据外传。
- **排查/调整：** 查操作者、工具参数及目标；与容器版本共用 `user_known_network_tool_activities`，修改时同时评估两条的影响。

### 70. `Delete or rename shell history`

**中文：删除、重命名或截断匹配的 shell 历史文件。** 级别：WARNING。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1010)

- **触发：** `modify_shell_history` 或 `truncate_shell_history` 命中 ash/bash、zsh、fish 的相关后缀模式；排除 Docker 路径/程序。
- **含义与边界：** 可能清理痕迹，也可能是 shell 退出时更新历史。`ash_history` 后缀同样可匹配 `bash_history`；不是监控所有历史文件和所有内存中清理方式。
- **排查/调整：** 核对原/新路径、截断标志、终端退出时间与相邻操作；不要把正常历史写回和蓄意删证据混为一谈。

### 71. `Set Setuid or Setgid bit`

**中文：chmod 参数包含 SUID/SGID 位。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1038)

- **触发：** chmod 类事件的 mode 含 `S_ISUID` 或 `S_ISGID`，排除已知 chmod 程序、Docker save 和用户例外。
- **含义与边界：** 是文件权限位调整，不是第 62 条的进程身份切换。合法软件安装、目录 SGID 共享权限也可能命中；条件未比较旧权限，不能证明此次新增加了权限位。
- **排查/调整：** 查目标是否普通文件或目录、原权限和返回结果；使用 `user_known_set_setuid_or_setgid_bit_conditions` 精确调优。

### 72. `Launch Remote File Copy Tools in Container`

**中文：容器执行远程文件复制工具。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1066)

- **触发：** 容器执行 `rsync/scp/sftp/dcp` 等 `remote_file_copy_binaries` 中的工具，且不在已知活动中。
- **含义与边界：** 可能传出文件，也可能是正常同步；仅执行工具不证明发生传输，条件也没有判断上传、下载或传输内容。
- **排查/调整：** 查源路径、目的地、凭据及业务任务；通过 `user_known_remote_file_copy_activities` 调整，外传结论需要网络和文件证据。

### 73. `Network Connection outside Local Subnet`

**中文：指定命名空间的容器连接名单外网络。** 级别：WARNING。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1095)

- **触发：** 容器满足 `inbound_outbound`，`k8s.ns.name` 在 `namespace_scope_network_only_subnet` 中，且不符合 `network_local_subnet`。
- **含义与边界：** **命名空间列表默认是空的，因此默认没有监控目标。** 此处 local subnet 实际依据 RFC1918 私网等条件，不是自动读取 Ubuntu 网卡掩码计算“本地子网”。
- **排查/调整：** 先填实际命名空间并确认元数据，再按业务修订 `network_local_subnet`；正常调用外部 API 也可能命中，不能用于宣称默认已限制所有容器联网。

### 74. `Mount Launched in Privileged Container`

**中文：特权容器执行非纯查询形式的 mount。** 级别：WARNING。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1130)

- **触发：** privileged 容器执行名为 `mount` 的程序，排除无参数、指定信息/帮助参数及已知云平台和用户例外。
- **含义与边界：** 可能试图挂载主机资源，也可能是存储维护；检测的是程序执行，**不是所有 mount 系统调用**，也不证明挂载成功。
- **排查/调整：** 查设备、挂载点、参数和容器授权；使用 `user_known_mount_in_privileged_containers`，不要仅因工具启动就宣称逃逸成功。

### 75. `Launch Ingress Remote File Copy Tools in Container`

**中文：容器执行 wget 或带保存文件参数的 curl。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1167)

- **触发：** 容器执行 `wget`，或 curl 命令符合 `-o/--output/-O/--remote-name` 的指定形式，排除已知用户活动。
- **含义与边界：** 可能下载后续载荷，也可能是合法依赖获取；不是所有 curl 都匹配，也没有校验下载内容或确认传输成功。
- **排查/调整：** 查下载地址、保存位置、校验值及是否后续执行；通过 `user_known_ingress_remote_file_copy_activities` 限定业务例外。

### 76. `Read environment variable from /proc files`

**中文：容器程序读打开进程环境文件。** 级别：WARNING。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1187)

- **触发：** 容器成功读打开符合 `/proc/*/environ` 的文件，程序名不在允许列表中。
- **含义与边界：** 环境中可能存在密钥，也可能只是应用读取自身配置；条件没有要求读取其他进程，也没有检查文件中实际是否有秘密。
- **排查/调整：** 对照读取者与目标 PID、容器 PID 命名空间和程序用途；维护 `known_binaries_to_read_environment_variables_from_proc_files`，同时避免把真实秘密长期放入环境。

### 77. `Exfiltrating Artifacts via Kubernetes Control Plane`

**中文：容器入口 tar 无终端读取非排除路径。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1223)

- **触发：** 容器中的 `tar` 符合 `container_entrypoint`、TTY 为 0，成功读打开文件，排除 `/etc`、`/proc`、`/lib`、`/run`、`/usr` 等系统副作用路径。
- **含义与边界：** 可对应 `kubectl cp` 获取文件，也可由其他入口 tar 操作产生；条件没有验证 Kubernetes API 调用、操作者或实际外传成功。
- **排查/调整：** 结合平台 exec/cp 审计、文件路径和授权记录；查看 `system_level_side_effect_artifacts_kubectl_cp`，不要把排除路径误认为已被完整监控。

### 78. `Adding ssh keys to authorized_keys`

**中文：非 SSH 工具写打开 authorized_keys。** 级别：WARNING。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1241)

- **触发：** 成功写打开用户 SSH 路径模式或 `/root/.ssh` 前缀下、名称以 `authorized_keys` 结尾的文件，进程不在 `ssh_binaries` 中。
- **含义与边界：** 可能添加持久化访问，也可能是正常密钥发放；条件仅表示写打开，**没有验证新增了一把密钥**，也不覆盖所有自定义密钥路径。
- **排查/调整：** 对照文件差异、密钥指纹、账号和变更记录；自动化密钥管理应按任务上下文设置例外，而非给所有写入程序放行。

### 79. `Potential Local Privilege Escalation via Environment Variables Misuse`

**中文：执行环境中出现 GLIBC_TUNABLES 字样。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1262)

- **触发：** 执行事件的 `proc.env` 不区分大小写包含 `GLIBC_TUNABLES`。
- **含义与边界：** 是非常宽的环境特征，正常运行时调优也会命中；不检查变量值是否构成利用、不检查 glibc 版本，更不确认提权。
- **排查/调整：** 查变量来源、具体值、父进程和软件补丁；若需更窄检测，应针对本环境分析后覆盖条件，不能把所有包含该变量的程序都认定恶意。

### 80. `Backdoored library loaded into SSHD (CVE-2024-3094)`

**中文：sshd 读打开指定版本名称的 liblzma 文件。** 级别：WARNING。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1277)

- **触发：** `proc.name=sshd`，成功读打开名称含 `liblzma.so.5.6.0` 或 `liblzma.so.5.6.1` 且符合 open 宏的文件。
- **含义与边界：** 是与特定供应链事件相关的文件名启发式；**不验证文件哈希、后门内容或是否真正加载执行**，同名测试文件也可能命中。
- **排查/调整：** 查实际文件来源、软件包签名、版本与加载证据；不要通过更名文件来“修复”风险，也不能把本条当作后门鉴定工具。

### 81. `BPF Program Not Profiled`

**中文：未列入名单的程序尝试加载 BPF 程序。** 级别：NOTICE。[源码](../falco/official-rules/falco-incubating_rules.yaml#L1293)

- **触发：** `bpf` 调用的 cmd 为 5 或 `BPF_PROG_LOAD`，进程名不在 `bpf_profiled_binaries` 中。
- **含义与边界：** 是 BPF 使用审计，正常观测工具也可能命中；**不是所有 bpf 调用，不验证程序恶意性或加载成功**。本快照实际 condition 没有描述中所说的显式方向过滤，解释以 condition 为准。
- **排查/调整：** 查工具来源、加载目的及结果；官方名单含 falco、bpftool、systemd。本规则检测异常 BPF 加载，不是项目阻断功能。

## 四、项目规则：1 条

### 82. `Monitor specific file access`

**中文：打开项目演示文件。** 级别：WARNING。[源码](../falco/rules.d/90-local-file-monitoring.yaml#L1)

- **触发：** `open/openat/openat2`，`fd.name` 恰好为 `/etc/tsa-protected-demo`，且以读或写方式打开。
- **含义与边界：** 用于演示检测链路；没有恶意进程或用户判断，合法 cat/tee 也可能报警。**它没有复用 `open_read/open_write`，也没有显式要求成功返回**；不能因报警就断言文件已经被读写成功。
- **排查/调整：** 查目标文件、进程、时间与返回结果，将告警和自己的测试操作对齐。更换目标可修改本项目规则并重新部署。演示文件名称沿用历史名称，现在仅用于检测，不受本项目阻断保护。

## 五、怎样判断一条报警

1. **找规则：** 用英文 `rule` 名称找到本文条目，不只看网页中文标题。
2. **对操作：** 对齐事件时间及其时区、进程、完整命令、文件/网络目标、容器和返回结果。旧版日志字段不完整时，不凭进程名推断一定是自己的测试。
3. **看上下文：** 确认是登录、代理、软件安装、备份等已知任务，还是无法解释的访问；一条报警不是入侵结论。
4. **分清记录：** 同一操作可符合多条规则，同一程序也可能反复打开不同文件；事件数量不是攻击次数。TSA 扣 0 分可能是同规则风险续期、已达总分下限、过期、维护或未配置计分，不代表这条检测不存在。
5. **再调整：** 只针对证据充分的正常行为增加有边界的例外。不要因为某条很吵就删除所有证据，也不要把调低评分当成修复检测。

## 六、在哪里修改

- **新增规则或覆盖条件：** 仓库 [falco/rules.d/91-custom-rules.yaml](../falco/rules.d/91-custom-rules.yaml)，也可在同目录新增 YAML。使用受支持的 `override` 方式追加/替换已有 macro/list/condition，不要直接编辑带校验的官方文件。
- **默认规则选择：** [89-host-profile.yaml](../falco/rules.d/89-host-profile.yaml) 覆盖官方规则开关；添加规则时同时评估是否应在 TSA 中配置分值。
- **项目自带例外：** [95-security-stack-exceptions.yaml](../falco/rules.d/95-security-stack-exceptions.yaml) 只豁免相关 Falco 报警；本项目没有 BPF 文件保护。本文提到的 `user_known_*` 多为调优入口，并不代表默认已配置业务白名单。
- **安装路径：** `/etc/falco/falco.yaml` 的 `rules_files` 指向 `/etc/falco/security-stack/rules/<规则包ID>/official/`、`custom/` 等实际文件；额外主机规则、服务 `-r` 参数和优先级设置也可能改变实际加载效果。
- **生效步骤：** 按 [规则指南](FALCO_RULES.md#4-自定义规则怎么添加) 校验并重新部署。不要只修改安装副本，也不要把 GitHub 页面更新理解为 Ubuntu 上自动更新。
- **扣分而非检测：** [tsa/policy_config.yaml](../tsa/policy_config.yaml) 控制 TSA 评分。评分配置不改变 Falco 检测条件，也不会触发阻断。

## 附录：原始快照关闭的 12 条规则

以下全部位于 [falco-sandbox_rules.yaml](../falco/official-rules/falco-sandbox_rules.yaml)，原始定义均设置 `enabled: false`，目前继续关闭。加上本次关闭的 52 条，项目默认共关闭 64 条；启用前需单独评估条件、字段、噪声和环境。

| 规则名 | 用途与启用前注意事项 |
|---|---|
| `Unexpected inbound connection source` | 检测允许 IP/网段/域名以外的入站来源；需先定义允许范围。 |
| `Read Shell Configuration File` | 非 shell 程序读 shell 配置；正常索引/备份可能很频繁。 |
| `Interpreted procs inbound network activity` | 解释器程序的入站活动；合法服务很多。 |
| `Interpreted procs outbound network activity` | 解释器程序的出站活动；需建立业务基线。 |
| `Unexpected K8s NodePort Connection` | 容器连接类事件涉及 30000～32767 服务端端口；范围未必等于实际集群配置。 |
| `Create Hidden Files or Directories` | 创建或重命名到隐藏路径；大量正常软件也使用点文件。 |
| `Detect outbound connections to common miner pool ports` | 矿池相关网络特征；还要评估规则域名解析带来的 DNS 活动。 |
| `Container Drift Detected (chmod)` | 容器 chmod 设置可执行位；不等于程序已执行。 |
| `Container Drift Detected (open+create)` | 容器通过指定打开/创建事件形成可执行文件；需核对字段支持。 |
| `Container Run as Root User` | 容器 PID 1 以 UID 0 执行；不等于 privileged 或已逃逸。 |
| `Java Process Class File Download` | Java 网络读取缓冲区含 class 魔数；依赖事件/缓冲区采集，不是完整漏洞判定。 |
| `Modify Container Entrypoint` | 容器写打开特定 `/proc/self/exe` 或 fd 路径；条件范围窄，不是所有入口修改。 |

**维护约定：** 本文编号只是阅读顺序，不是 Falco 的运行时规则 ID。后续更换规则快照或修改开关时，应重新核对数量和条目；不要为了凑成 83 条而虚构一条旧仓库不存在的规则。
