# Ubuntu 复现指南

适用 Ubuntu 22.04 x86_64、systemd、可 sudo 的普通用户。建议虚拟机 2 核、4 GB 内存，操作前做快照。
在 Ubuntu 的普通用户终端逐条执行；提示 sudo 密码时输入该用户密码。项目放在用户家目录，路径不要含空格或中文；需要能访问 Ubuntu 软件源、Falco 软件源和 GitHub。
本项目只做 **Lynis 基线检测 + Falco 告警 + TSA 评分**，不阻断、不终止进程；无需安装 Go 或启用 BPF LSM。

验证范围：上一版 `17037ca` 在全新 Ubuntu Server 22.04.5（5.15.0-190 内核）完成克隆部署及重启验证。当前版本于 2026-09-20 在 2IIE-OS（Ubuntu 22.04.5、6.8.0-60 内核）通过 120 项回归、真实部署扫描、定时扫描自动更新评分及告警扣分验收。9 月 18 日另验证了 3 条规则、权重接口和故障恢复。当前版本没有重新在新装系统验证，也不是全部 30 条规则攻击实测；不同主机仍须完成第 4 节验收。

## 1. 准备依赖

**命令 1.1：更新软件包索引。**
```bash
sudo apt-get -o APT::Update::Error-Mode=any update
```

**命令 1.2：安装依赖。**
```bash
sudo apt-get install -y ca-certificates curl gnupg git python3-yaml jq lynis logrotate update-notifier-common
```

**命令 1.3：检查 Falco 采集所需的 BTF，预期输出 BTF OK。**
```bash
test -r /sys/kernel/btf/vmlinux && echo "BTF OK" || echo "BTF MISSING"
```

BTF OK 是初步检查，最终以第 4 节真实告警验收为准。BTF 缺失或 Falco 提示内核不支持时，安装 `linux-generic-hwe-22.04` 并重启后重试；**不修改 GRUB 的 LSM 配置**。

APT 出现 403 时先修复对应软件源；第三方源握手失败应修复网络或临时禁用该源，不要关闭签名或 TLS 验证。

## 2. 安装 Falco

已安装 Falco 0.44.1 时可跳过本节。以下使用[官方签名软件源](https://falco.org/docs/setup/packages/)与 modern eBPF 驱动。

**命令 2.1：下载公钥。**
```bash
curl -fL --retry 3 https://falco.org/repo/falcosecurity-packages.asc -o /tmp/falcosecurity.asc
```

**命令 2.2：安装公钥。**
```bash
sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg /tmp/falcosecurity.asc
```

**命令 2.3：添加软件源。**
```bash
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main' | sudo tee /etc/apt/sources.list.d/falcosecurity.list
```

**命令 2.4：更新索引。**
```bash
sudo apt-get -o APT::Update::Error-Mode=any update
```

**命令 2.5：安装 Falco。**
```bash
sudo env FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf FALCOCTL_ENABLED=no apt-get install -y falco=0.44.1
```

若指定版本不可用，先查明软件源及可用版本，不要跳过版本兼容验证。Falco 使用 eBPF 采集系统调用，这不是被移除的 BPF LSM 阻断组件。

## 3. 克隆并部署

**命令 3.1：克隆。已有本仓库时使用第 5 节更新，不覆盖原目录。**
```bash
git clone https://github.com/rrenziho333-bot/linux-runtime-security-stack.git
```

**命令 3.2：进入项目；后续命令在此目录运行。**
```bash
cd linux-runtime-security-stack
```

**命令 3.3：确认日期和时间正确，否则先校时。**
```bash
timedatectl
```

**命令 3.4：部署，等待命令返回；首次基线扫描可能需要数分钟。**
```bash
sudo ./deploy-security-stack.sh
```

部署自动运行回归测试、安装 30 条启用规则、刷新 APT 索引、完成首次 Lynis 扫描、安装定时器并启动服务。扫描失败时部署报错，先修复原因再重试，不把失败当作部署成功。`long execution` 仅表示某项检查较慢。

不再手动生成项目目录里的报告；统一报告为 `/var/lib/tsa-baseline/lynis-report.dat`，由 root 生成，TSA 通过 adm 组只读。部署会停用软件包自带的 `lynis.timer`，改由本项目定时器接管，避免扫描与评分读取不同文件。

## 4. 验收

部署返回后，在同一个终端继续；健康检查会重试等待采集初始化。

**命令 4.1：三个服务均应输出 active。**
```bash
systemctl is-active falco-modern-bpf tsa-fusion tsa-dashboard
```

**命令 4.2：健康接口应返回 {"status":"ok"}。**
```bash
curl --fail --retry 12 --retry-delay 2 --retry-connrefused --noproxy '*' http://127.0.0.1:8766/healthz
```

重试后仍失败，先查看 4.5 的日志，不继续验收。部署会预建空日志，安静的主机无需先触发报警才能就绪。

**命令 4.3：真实触发一次文件写入告警。**
```bash
python3 tsa/verify_runtime.py
```

脚本会提示 sudo 密码，仅向已有 `/etc/tsa-protected-demo` 追加一行测试编号。预期输出本次 PID、事件链接、规则 `Monitor specific file access`、测试前后分数和 `PASS`；它同时核对真实写入、同 PID/路径的告警及运行时计分。文件名沿用历史名称，不表示保护或拒绝。

**命令 4.4：读取评分，预期 HTTP 200、data 非空。**
```bash
curl --fail --noproxy '*' http://127.0.0.1:8766/systemManage/risk/score
```

在 **Ubuntu 浏览器**打开 `http://127.0.0.1:8766/`。没有图形桌面时使用下方 SSH 转发，勿直接开放看板端口。分数随主机配置和告警变化，不要求固定数值；SSH 登录等正常活动也可能命中规则，需结合证据判断。

**命令 4.5（排障）：查看日志。**
```bash
journalctl -u falco-modern-bpf -u tsa-fusion -u tsa-dashboard -n 80 --no-pager
```

服务 active 不是完整验收；还要看到本次 Falco 告警入库与有效评分。此测试不代表所有规则逐条攻击验证。

**命令 4.6（可选，Windows 终端）：Ubuntu 已启用 SSH 时转发看板。将 USER、UBUNTU_IP 替换为实际用户名和地址。**
```bash
ssh -N -L 127.0.0.1:18768:127.0.0.1:8766 USER@UBUNTU_IP
```

保持该终端打开，在 Windows 浏览器访问 `http://127.0.0.1:18768/`；查看 4.3 的事件链接时也将端口改为 `18768`。

### 实时观察扣分

在 Ubuntu 再开一个终端执行以下命令，保持打开；每 2 秒显示一次三个分数，`Ctrl+C` 退出：

```bash
watch -n 2 'curl --noproxy "*" -sS http://127.0.0.1:8766/systemManage/risk/score | jq .'
```

回到项目目录所在终端，执行 **4.3**。网页自动刷新，也可打开脚本输出的“本次证据”链接，在“当前运行时扣分明细”查看本规则。

只想手动触发同一规则时，也可以执行下面这条命令；它向演示文件追加文本，不是伪造告警。Falco 检测文件操作后由 TSA 自动入库计分，完整对账仍使用 4.3：

```bash
echo "manual-score-test-$(date +%s)" | sudo tee -a /etc/tsa-protected-demo
```

| 情况 | 应看到的结果 |
|---|---|
| 本规则原先未计分、没有其他风险变化 | 运行时扣 1 分；如 100 → 99 |
| 基线 85、权重 0.4/0.6、运行时 100 → 99 | 综合分 94 → 93.4，基线仍为 85 |
| 15 分钟内再次执行 4.3 | 新证据出现、有效期续期，本规则仍只占 1 分，不再次扣 1 |
| 最后一次触发后 15 分钟无新命中 | 该规则的 1 分退出当前计分，历史证据保留 |

其他进程可能同时触发规则或风险到期，因此总分变化未必恰好是 1；以脚本的“本规则当前风险”和网页逐规则明细对账。总分已到 0 时不能继续下降。不要删除数据库或修改报告时间来制造满分。

本次 2IIE-OS 实测：基线 85，原有其他风险占 5 分；首次演示写入使运行时 **95 → 94**、综合分 **91 → 90.4**，再次写入分数不变。自动补扫更新了报告，TSA 进程未重启也接收到了新基线。

### 部署后哪些步骤自动运行

| 环节 | 触发方式 | 结果 |
|---|---|---|
| Falco 监测 | 开机启动，持续读取系统调用 | 命中启用规则才写入告警 |
| TSA 运行时计分 | 自动读取新增告警，轮询间隔 1 秒 | 入库、更新规则风险；无需手动启动评分 |
| Lynis 基线扫描 | 部署时一次；每天 00/06/12/18 点及开机约 2 分钟后，最多随机延迟 1 分钟 | 先更新 APT 索引，再扫描、验证并原子替换统一报告 |
| TSA 基线计分 | 自动每 30 秒重读报告 | 新报告成功发布后约 30 秒内更新，无需重启 TSA |
| 综合分、网页、接口 | 按当前基线、未过期风险及实际权重计算 | 主系统主动查询评分接口 |

定时任务会补执行关机时错过的日历计划；失败不覆盖上一份完整报告，下一计划会重试。旧报告超过 24 小时仍无成功扫描时显示未评估，不使用旧分数冒充当前分数。

**命令 4.7：检查自动扫描计划，预期存在 NEXT 时间。**
```bash
systemctl list-timers --all tsa-baseline.timer
```

**命令 4.8：现在重新扫描，等待完成；这不是重启常驻服务。**
```bash
sudo systemctl start tsa-baseline.service
```

扫描结束后 service 显示 `inactive (dead)` 可以是正常的，因为它是一次性任务；定时器应为 `active (waiting)`。判断扫描成败看以下日志与报告，而非要求扫描服务一直 active。

**命令 4.9：查看最近扫描结果；另开终端将 `-n 60` 换成 `-f` 可实时跟踪。**
```bash
sudo journalctl -u tsa-baseline.service -n 60 --no-pager
```

**命令 4.10：查看 TSA 实际采用的报告与扫描时间，预期 data.status 为 ok。**
```bash
curl --fail --noproxy '*' -sS http://127.0.0.1:8766/systemManage/risk/baseline | jq '.data | {status,score,scan_end_local,report_path,errors}'
```

首次扫描或故障排查期间，在新报告发布后等最多 30 秒再查；若仍不可用，按 `errors` 和 4.9 排查 APT、扫描或报告问题，不关闭报告有效期检查。

## 5. 更新与配置

在原 Ubuntu 项目目录内：

**命令 5.1：更新源码。**
```bash
git pull --ff-only
```

**命令 5.2：重新部署，不是只刷新网页。**
```bash
sudo ./deploy-security-stack.sh
```

从旧版升级会备份并停用、移除原 BPF LSM 控制器；备份在 `/var/backups/lrss-legacy-*`。历史日志和数据库保留，但旧 BPF 事件不再计分或出现在当前看板。旧 GRUB 配置不自动修改，避免影响其他安全模块。

| 修改内容 | 文件 / 操作 |
|---|---|
| Falco 自定义规则 | `falco/rules.d/91-custom-rules.yaml`，见 [规则指南](FALCO_RULES.md) |
| 默认 30 条规则的选择 | `falco/rules.d/89-host-profile.yaml`；修改后重新部署 |
| 基线扣分、告警扣分 | `tsa/policy_config.yaml`，修改后 `sudo systemctl restart tsa-fusion tsa-dashboard` |
| 综合分权重 | 主系统调用权重接口，见第 6 节；YAML 权重仅为尚无接口设置时的初始值 |
| Lynis 检查内容 | 系统安装的 Lynis 测试与 profile；TSA 的 `baseline_lynis.controls` 只配置计分，不改变 Lynis 检查 |
| 告警、数据库、评分报告 | `/var/log/falco/falco.json`、`tsa/state/tsa.db`、`tsa/reports/last_scan.json` |
| 当前基线报告与扫描日志 | `/var/lib/tsa-baseline/lynis-report.dat`、`/var/lib/tsa-baseline/lynis.log` |
| 自动扫描入口 | `systemd/tsa-baseline.timer` / `.service`、`tsa/refresh_baseline.py`；修改源码后重新部署 |

默认综合分 = 基线分 × 40% + 运行时分 × 60%。基线分按选定 Lynis 检查项扣分，**不是原始 hardening_index**。运行时从 100 分减去各规则当前风险值，同规则重复事件不叠加；有效期从事件发生时间计算，过期不再计分但证据保留。新规则未配置分值时仅记录，priority 不自动换算扣分。看板“当前运行时扣分明细”展示依据；分值是项目风险指标，不代表真实入侵概率。

### 基线计分依据

Lynis 仍执行适用于本机的系统检查；不是只检查下表。TSA 从 100 分减去下表命中的权重，**同一检查项取最高值、只扣一次，总扣分不超过 100**。所有 warning 和 suggestion 均保留，包括不扣分项。

| 检查项 | 扣分条件 | 分值 |
|---|---|---:|
| AUTH-9204：额外 UID 0 账号 | warning | 25 |
| AUTH-9283：无密码账号 | warning | 25 |
| AUTH-9216：组文件一致性 | warning，需复核 grpck 错误 | 10 |
| PKGS-7392：安全更新 | warning，不等同已确认可利用漏洞 | 15 |
| SSH-7408：SSH 配置 | `details[]` 中 PermitRootLogin=YES / StrictModes=NO / IgnoreRhosts=NO / PermitUserEnvironment=YES | 15 / 15 / 10 / 5，取最高 |
| AUTH-9262：PAM 密码强度模块 | suggestion；外部统一认证主机可配置为 0 | 5 |
| AUTH-9328 / KRNL-5820 / LOGG-2190 / FIRE-4513 / BOOT-5122 | umask / core dump / 已删除但仍打开文件 / 未命中防火墙规则 / 引导密码，需结合场景审查 | 0，仅提示 |

其他检查项默认只展示、不自动扣分；SSH 缺少结构化证据时不猜测配置值。分值是可调整的项目风险权重，不是 Lynis 官方分值、等保/CIS 合规分或入侵概率。100 只表示本策略没有可计分发现，不表示所有检查通过。

**查看依据：**看板“基线检查与扣分明细”，或 `GET /systemManage/risk/baseline`。包括原文、建议、扣分、执行/跳过记录、报告时间和报告列出的风险软件包/账号；不按软件包或账号数量累加扣分，软件包列表也不等于已验证的 CVE。证据同时保存在 `tsa/reports/last_scan.json` 的 `baseline` 中。

**检查范围：**执行和跳过的 ID 来自报告 `tests_executed` / `tests_skipped`；执行过不代表所有子检查成功。缺少执行记录，或 AUTH-9204、AUTH-9283、PKGS-7392 未执行/异常时基线未评估。其他计分项报告 exception 时也未评估。报告默认 24 小时过期；自动扫描与手动更新见 4.7～4.10。

**检查代码与配置：**Ubuntu 软件包通常将测试放在 `/usr/share/lynis/include/tests_*`，活动 profile 用 `sudo lynis show profiles` 查看，按需修改 `custom.prf`；不直接改 Lynis 自带测试。完整执行及跳过原因看 `/var/lib/tsa-baseline/lynis.log`（每次扫描覆盖）。`PKGS-7392` 依赖 APT 索引和 apt-check（`update-notifier-common` 提供）；自动扫描前严格检查 APT 更新成功，否则保留旧报告并报错，不生成新的“正常”基线。

Lynis 原生 `hardening_index` 单独展示，不参与综合分。扫描时间沿用报告中的受审主机本地时间（未注明时区），有效期按报告文件 mtime 计算；不要用 touch 或复制旧报告伪造新扫描。

依据：[Lynis 3.0.7 认证检查](https://github.com/CISOfy/lynis/blob/3.0.7/include/tests_authentication)、[SSH 检查](https://github.com/CISOfy/lynis/blob/3.0.7/include/tests_ssh)、[APT 安全更新检查](https://github.com/CISOfy/lynis/blob/3.0.7/include/tests_ports_packages)。其他 Lynis 版本需复核报告字段，不假定检查覆盖完全一致。

升级不删除历史记录；关闭规则的旧记录不参与当前计分，保留规则的旧风险按峰值收敛，历史扣分不改写。分数可能因此变化，不表示主机漏洞已被修复。缺少有效基线或采集异常时评分不可用，不以 100 分替代。

事件时间缺失、无时区或领先主机超过 5 分钟时保留证据但暂停展示有效评分；校时、修正日志后重新执行 4.3，收到时间正常的计分规则事件后恢复。规则到期不等于异常已处理，仍需人工排查。

## 6. 主系统对接

**TSA 统一计算，主系统配置权重并展示结果，不在主系统重复计算综合分。** 主系统后端主动查询，不是 TSA 主动推送。

| 方法与路径 | 用途 | 认证 |
|---|---|---|
| `GET /systemManage/risk/score` | 获取 `posture` 基线分、`runtime` 运行时分、`final` 综合分及 `weights` | 本机读取保留原行为 |
| `GET /systemManage/risk/baseline` | 获取基线检查、逐项扣分和原始证据 | 与评分读取相同，限本机或安全代理 |
| `GET /systemManage/risk/weights` | 查询权重及版本 | Bearer 令牌 |
| `PUT /systemManage/risk/weights` | 设置权重，立即生效 | Bearer 令牌 |

默认地址为 `http://127.0.0.1:8766`。部署自动创建 `/etc/tsa/weights-api.env`（root 所有、0600），包含 `TSA_WEIGHTS_API_TOKEN` 与调用方标识 `TSA_WEIGHTS_API_CLIENT`。升级保留令牌；由管理员安全配置到主系统后端的密钥存储，不提交 Git、不放前端或 URL。轮换令牌后重启 `tsa-dashboard`；令牌未配置时权重接口返回 503，不影响原评分读取。

跨机器调用使用 SSH 转发，或带认证、访问限制的 HTTPS 反向代理；不要开放裸 HTTP 端口。代理转发到本地时须设置 `Host: 127.0.0.1:8766` 并转发 Authorization。权重接口仅供后端调用，拒绝带 Origin 的浏览器请求。

先 GET 权重获取 `data.version`（首次为 0），再 PUT，例如：

```http
PUT /systemManage/risk/weights
Authorization: Bearer <令牌>
Content-Type: application/json
```

```json
{"posture":0.3,"runtime":0.7,"expected_version":0,"reason":"主系统管理员调整评分权重"}
```

两项必须是 0～1 的数字且总和为 1，不自动归一化非法请求。`expected_version` 必填；不一致返回 409，主系统重新 GET 后让管理员确认，不盲目覆盖。成功返回 HTTP 200、`code:20000`、`status:true`，`data` 为新权重、递增版本、`updated_at`、`updated_by` 和 `reason`。`reason` 可省略，最长 500 字符；请求体最多 4096 字节。

评分接口成功示例（示例分数，不是当前主机实测）：

```json
{
  "code":20000,"status":true,"message":"操作成功",
  "data":{
    "posture":80,"runtime":60,"final":66,
    "weights":{"posture":0.3,"runtime":0.7,"version":1,
      "updated_at":"2026-09-18T08:00:00+00:00","updated_by":"main-system","reason":"主系统管理员调整评分权重"},
    "generated_time":"2026-09-18T08:00:01+00:00"
  }
}
```

`generated_time` 是响应生成时间，不是 Lynis 扫描时间。非法请求返回 400，认证失败 401，来源不允许 403，版本冲突 409，存储或评分不可用 503；失败时 `status:false`、`data:null`。主系统必须同时检查 HTTP 状态和 status；评分不可用应显示“未评估”，不能替换成 0 或 100。基线权重为 0 时允许忽略缺失基线，`posture` 仍可能为 null。

基线明细接口用于诊断：读取成功可返回 HTTP 200，同时 `data.status=unavailable`、`data.score=null` 和 `data.errors` 解释未评估原因。不要将外层 `status:true` 误读为基线检查通过。基线报告和接口可能包含账号、路径等敏感信息，不公开暴露。

权重及变更前后版本保存在 `tsa/settings/weights.db`，重启和重新部署不清空；备份时应包含该数据库。`updated_by` 标识持有令牌的主系统，具体管理员身份由主系统审计关联。已有接口设置优先于 YAML，恢复 0.4/0.6 也通过 PUT 完成，不删除数据库。权重变更不修改两项原始分数、不重写历史事件；网页与下一次定期评分报告也读取同一份权重。
