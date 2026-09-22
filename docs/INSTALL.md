# Ubuntu 复现指南

环境：Ubuntu 22.04 x86_64（systemd），使用可 sudo 的普通用户，网络能访问 Ubuntu、Falco 软件源和 GitHub。项目放在用户家目录，路径不含空格或中文。

功能：**Lynis 基线检测 + Falco 告警 + TSA 评分**。

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

**命令 3.4：部署项目，首次运行需等待数分钟。**
```bash
sudo ./deploy-security-stack.sh
```

自动检查程序、启用 30 条规则、完成首次基线扫描并启动服务，后续扫描定时执行。命令结束且无报错后，继续第 4 节；`long execution` 只是检查较慢，请继续等待。

基线报告自动保存到 `/var/lib/tsa-baseline/lynis-report.dat`，无需手动生成。

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

健康检查失败时，先处理错误再继续。

先在 Ubuntu 浏览器打开 `http://127.0.0.1:8766/`，保持网页打开，观察“运行时评分”。下面两种测试都会实际扣分，评分接口也会同步变化。

**命令 4.3：样例一，写入演示文件，首次扣 10 分。**
```bash
python3 tsa/verify_runtime.py
```

脚本向演示文件 `/etc/tsa-protected-demo` 追加一行内容，触发 `Monitor specific file access` 告警。

没有其他有效风险时，网页运行时分从 `100 → 90`。终端显示“验证通过（PASS）”表示本次操作、告警入库和实际计分检查通过；不是所有规则都已通过测试。

**命令 4.4：读取评分，预期 HTTP 200、data 非空。**
```bash
curl --fail --noproxy '*' http://127.0.0.1:8766/systemManage/risk/score
```

在 **Ubuntu 浏览器**打开 `http://127.0.0.1:8766/` 查看分数和告警。

### 实时观察分数

在 Ubuntu 再开一个终端执行以下命令，保持打开；每 2 秒显示一次三个分数，`Ctrl+C` 退出：

```bash
watch -n 2 'curl --noproxy "*" -sS http://127.0.0.1:8766/systemManage/risk/score | jq .'
```

网页自动刷新；终端的“本次证据”链接可定位本次告警。再次执行 **4.3**，有效期内新增扣分为 0，并显示“同规则有效风险已覆盖本次风险值”。

**样例二：执行无害脚本，触发另一条规则，再扣 10 分。**

```bash
python3 tsa/verify_runtime.py --scenario shm-exec
```

脚本在 `/dev/shm` 的临时目录中创建并执行仅含 `exit 0` 的脚本，触发 `Execution from /dev/shm`，随后删除临时文件。不修改挂载权限，不读取敏感数据。再次执行此命令，有效期内不重复扣分。

| 情况 | 应看到的结果 |
|---|---|
| 样例一首次触发 | 运行时分 100 → 90，新增扣分 10 |
| 重复样例一 | 保持 90，新增扣分 0 |
| 再首次触发样例二 | 90 → 80，新增扣分 10 |
| 重复样例二 | 保持 80，新增扣分 0 |

上表假定开始时运行时分为 100，且没有其他告警或风险到期。综合分按实际权重变化：基线 85、权重 0.4/0.6 时，综合分依次为 `94 → 88 → 82`，不是每次减 10。

样例一风险有效期为 15 分钟，样例二为 4 小时；重复命中会续期。停止触发并等风险到期后，才会恢复对应分数，再触发可再次扣分。不要清库、改时间或降低真实规则的有效期来重置演示。

若 4.3 提示“事件时间与实际操作不符”（可能出现在虚拟机挂起恢复后），先用 `timedatectl` 确认系统时间正确，再执行 `sudo systemctl restart falco-modern-bpf` 并重试 4.3；不要关闭事件过期检查。

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
| SSH-7408：SSH 配置 | `details[]` 中 PermitRootLogin=YES / StrictModes=NO / PermitUserEnvironment=YES | 15 / 15 / 5，取最高 |
| SSH-7408：IgnoreRhosts=NO | 缺少 HostbasedAuthentication 上下文，无法确认用户信任文件是否生效 | 0，仅提示 |
| AUTH-9262：PAM 密码强度模块 | suggestion；外部统一认证主机可配置为 0 | 5 |
| AUTH-9328 / KRNL-5820 / LOGG-2190 / FIRE-4513 / BOOT-5122 / NETW-3200 | umask / core dump / 已删除但仍打开文件 / 未命中防火墙规则 / 引导密码 / 网络协议，需结合场景审查 | 0，仅提示 |

其他检查项默认只展示、不自动扣分；SSH 缺少结构化证据时不猜测配置值。基线分 = 100 - 各检查项扣分之和（最低 0）。例如 PKGS-7392 扣 15 分，基线就是 85；15 表示本项目对安全更新缺口的重视程度，不是 15% 的入侵概率，也不随软件包数量增加。分值是项目策略，不是 Lynis 官方分、等保/CIS 合规分；100 只表示没有可计分发现，不表示所有检查通过。

**查看依据：**看板“基线检查与扣分明细”，或 `GET /systemManage/risk/baseline`。包括原文、建议、扣分、执行/跳过记录、报告时间和报告列出的风险软件包/账号；不按软件包或账号数量累加扣分，软件包列表也不等于已验证的 CVE。证据同时保存在 `tsa/reports/last_scan.json` 的 `baseline` 中。

**检查范围：**执行和跳过的 ID 来自报告 `tests_executed` / `tests_skipped`；执行过不代表所有子检查成功。缺少执行记录，或 AUTH-9204、AUTH-9283、PKGS-7392 未执行/异常时基线未评估。其他计分项报告 exception 时也未评估。报告默认 24 小时过期。

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
