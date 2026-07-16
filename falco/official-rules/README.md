# Falco 官方规则（仓库快照）

本目录存放 Falco 官方检测规则的**版本快照**，方便在 clone 仓库后直接阅读和分析，
无需先在本机安装 Falco。

## 这是什么 / 不是什么

- **是**：Falco 官方规则的可读快照（`falco_rules.yaml`、`falco-sandbox_rules.yaml`、
  `falco-incubating_rules.yaml`），Apache-2.0 许可，源自 https://github.com/falcosecurity/rules 。
- **不是**：部署时实际使用的规则。部署用的永远是**本机已安装 Falco 包**自带的规则，
  `../deploy-host-falco.sh` 只在此基础上追加本项目的自定义规则 `../rules.d/`。
- **快照会过时**：Falco 每个版本的官方规则都有差异。本目录的快照对应 `VERSION.txt`
  记录的版本，可能与线上安装版本不同。分析线上行为前，请用本机版本重新拉取对齐。

## 当前快照状态

> 见 `VERSION.txt`。若该文件标注 `status=empty`，表示仓库尚未写入规则快照——
> 需在已安装 Falco 的机器上执行下面"更新快照"步骤后提交。

## 更新快照（与已装 Falco 版本对齐）

```bash
# 推荐：从本机已装 falco 拷贝（/etc/falco），与实际部署一致
./falco/fetch-official-rules.sh

# 没装 falco 时：从官方 release 下载 tarball（URL 自行从 release 页复制）
./falco/fetch-official-rules.sh --remote-url \
  https://github.com/falcosecurity/rules/releases/download/<tag>/falco_rules.tar.gz
```

拉取后本目录会更新三个 yaml 与 `VERSION.txt`，直接 `git add` 提交即可形成新快照。

## 分析示例

```bash
# 官方规则总数
grep -c '^- rule:' falco/official-rules/falco_rules.yaml

# 查提权/逃逸相关规则
grep -B1 -A6 'privilege\|escalat\|escape' falco/official-rules/falco_rules.yaml | head

# 对照 TSA 评分映射：哪些官方规则已配扣分权重
grep -c '"T' tsa/policy_config.yaml   # 粗略点数；精确对照见具体规则名
```

## 与本项目其他部分的关系

| 规则来源 | 文件 | 作用 |
|---|---|---|
| 官方（本目录快照） | `falco/official-rules/*.yaml` | 分析用快照，不参与部署 |
| 官方（运行时） | `/etc/falco/falco_rules*.yaml` | 部署实际加载，由 falco 包提供 |
| 项目自定义 | `falco/rules.d/90-local-file-monitoring.yaml` | 1 条：盯 `/etc/tsa-protected-demo` |
| 项目白名单补丁 | `falco/rules.d/95-security-stack-exceptions.yaml` | 给官方规则打例外 |
| TSA 评分映射 | `tsa/policy_config.yaml` 的 `specific_rules` | 约 87 条官方规则名→扣分权重 |