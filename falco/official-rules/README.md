# 默认部署的 Falco 官方规则

本目录的三份 YAML 随 Git 提交固定，clone 后即可阅读和部署。当前包含 stable 25 条、sandbox 37 条、incubating 31 条规则定义。数量不是实际启用数量，保留上游 enabled 设置和运行环境过滤。

- `../rules.lock.json` 记录文件的 SHA256（UTF-8、LF 换行）及规则定义数量。
- `../rules.d/91-custom-rules.yaml` 是用户添加自定义规则的入口，不应直接修改本目录。
- `../manage_rules.py check` 在本机 Falco 上校验整个候选规则集。
- `../deploy-host-falco.sh` 安装至 `/etc/falco/security-stack/rules/<规则包ID>/`，不覆盖系统包的官方文件。
- 本机额外规则保留；完整加载路径见 `/etc/falco/falco.yaml` 的 `rules_files`。

这些文件来自 [falcosecurity/rules](https://github.com/falcosecurity/rules)，保留原 Apache-2.0 许可声明。历史快照没有可靠的上游 release tag，详见 `VERSION.txt`；校验和仅固定内容，不证明上游发布身份。

维护者更新规则后需审查来源、刷新锁、校验并测试，不能只下载后直接用于生产。新机步骤与自定义规则示例见 [FALCO_RULES.md](../../docs/FALCO_RULES.md)。
