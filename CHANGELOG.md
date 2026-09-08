# Changelog

本项目的重要变更记录在此。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [1.2.1] - 2026-09-08

### Changed

- sudo 预检现在会区分账号未获授权、服务器未安装 sudo 和 sudo 密码被拒绝，并在中英文界面直接显示 Debian 修复命令与重新登录步骤。
- 初始 SSH 连接失败时会区分密码认证被拒绝、连接超时和网络不可达，不再只显示笼统错误。
- Windows 默认密钥目录改为 `%USERPROFILE%\.ssh\ssh-key-deployer`，并在选择、验证和 ACL 加固阶段拒绝 UNC 网络路径与映射盘，避免 Windows OpenSSH 因权限过宽而忽略私钥。

### Security

- Updated SSH.NET to 2026.0.0 to resolve the high-severity advisory affecting the previous package version.

## [1.0.0] - 2026-08-03

### Added

- Windows WPF 中文图形界面，支持亮色与深色主题。
- 本机 Ed25519 密钥生成、私钥 ACL 加固和公钥管理。
- Debian 12/13 公钥安装、SSH 登录策略设置和主机指纹确认。
- `sshd` 配置检查、回滚和密钥回连验证。
- `win-x64` 自包含单文件发布、SHA-256 校验文件与当前用户安装脚本。

[1.2.1]: https://github.com/tuolaji996/windows-ssh-key-deployer/compare/v1.2.0...v1.2.1
[1.0.0]: https://github.com/tuolaji996/windows-ssh-key-deployer/releases/tag/v1.0.0
