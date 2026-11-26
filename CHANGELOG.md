# Changelog

本项目的重要变更记录在此。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [1.4.0] - 2026-11-26

### Added

- 支持更多 Linux 发行版：Debian、Ubuntu、RHEL/Rocky/AlmaLinux、Fedora、openSUSE、Arch Linux、Alpine；CI 新增在这些发行版容器中真实部署的端到端测试矩阵。
- 部署前检测服务器：先检测账户权限（root / sudo / su），再检测系统版本、包管理器、init 系统、防火墙、SELinux 与 ssh.socket，并展示变更计划，确认后才修改。
- 账户没有 sudo 时，可填写 root 密码，通过 `su` 安装 `sudo`（apt、dnf、yum、zypper、pacman、apk）并授予临时 sudo 规则，结束或回滚时一定删除。
- 两阶段修改 SSH 端口：放行防火墙（ufw/firewalld）与 SELinux 端口标签，在新端口验证密钥登录后再关闭旧端口，失败自动回滚。
- 原生 macOS 版界面重做：双栏布局、单一登录策略选项与结果说明、逐字段即时校验、变更计划确认、结果卡片（ssh 命令与 `~/.ssh/config` 片段）、最近服务器列表，以及 CI 自动截图。
- Windows 与跨平台 macOS 版同样支持服务器检测、su、自动安装与端口修改。

### Changed

- sudo 相关错误提示按发行版给出对应命令；服务器不加载 `sshd_config.d` 时在任何修改前停止并说明需要添加的 Include 行。
- 远程脚本兼容 BusyBox（Alpine），密钥安装后执行 `restorecon`，sshd 重载支持 systemd、OpenRC、service 和信号回退。

### Fixed

- C# 版远程脚本同样修复了 `set -e` 下 `test A && test B` 检查失败不中止的问题。

## [1.3.0] - 2026-11-25

### Added

- 新增原生 macOS 版（`macos-native/`，SwiftUI）：Apple Silicon 与 Intel 通用二进制，支持 macOS 13+，只依赖系统框架，无需附带 .NET 运行时。
- 原生版使用系统自带的 `ssh`、`ssh-keyscan`、`ssh-keygen`：主机密钥固定到用户确认的指纹，密码只通过一条 ControlMaster 连接发送一次，不读取或修改用户自己的 SSH 配置、known_hosts 和 agent。
- 原生版新增部署步骤列表、复制公钥、在访达中显示、选择新建或现有密钥，以及部署中退出时先回滚再关闭。
- CI 新增原生 macOS 通用包的测试与打包任务。

### Changed

- CI 的 macOS 任务改用 `macos-15` 运行器（GitHub 已停用 `macos-14`，原 .NET macOS 任务无法启动）。
- 原生版把检查与备份受管 sshd 配置的 5 次远程调用合并为 1 次，并移除未使用的公钥删除命令；authorized_keys 回滚脚本去除了重复分支。

### Fixed

- 远程脚本在 `set -e` 下，`test A && test B` 形式的检查失败时不会中止（例如已存在的备份可能被覆盖）；12 处检查改为失败即退出。
- UID 为 0 但账号名不是 `root` 时，最后的 root 密钥登录验证会误判失败。

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

[1.4.0]: https://github.com/tuolaji996/windows-ssh-key-deployer/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/tuolaji996/windows-ssh-key-deployer/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/tuolaji996/windows-ssh-key-deployer/compare/v1.2.0...v1.2.1
[1.0.0]: https://github.com/tuolaji996/windows-ssh-key-deployer/releases/tag/v1.0.0
