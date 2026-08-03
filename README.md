# SSH Key Deployer

[![CI](https://github.com/tuolaji996/windows-ssh-key-deployer/actions/workflows/ci.yml/badge.svg)](https://github.com/tuolaji996/windows-ssh-key-deployer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

SSH Key Deployer 是一个面向 Windows 用户的中文 WPF 工具，用于将独立 Ed25519 密钥安全部署到自己管理的 Debian 服务器。

## 主要功能

- 在本机生成独立 Ed25519 私钥和公钥，并加固私钥文件权限。
- 首次连接时显示 SSH 主机指纹，由用户核对后再继续。
- 安装 `authorized_keys`，并可配置 root 登录与密码登录策略。
- 写入配置前备份，执行 `sshd` 语法检查、有效配置检查和密钥回连验证；失败时尝试回滚。
- 密码只用于当前连接，不写入配置或日志。
- 支持亮色/深色主题，并提供本机密钥文件入口。

## 系统要求

- Windows 10/11 x64。
- Windows OpenSSH Client（需要 `ssh-keygen.exe`）。
- 目标为 Debian 12/13，已运行 OpenSSH Server。
- 首次连接所需的账户密码，以及修改 SSH 配置所需的 root 或 `sudo` 权限。

## 安装

从 [Releases](https://github.com/tuolaji996/windows-ssh-key-deployer/releases) 下载 `SSH-Key-Deployer-v1.0.0-win-x64.zip` 和同名 `.sha256` 文件，核对哈希后解压运行。也可使用仓库中的安装脚本：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Version 1.0.0
```

默认安装到当前用户的 `%LOCALAPPDATA%\Programs\SSH Key Deployer`，不需要管理员权限。

## 使用

1. 填写服务器域名、SSH 端口、账户和当前密码。
2. 选择本机私钥保存位置，并设定所需的登录策略。
3. 从独立的服务器控制台核对主机指纹，确认一致后继续。
4. 等待密钥回连验证成功，再结束原有 SSH 会话或调整密码登录策略。

> 仅对你拥有或获得明确授权的服务器使用本工具。主机指纹不匹配时必须取消部署。

## 从源码构建

需要 .NET 8 SDK 和 Windows PowerShell 5.1 或 PowerShell 7：

```powershell
.\build.ps1
.\scripts\scan-secrets.ps1
```

生成 `win-x64` 自包含单文件发布包：

```powershell
.\release.ps1 -Version 1.0.0
```

产物位于 `artifacts/`，包含 ZIP 和对应的 `.sha256` 文件。

## 安全与许可证

安全问题请按 [SECURITY.md](SECURITY.md) 私密报告。本项目使用 [MIT License](LICENSE)。

---

**English:** SSH Key Deployer is a Windows WPF utility for generating an Ed25519 key and safely deploying it to an authorized Debian server, with host-key confirmation, configuration validation, rollback, and key-login verification.
