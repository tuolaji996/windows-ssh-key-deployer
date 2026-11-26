using System.Globalization;
using System.Text;

namespace SshKeyDeployer.Core;

/// <summary>
/// Chinese and English texts shared by the Windows and macOS front ends for the plan dialog,
/// privilege guidance, and the final SSH command.
/// </summary>
public static class DeploymentPresentation
{
    public const string SupportedDistributions =
        "Debian / Ubuntu · RHEL / Rocky / Alma / Fedora · openSUSE · Arch · Alpine";

    public static string DescribePrivilege(PrivilegeMode privilege, bool english) => privilege switch
    {
        PrivilegeMode.Root => english ? "root account" : "root 账户",
        PrivilegeMode.Sudo => english ? "sudo (account password)" : "sudo（当前账户密码）",
        PrivilegeMode.Su => english ? "su (root password) with temporary sudo" : "su（root 密码）+ 临时 sudo",
        _ => english ? "none" : "无"
    };

    public static string DescribeFirewall(Firewall? firewall, bool english) => firewall switch
    {
        Firewall.Ufw => "ufw",
        Firewall.Firewalld => "firewalld",
        _ => english ? "none detected" : "未检测到"
    };

    public static string DescribeServerSummary(ServerInfo server, bool english) =>
        english
            ? $"{server.DisplayName} · privilege: {DescribePrivilege(server.Privilege, true)}"
            : $"{server.DisplayName} · 权限方式：{DescribePrivilege(server.Privilege, false)}";

    /// <summary>Label/value rows describing the inspected server.</summary>
    public static IReadOnlyList<(string Label, string Value)> DescribeServer(ServerInfo server, bool english)
    {
        var ports = server.CurrentPorts.Count == 0
            ? "?"
            : string.Join(", ", server.CurrentPorts.Select(port => port.ToString(CultureInfo.InvariantCulture)));
        var manager = server.PackageManager is PackageManager value
            ? ServerInspection.CommandName(value)
            : english ? "not found" : "未找到";
        var init = server.InitSystem switch
        {
            InitSystem.Systemd => "systemd",
            InitSystem.OpenRc => "OpenRC",
            _ => english ? "other" : "其他"
        };
        if (server.SocketActivated)
        {
            init += english ? " (ssh.socket activation)" : "（ssh.socket 套接字激活）";
        }

        return
        [
            (english ? "System" : "系统", server.DisplayName),
            (english ? "Privilege" : "权限方式", DescribePrivilege(server.Privilege, english)),
            (english ? "Init system" : "服务管理", init),
            (english ? "Package manager" : "包管理器", manager),
            (english ? "Firewall" : "防火墙", DescribeFirewall(server.Firewall, english)),
            ("SELinux", server.SelinuxEnforcing ? (english ? "enforcing" : "强制模式（enforcing）") : (english ? "not enforcing" : "未强制")),
            (english ? "SSH port(s)" : "当前 SSH 端口", ports)
        ];
    }

    public static string DescribeAction(PlannedAction action, bool english) => action switch
    {
        InstallPackagesAction install => english
            ? $"Install {string.Join(", ", install.Packages)} with {ServerInspection.CommandName(install.Manager)} — persistent, packages are not removed on rollback"
            : $"使用 {ServerInspection.CommandName(install.Manager)} 安装 {string.Join(", ", install.Packages)} —— 持久变更，回滚时不会卸载",
        TemporarySudoViaSuAction sudo => english
            ? $"Use su with the root password to grant '{sudo.Account}' temporary sudo (a file in /etc/sudoers.d, always removed at the end)"
            : $"通过 su（root 密码）临时授予“{sudo.Account}” sudo 权限（/etc/sudoers.d 中的临时文件，结束时总会删除）",
        InstallPublicKeyAction key => english
            ? $"Add the public key to {key.Account}'s ~/.ssh/authorized_keys"
            : $"把公钥加入 {key.Account} 的 ~/.ssh/authorized_keys",
        WriteSshdPolicyAction policy => english
            ? $"Write {DeploymentService.ManagedConfigPath}: root login {DescribeRootLogin(policy.RootLogin, true)}, password login {(policy.PasswordLogin ? "allowed" : "disabled")}"
            : $"写入 {DeploymentService.ManagedConfigPath}：root 登录{DescribeRootLogin(policy.RootLogin, false)}，密码登录{(policy.PasswordLogin ? "允许" : "关闭")}",
        ChangePortAction port => english
            ? $"Move SSH from port {JoinPorts(port.From)} to {port.To}; the new port is verified with key login before the old one is closed"
            : $"把 SSH 端口从 {JoinPorts(port.From)} 改为 {port.To}；先用密钥验证新端口可登录，再关闭旧端口",
        OpenFirewallPortAction firewall => english
            ? $"Open TCP port {firewall.Port} in {DescribeFirewall(firewall.Firewall, true)} (kept after success)"
            : $"在 {DescribeFirewall(firewall.Firewall, false)} 中放行 TCP 端口 {firewall.Port}（成功后保留）",
        LabelSelinuxPortAction selinux => english
            ? $"Label TCP port {selinux.Port} as ssh_port_t in SELinux (kept after success)"
            : $"在 SELinux 中把 TCP 端口 {selinux.Port} 标记为 ssh_port_t（成功后保留）",
        _ => action.ToString()
    };

    public static string DescribeRootLogin(RootLoginPolicy policy, bool english) => policy switch
    {
        RootLoginPolicy.PasswordAndKey => english ? "allowed (password and key)" : "允许（密码和密钥）",
        RootLoginPolicy.KeyOnly => english ? "key only" : "仅密钥",
        _ => english ? "disabled" : "禁止"
    };

    /// <summary>The ssh command that uses the deployed key on the final port.</summary>
    public static string BuildSshCommand(DeploymentResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        var keyPath = result.PrivateKeyPath.Contains(' ', StringComparison.Ordinal)
            ? $"\"{result.PrivateKeyPath}\""
            : result.PrivateKeyPath;
        return $"ssh -i {keyPath} -p {result.SshPort.ToString(CultureInfo.InvariantCulture)} {result.VerifiedUsername}@{result.ApprovedHostKey.Host}";
    }

    /// <summary>
    /// A localized explanation for privilege, support and plan failures, or null for other errors.
    /// </summary>
    public static string? DescribeFailure(DeploymentException exception, bool english)
    {
        ArgumentNullException.ThrowIfNull(exception);
        if (english)
        {
            return exception is SudoAccessException or PrivilegeException or UnsupportedServerException or PlanRejectedException
                ? exception.Message
                : null;
        }

        switch (exception)
        {
            case SudoAccessException sudo:
            {
                var username = sudo.Username;
                var builder = new StringBuilder();
                switch (sudo.Reason)
                {
                    case SudoAccessFailureReason.NotAuthorized:
                        builder.Append($"SSH 密码登录已经成功，但账户“{username}”没有 sudo 权限。能用 su 输入 root 密码，并不等于该账户拥有 sudo 权限。\n\n请在 root 终端执行：\n");
                        builder.Append(string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(sudo.Family, username, sudoInstalled: true)));
                        builder.Append($"\n\n然后完全退出“{username}”的所有会话，重新登录，运行 sudo -k true 验证后再试。");
                        break;
                    case SudoAccessFailureReason.CommandUnavailable:
                        builder.Append("SSH 密码登录已经成功，但服务器没有安装 sudo。\n\n请在 root 终端执行：\n");
                        builder.Append(string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(sudo.Family, username, sudoInstalled: false)));
                        builder.Append($"\n\n然后完全退出“{username}”的所有会话，重新登录后再试。");
                        break;
                    default:
                        builder.Append($"SSH 密码登录已经成功，但 sudo 拒绝了账户“{username}”的密码。sudo 通常需要当前账户的密码，而不是 root 密码。\n\n请重新登录“{username}”，先运行 sudo -k true 验证，再回到本工具重试。");
                        break;
                }

                AppendSuseNote(builder, sudo.Family);
                builder.Append("\n\n也可以在“root 密码”栏填写 root 密码：工具会通过 su 临时授予 sudo，并在部署结束时撤销。");
                return builder.ToString();
            }

            case PrivilegeException privilege:
            {
                var username = privilege.Username;
                var builder = new StringBuilder();
                switch (privilege.Reason)
                {
                    case PrivilegeFailureReason.NoPrivilege:
                        builder.Append($"SSH 密码登录已经成功（{privilege.OsName}），但账户“{username}”无法以 root 身份执行命令：");
                        builder.Append(privilege.SudoInstalled ? "该账户没有可用的 sudo 权限" : "服务器没有安装 sudo");
                        builder.Append("，并且没有填写 root 密码。\n\n方法一：在“root 密码”栏填写 root 密码，工具会通过 su 临时授予 sudo，并在结束时撤销。\n\n方法二：在 root 终端执行：\n");
                        builder.Append(string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(privilege.Family, username, privilege.SudoInstalled)));
                        builder.Append($"\n\n然后完全退出“{username}”的所有会话，重新登录后再试。");
                        AppendSuseNote(builder, privilege.Family);
                        break;
                    case PrivilegeFailureReason.RootPasswordRejected:
                        builder.Append($"su 拒绝了 root 密码。请填写 root 账户本身的密码（不是“{username}”的密码）后重试。");
                        break;
                    default:
                        builder.Append($"服务器（{privilege.OsName}）上的 su 不可用，或不允许账户“{username}”使用，因此无法使用 root 密码。请改为在 root 终端为该账户开通 sudo：\n");
                        builder.Append(string.Join("\n", PrivilegeGuidance.GetSudoSetupCommands(privilege.Family, username, privilege.SudoInstalled)));
                        break;
                }

                builder.Append("\n\n服务器未做任何修改。");
                return builder.ToString();
            }

            case UnsupportedServerException unsupported:
                return unsupported.Reason == UnsupportedServerReason.SshdConfigWithoutInclude
                    ? $"{unsupported.ConfigPath} 没有加载 /etc/ssh/sshd_config.d，工具写入的 SSH 策略不会生效。\n\n请以 root 身份在 {unsupported.ConfigPath} 的开头加入下面这一行，用 sshd -t 检查后重试：\n{unsupported.RequiredLine}\n\n工具不会修改主配置文件 sshd_config。服务器未做任何修改。"
                    : $"{unsupported.ConfigPath} 没有包含 /etc/sudoers.d，无法通过 su 临时授予 sudo。\n\n请以 root 身份运行 visudo 加入下面这一行后重试：\n{unsupported.RequiredLine}\n\n服务器未做任何修改。";

            case PlanRejectedException:
                return "已取消：部署计划未获批准。服务器未做任何修改。";

            default:
                return null;
        }
    }

    private static void AppendSuseNote(StringBuilder builder, LinuxFamily family)
    {
        if (family == LinuxFamily.Suse)
        {
            builder.Append("\n\n说明：openSUSE 默认的“Defaults targetpw”会让 sudo 要求输入 root 密码；上面的 sudoers 文件为 wheel 组关闭了这一行为。");
        }
    }

    private static string JoinPorts(IReadOnlyList<int> ports) =>
        ports.Count == 0
            ? "?"
            : string.Join(", ", ports.Select(port => port.ToString(CultureInfo.InvariantCulture)));
}
