using System.Collections.ObjectModel;
using System.Globalization;

namespace SshKeyDeployer.Core;

public enum LinuxFamily
{
    Debian,
    Rhel,
    Suse,
    Arch,
    Alpine,
    Unknown
}

public enum PackageManager
{
    Apt,
    Dnf,
    Yum,
    Zypper,
    Pacman,
    Apk
}

public enum InitSystem
{
    Systemd,
    OpenRc,
    Other
}

public enum Firewall
{
    Ufw,
    Firewalld
}

/// <summary>How root commands are run for this deployment.</summary>
public enum PrivilegeMode
{
    /// <summary>Logged in as UID 0.</summary>
    Root,
    /// <summary>The account can use sudo with its own password.</summary>
    Sudo,
    /// <summary>sudo is missing or not permitted; su with the root password bootstraps temporary sudo.</summary>
    Su,
    /// <summary>No usable way to become root.</summary>
    None
}

/// <summary>Everything learned about the server before any change is made.</summary>
public sealed record ServerInfo(
    string OsId,
    string OsName,
    string OsVersion,
    LinuxFamily Family,
    PackageManager? PackageManager,
    InitSystem InitSystem,
    PrivilegeMode Privilege,
    bool SudoInstalled,
    bool SshdIncludesDropIns,
    bool SelinuxEnforcing,
    Firewall? Firewall,
    bool SocketActivated,
    IReadOnlyList<int> CurrentPorts)
{
    public string DisplayName
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(OsName))
            {
                return OsName;
            }

            var fallback = $"{OsId} {OsVersion}".Trim();
            return fallback.Length == 0 ? "Linux" : fallback;
        }
    }
}

/// <summary>One change the deployment will make, shown to the user before anything happens.</summary>
public abstract record PlannedAction
{
    /// <summary>True when rollback does not undo the change.</summary>
    public virtual bool IsPersistent => false;
}

/// <summary>Persistent: packages are not removed on rollback.</summary>
public sealed record InstallPackagesAction(PackageManager Manager, IReadOnlyList<string> Packages) : PlannedAction
{
    public override bool IsPersistent => true;
}

/// <summary>A sudoers drop-in for this account, created through su and always removed afterwards.</summary>
public sealed record TemporarySudoViaSuAction(string Account) : PlannedAction;

public sealed record InstallPublicKeyAction(string Account) : PlannedAction;

public sealed record WriteSshdPolicyAction(RootLoginPolicy RootLogin, bool PasswordLogin) : PlannedAction;

public sealed record ChangePortAction(IReadOnlyList<int> From, int To) : PlannedAction;

public sealed record OpenFirewallPortAction(Firewall Firewall, int Port) : PlannedAction;

public sealed record LabelSelinuxPortAction(int Port) : PlannedAction;

public sealed record DeploymentPlan(ServerInfo Server, IReadOnlyList<PlannedAction> Actions);

/// <summary>
/// Shown after inspection and before any server change; returning false stops the deployment
/// with <see cref="PlanRejectedException"/>.
/// </summary>
public delegate Task<bool> PlanApprovalCallback(
    DeploymentPlan plan,
    CancellationToken cancellationToken);

/// <summary>Result of the unprivileged one-round-trip probe.</summary>
public sealed record UnprivilegedProbe(
    int? Uid,
    string OsId,
    string OsIdLike,
    string OsName,
    string OsVersion,
    IReadOnlySet<string> Commands,
    InitSystem InitSystem)
{
    public bool Has(string command) => Commands.Contains(command);
}

/// <summary>Result of the probe that runs as root (sshd, firewall, SELinux, includes).</summary>
public sealed record RootProbe(
    bool SshdAvailable,
    bool SshdConfigValid,
    IReadOnlyList<int> Ports,
    bool SelinuxEnforcing,
    Firewall? Firewall,
    bool SocketActivated,
    string MainConfigPath,
    bool IncludesDropIns,
    IReadOnlyList<int> MainConfigPorts,
    IReadOnlyList<int> ManagedPorts,
    bool? SudoersIncludesDropIns);

public static class ServerInspection
{
    public const string SemanageCommand = "semanage";

    /// <summary>
    /// Runs as the login account. Prints key=value lines: uid, os-release fields, available commands, init system.
    /// </summary>
    public const string UnprivilegedProbeScript =
        """
        PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
        export PATH
        LC_ALL=C
        export LC_ALL
        printf 'uid=%s\n' "$(id -u)"
        if [ -r /etc/os-release ]; then
            (
                . /etc/os-release 2>/dev/null
                printf 'id=%s\n' "${ID-}"
                printf 'id_like=%s\n' "${ID_LIKE-}"
                printf 'pretty=%s\n' "${PRETTY_NAME-}"
                printf 'version=%s\n' "${VERSION_ID-}"
            )
        fi
        for c in sudo su apt-get dnf yum zypper pacman apk restorecon semanage visudo systemctl rc-service; do
            if command -v "$c" >/dev/null 2>&1; then
                printf 'cmd=%s\n' "$c"
            fi
        done
        if [ -d /run/systemd/system ]; then
            printf 'init=systemd\n'
        elif command -v rc-service >/dev/null 2>&1; then
            printf 'init=openrc\n'
        else
            printf 'init=other\n'
        fi
        printf 'probe=done\n'
        """;

    /// <summary>
    /// Runs as root. Never changes anything. Prints key=value lines describing sshd, firewall and SELinux.
    /// </summary>
    public const string RootProbeScript =
        """
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
        export PATH
        LC_ALL=C
        export LC_ALL
        sshd=/usr/sbin/sshd
        if [ -x "$sshd" ]; then
            printf 'sshd=present\n'
            if effective=$("$sshd" -T 2>/dev/null); then
                printf 'sshd_t=ok\n'
                printf '%s\n' "$effective" | awk '$1 == "port" { print "port=" $2 }'
            else
                printf 'sshd_t=failed\n'
            fi
        else
            printf 'sshd=missing\n'
        fi
        if [ -r /sys/fs/selinux/enforce ] && [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = 1 ]; then
            printf 'selinux=enforcing\n'
        elif command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" = Enforcing ]; then
            printf 'selinux=enforcing\n'
        fi
        if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
            printf 'firewall=ufw\n'
        elif command -v firewall-cmd >/dev/null 2>&1 && [ "$(firewall-cmd --state 2>/dev/null)" = running ]; then
            printf 'firewall=firewalld\n'
        fi
        if [ -d /run/systemd/system ] && systemctl is-active --quiet ssh.socket 2>/dev/null; then
            printf 'socket=1\n'
        fi
        main=/etc/ssh/sshd_config
        if [ ! -e "$main" ] && [ -e /usr/etc/ssh/sshd_config ]; then
            main=/usr/etc/ssh/sshd_config
        fi
        printf 'main_config=%s\n' "$main"
        if [ -r "$main" ]; then
            awk '
                tolower($1) == "include" {
                    for (i = 2; i <= NF; i++) {
                        v = $i
                        gsub(/"/, "", v)
                        if (v == "/etc/ssh/sshd_config.d/*.conf" || v == "/etc/ssh/sshd_config.d/*" ||
                            v == "sshd_config.d/*.conf" || v == "sshd_config.d/*") {
                            print "includes=1"
                            exit
                        }
                    }
                }
            ' "$main"
            awk 'tolower($1) == "match" { exit } tolower($1) == "port" && $2 ~ /^[0-9]+$/ { print "main_port=" $2 }' "$main"
        fi
        managed=/etc/ssh/sshd_config.d/00-ssh-key-deployer.conf
        if [ -f "$managed" ] && [ ! -L "$managed" ] &&
            [ "$(head -n 1 "$managed")" = '# Managed by SSH Key Deployer. Local edits will be replaced.' ]; then
            awk '$1 == "Port" && $2 ~ /^[0-9]+$/ { print "managed_port=" $2 }' "$managed"
        fi
        sudoers_found=0
        sudoers_include=0
        for s in /etc/sudoers /usr/etc/sudoers; do
            if [ -f "$s" ]; then
                sudoers_found=1
                if grep -Eq '^[[:space:]]*[@#]includedir[[:space:]]+/etc/sudoers\.d/?[[:space:]]*$' "$s"; then
                    sudoers_include=1
                fi
            fi
        done
        if [ "$sudoers_found" = 1 ]; then
            printf 'sudoers_includedir=%s\n' "$sudoers_include"
        fi
        printf 'probe=done\n'
        """;

    public static UnprivilegedProbe ParseUnprivilegedProbe(string output)
    {
        int? uid = null;
        string id = string.Empty, idLike = string.Empty, pretty = string.Empty, version = string.Empty;
        var commands = new HashSet<string>(StringComparer.Ordinal);
        var init = InitSystem.Other;
        var complete = false;

        foreach (var (key, value) in ParseKeyValues(output))
        {
            switch (key)
            {
                case "uid" when int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed):
                    uid = parsed;
                    break;
                case "id":
                    id = value.ToLowerInvariant();
                    break;
                case "id_like":
                    idLike = value.ToLowerInvariant();
                    break;
                case "pretty":
                    pretty = value;
                    break;
                case "version":
                    version = value;
                    break;
                case "cmd" when value.Length > 0:
                    commands.Add(value);
                    break;
                case "init":
                    init = value switch
                    {
                        "systemd" => InitSystem.Systemd,
                        "openrc" => InitSystem.OpenRc,
                        _ => InitSystem.Other
                    };
                    break;
                case "probe" when value == "done":
                    complete = true;
                    break;
            }
        }

        if (!complete)
        {
            throw new DeploymentException("The server inspection output was incomplete. No server changes were made.");
        }

        return new UnprivilegedProbe(uid, id, idLike, pretty, version, commands, init);
    }

    public static RootProbe ParseRootProbe(string output)
    {
        var sshdAvailable = false;
        var sshdValid = false;
        var ports = new List<int>();
        var selinux = false;
        Firewall? firewall = null;
        var socket = false;
        var mainConfig = "/etc/ssh/sshd_config";
        var includes = false;
        var mainPorts = new List<int>();
        var managedPorts = new List<int>();
        bool? sudoersInclude = null;
        var complete = false;

        foreach (var (key, value) in ParseKeyValues(output))
        {
            switch (key)
            {
                case "sshd":
                    sshdAvailable = value == "present";
                    break;
                case "sshd_t":
                    sshdValid = value == "ok";
                    break;
                case "port" when TryParsePort(value, out var port):
                    AddDistinct(ports, port);
                    break;
                case "selinux":
                    selinux = value == "enforcing";
                    break;
                case "firewall":
                    firewall = value switch
                    {
                        "ufw" => Firewall.Ufw,
                        "firewalld" => Firewall.Firewalld,
                        _ => firewall
                    };
                    break;
                case "socket":
                    socket = value == "1";
                    break;
                case "main_config" when value.StartsWith('/'):
                    mainConfig = value;
                    break;
                case "includes":
                    includes = value == "1";
                    break;
                case "main_port" when TryParsePort(value, out var mainPort):
                    AddDistinct(mainPorts, mainPort);
                    break;
                case "managed_port" when TryParsePort(value, out var managedPort):
                    AddDistinct(managedPorts, managedPort);
                    break;
                case "sudoers_includedir":
                    sudoersInclude = value == "1";
                    break;
                case "probe" when value == "done":
                    complete = true;
                    break;
            }
        }

        if (!complete)
        {
            throw new DeploymentException("The privileged server inspection output was incomplete. No server changes were made.");
        }

        return new RootProbe(
            sshdAvailable,
            sshdValid,
            ports.AsReadOnly(),
            selinux,
            firewall,
            socket,
            mainConfig,
            includes,
            mainPorts.AsReadOnly(),
            managedPorts.AsReadOnly(),
            sudoersInclude);
    }

    public static LinuxFamily DetectFamily(string osId, string osIdLike)
    {
        var fromId = FamilyFromToken(osId.Trim().ToLowerInvariant());
        if (fromId is not null)
        {
            return fromId.Value;
        }

        foreach (var token in osIdLike.ToLowerInvariant().Split(
                     (char[]?)null,
                     StringSplitOptions.RemoveEmptyEntries))
        {
            var family = FamilyFromToken(token);
            if (family is not null)
            {
                return family.Value;
            }
        }

        return LinuxFamily.Unknown;
    }

    public static string CommandName(PackageManager manager) => manager switch
    {
        PackageManager.Apt => "apt-get",
        PackageManager.Dnf => "dnf",
        PackageManager.Yum => "yum",
        PackageManager.Zypper => "zypper",
        PackageManager.Pacman => "pacman",
        PackageManager.Apk => "apk",
        _ => throw new ArgumentOutOfRangeException(nameof(manager), manager, null)
    };

    public static PackageManager? SelectPackageManager(LinuxFamily family, IReadOnlySet<string> commands)
    {
        var preferred = family switch
        {
            LinuxFamily.Debian => new[] { PackageManager.Apt },
            LinuxFamily.Rhel => new[] { PackageManager.Dnf, PackageManager.Yum },
            LinuxFamily.Suse => new[] { PackageManager.Zypper },
            LinuxFamily.Arch => new[] { PackageManager.Pacman },
            LinuxFamily.Alpine => new[] { PackageManager.Apk },
            _ => new[]
            {
                PackageManager.Apt,
                PackageManager.Dnf,
                PackageManager.Yum,
                PackageManager.Zypper,
                PackageManager.Pacman,
                PackageManager.Apk
            }
        };

        foreach (var manager in preferred)
        {
            if (commands.Contains(CommandName(manager)))
            {
                return manager;
            }
        }

        return null;
    }

    /// <summary>
    /// root → Root; working sudo → Sudo; otherwise su with a root password → Su; otherwise None.
    /// </summary>
    public static PrivilegeMode DecidePrivilege(
        bool sessionIsRoot,
        bool sudoSucceeded,
        bool suAvailable,
        bool rootPasswordProvided)
    {
        if (sessionIsRoot)
        {
            return PrivilegeMode.Root;
        }

        if (sudoSucceeded)
        {
            return PrivilegeMode.Sudo;
        }

        return suAvailable && rootPasswordProvided ? PrivilegeMode.Su : PrivilegeMode.None;
    }

    /// <summary>The package that provides semanage, or null when it is not known for this distribution.</summary>
    public static string? SemanagePackage(LinuxFamily family, PackageManager? manager) => family switch
    {
        LinuxFamily.Rhel when manager == PackageManager.Yum => "policycoreutils-python",
        LinuxFamily.Rhel or LinuxFamily.Debian or LinuxFamily.Suse => "policycoreutils-python-utils",
        _ => null
    };

    /// <summary>
    /// Packages that must be installed before any other change. Throws when one is needed but cannot be installed.
    /// </summary>
    public static IReadOnlyList<string> GetRequiredPackages(
        PrivilegeMode privilege,
        bool sudoInstalled,
        LinuxFamily family,
        PackageManager? manager,
        bool changesPort,
        bool selinuxEnforcing,
        bool semanageInstalled)
    {
        var packages = new List<string>();
        if (privilege == PrivilegeMode.Su && !sudoInstalled)
        {
            packages.Add("sudo");
        }

        if (changesPort && selinuxEnforcing && !semanageInstalled)
        {
            var package = SemanagePackage(family, manager)
                ?? throw new DeploymentException(
                    "SELinux is enforcing, so the new SSH port must be labelled with semanage, but semanage is not installed " +
                    "and the package that provides it is not known for this distribution. Install semanage and retry. " +
                    "No server changes were made.");
            packages.Add(package);
        }

        if (packages.Count > 0 && manager is null)
        {
            throw new DeploymentException(
                $"Required packages are missing ({string.Join(", ", packages)}) and no supported package manager " +
                "(apt-get, dnf, yum, zypper, pacman, apk) was found. Install them manually and retry. " +
                "No server changes were made.");
        }

        return packages.AsReadOnly();
    }

    /// <summary>The ports written to the managed drop-in while both the old and the new port are open.</summary>
    public static IReadOnlyList<int> GetTransitionPorts(
        IReadOnlyList<int> currentPorts,
        IReadOnlyList<int> mainConfigPorts,
        int newPort)
    {
        var ports = new List<int>();
        foreach (var port in currentPorts)
        {
            // Ports set in the main sshd_config stay open anyway; repeating them would bind twice.
            if (!mainConfigPorts.Contains(port))
            {
                AddDistinct(ports, port);
            }
        }

        AddDistinct(ports, newPort);
        return ports.AsReadOnly();
    }

    public static DeploymentPlan BuildPlan(
        ServerInfo server,
        DeploymentRequest request,
        IReadOnlyList<string> packages)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(packages);

        var actions = new List<PlannedAction>();
        if (packages.Count > 0)
        {
            actions.Add(new InstallPackagesAction(
                server.PackageManager
                    ?? throw new InvalidOperationException("Packages are required but no package manager was detected."),
                packages));
        }

        if (server.Privilege == PrivilegeMode.Su)
        {
            actions.Add(new TemporarySudoViaSuAction(request.Username));
        }

        actions.Add(new InstallPublicKeyAction(request.Username));
        if (request.EnableRootLogin && !request.Username.Equals("root", StringComparison.Ordinal))
        {
            actions.Add(new InstallPublicKeyAction("root"));
        }

        actions.Add(new WriteSshdPolicyAction(GetRootLoginPolicy(request), request.AllowPasswordLogin));

        if (request.NewSshPort is int newPort)
        {
            if (server.SelinuxEnforcing)
            {
                actions.Add(new LabelSelinuxPortAction(newPort));
            }

            if (server.Firewall is Firewall firewall)
            {
                actions.Add(new OpenFirewallPortAction(firewall, newPort));
            }

            actions.Add(new ChangePortAction(server.CurrentPorts, newPort));
        }

        return new DeploymentPlan(server, new ReadOnlyCollection<PlannedAction>(actions));
    }

    public static RootLoginPolicy GetRootLoginPolicy(DeploymentRequest request) =>
        request.EnableRootLogin
            ? request.AllowPasswordLogin
                ? RootLoginPolicy.PasswordAndKey
                : RootLoginPolicy.KeyOnly
            : RootLoginPolicy.Disabled;

    private static LinuxFamily? FamilyFromToken(string token)
    {
        if (token.StartsWith("opensuse", StringComparison.Ordinal) ||
            token.StartsWith("sle", StringComparison.Ordinal))
        {
            return LinuxFamily.Suse;
        }

        return token switch
        {
            "debian" or "ubuntu" or "raspbian" or "linuxmint" or "pop" or "kali" or "devuan" or "elementary"
                or "zorin" or "neon" or "deepin" or "uos" => LinuxFamily.Debian,
            "rhel" or "centos" or "fedora" or "rocky" or "almalinux" or "ol" or "amzn" or "scientific"
                or "eurolinux" or "circle" or "navy" or "virtuozzo" or "anolis" or "openeuler"
                or "opencloudos" or "tencentos" or "kylin" => LinuxFamily.Rhel,
            "suse" => LinuxFamily.Suse,
            "arch" or "archarm" or "manjaro" or "manjaro-arm" or "endeavouros" or "garuda" or "artix"
                => LinuxFamily.Arch,
            "alpine" or "postmarketos" => LinuxFamily.Alpine,
            _ => null
        };
    }

    private static IEnumerable<(string Key, string Value)> ParseKeyValues(string output)
    {
        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r');
            var separator = line.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            yield return (line[..separator].Trim(), line[(separator + 1)..].Trim());
        }
    }

    private static bool TryParsePort(string value, out int port) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out port) &&
        port is >= 1 and <= 65535;

    private static void AddDistinct(List<int> list, int value)
    {
        if (!list.Contains(value))
        {
            list.Add(value);
        }
    }
}

public static class PrivilegeGuidance
{
    /// <summary>Commands a root console must run so that <paramref name="username"/> can use sudo.</summary>
    public static IReadOnlyList<string> GetSudoSetupCommands(
        LinuxFamily family,
        string username,
        bool sudoInstalled)
    {
        var commands = new List<string>();
        const string wheelRule = "echo '%wheel ALL=(ALL:ALL) ALL' > /etc/sudoers.d/10-wheel && chmod 0440 /etc/sudoers.d/10-wheel";
        switch (family)
        {
            case LinuxFamily.Debian:
                if (!sudoInstalled)
                {
                    commands.Add("apt-get update && apt-get install -y sudo");
                }

                commands.Add($"usermod -aG sudo {username}");
                break;
            case LinuxFamily.Rhel:
                if (!sudoInstalled)
                {
                    commands.Add("dnf install -y sudo");
                }

                commands.Add($"usermod -aG wheel {username}");
                break;
            case LinuxFamily.Suse:
                if (!sudoInstalled)
                {
                    commands.Add("zypper --non-interactive install sudo");
                }

                commands.Add($"usermod -aG wheel {username}");
                // openSUSE ships "Defaults targetpw", which makes sudo ask for the root password.
                commands.Add("printf '%s\\n' 'Defaults:%wheel !targetpw' '%wheel ALL=(ALL:ALL) ALL' > /etc/sudoers.d/10-wheel && chmod 0440 /etc/sudoers.d/10-wheel");
                break;
            case LinuxFamily.Arch:
                if (!sudoInstalled)
                {
                    commands.Add("pacman -S --needed --noconfirm sudo");
                }

                commands.Add($"usermod -aG wheel {username}");
                commands.Add(wheelRule);
                break;
            case LinuxFamily.Alpine:
                if (!sudoInstalled)
                {
                    commands.Add("apk add sudo");
                }

                commands.Add($"addgroup {username} wheel");
                commands.Add(wheelRule);
                break;
            default:
                if (!sudoInstalled)
                {
                    commands.Add("install the 'sudo' package with the system package manager");
                }

                commands.Add($"usermod -aG sudo {username}  (or: usermod -aG wheel {username})");
                break;
        }

        return commands.AsReadOnly();
    }
}
