using System.Globalization;

namespace SshKeyDeployer.Core;

/// <summary>
/// POSIX sh scripts that run as root on the server. They avoid GNU-only options so that BusyBox
/// (Alpine) works too. Placeholders are only ever replaced with validated numbers, generated paths,
/// or shell-quoted account names.
/// </summary>
internal static class RemoteScripts
{
    internal const string RootPath =
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH\nLC_ALL=C\nexport LC_ALL\n";

    private const string ReloadTemplate =
        """
        restart_socket=__SOCKET__
        if [ "$restart_socket" = 1 ]; then
            systemctl daemon-reload || exit 1
            systemctl restart ssh.socket || exit 1
            if systemctl is-active --quiet ssh.service; then
                systemctl reload ssh.service || exit 1
            fi
            exit 0
        fi
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            for unit in ssh.service sshd.service; do
                if systemctl is-active --quiet "$unit"; then
                    systemctl reload "$unit" && exit 0
                fi
            done
            if systemctl is-active --quiet ssh.socket; then
                # Socket-activated sshd reads the configuration again for the next connection.
                exit 0
            fi
        fi
        if command -v rc-service >/dev/null 2>&1 && rc-service sshd status >/dev/null 2>&1; then
            rc-service sshd reload && exit 0
        fi
        if command -v service >/dev/null 2>&1; then
            service ssh reload >/dev/null 2>&1 && exit 0
            service sshd reload >/dev/null 2>&1 && exit 0
        fi
        for pidfile in /run/sshd.pid /var/run/sshd.pid; do
            if [ -f "$pidfile" ]; then
                pid=$(cat "$pidfile")
                case "$pid" in
                    '' | *[!0-9]*) ;;
                    *) kill -HUP "$pid" && exit 0 ;;
                esac
            fi
        done
        # Some sshd builds (e.g. openSUSE in -D mode) write no pid file: signal the
        # listener, which is the oldest process named exactly sshd.
        if command -v pgrep >/dev/null 2>&1; then
            pid=$(pgrep -o -x sshd || true)
            case "$pid" in
                '' | *[!0-9]*) ;;
                *) kill -HUP "$pid" && exit 0 ;;
            esac
        fi
        echo 'No supported way to reload sshd was found (systemd, OpenRC, service, or sshd.pid).' >&2
        exit 1
        """;

    private const string SelinuxPortCheckTemplate =
        """
        port=__PORT__
        if semanage port -l -C 2>/dev/null | awk -v p="$port" '
            $2 == "tcp" {
                for (i = 3; i <= NF; i++) {
                    v = $i
                    gsub(",", "", v)
                    if (v == p && $1 != "ssh_port_t") found = 1
                }
            }
            END { exit !found }'; then
            echo "TCP port $port already has a local SELinux label of another type; choose a different port." >&2
            exit 75
        fi
        if semanage port -l | awk -v p="$port" '
            $1 == "ssh_port_t" && $2 == "tcp" {
                for (i = 3; i <= NF; i++) {
                    v = $i
                    gsub(",", "", v)
                    if (v == p) found = 1
                }
            }
            END { exit !found }'; then
            echo present
        else
            echo absent
        fi
        """;

    private const string SelinuxPortAddTemplate =
        """
        port=__PORT__
        if semanage port -a -t ssh_port_t -p tcp "$port" 2>/dev/null; then
            echo added
            exit 0
        fi
        semanage port -m -t ssh_port_t -p tcp "$port"
        echo modified
        """;

    private const string SelinuxPortRemoveTemplate =
        """
        port=__PORT__
        if semanage port -l -C 2>/dev/null | awk -v p="$port" '
            $1 == "ssh_port_t" && $2 == "tcp" {
                for (i = 3; i <= NF; i++) {
                    v = $i
                    gsub(",", "", v)
                    if (v == p) found = 1
                }
            }
            END { exit !found }'; then
            semanage port -d -p tcp "$port"
        fi
        echo removed
        """;

    private const string UfwCheckTemplate =
        """
        port=__PORT__
        if ufw show added 2>/dev/null | grep -Eq "^ufw allow ${port}(/tcp)?\$"; then
            echo present
        else
            echo absent
        fi
        """;

    private const string UfwAddTemplate =
        """
        port=__PORT__
        ufw allow "${port}/tcp" >/dev/null
        echo added
        """;

    private const string UfwRemoveTemplate =
        """
        port=__PORT__
        ufw --force delete allow "${port}/tcp" >/dev/null
        echo removed
        """;

    private const string FirewalldCheckTemplate =
        """
        port=__PORT__
        if firewall-cmd --query-port="${port}/tcp" >/dev/null 2>&1; then
            echo runtime=1
        else
            echo runtime=0
        fi
        if firewall-cmd --permanent --query-port="${port}/tcp" >/dev/null 2>&1; then
            echo permanent=1
        else
            echo permanent=0
        fi
        """;

    private const string FirewalldChangeTemplate =
        """
        port=__PORT__
        runtime=__RUNTIME__
        permanent=__PERMANENT__
        action=__ACTION__
        if [ "$permanent" = 1 ]; then
            firewall-cmd --permanent "--${action}-port=${port}/tcp" >/dev/null || exit 1
        fi
        if [ "$runtime" = 1 ]; then
            firewall-cmd "--${action}-port=${port}/tcp" >/dev/null || exit 1
        fi
        echo done
        """;

    private const string InstallPackagesTemplate =
        """
        set -eu
        log=$(mktemp /tmp/ssh-key-deployer-packages.XXXXXXXXXX)
        trap 'rm -f -- "$log"' EXIT
        if ! { __INSTALL__ ; } </dev/null >"$log" 2>&1; then
            tail -n 40 "$log" >&2
            exit 1
        fi
        echo installed
        """;

    private const string CreateSudoersTemplate =
        """
        set -eu
        umask 077
        user=__USER__
        final=__FINAL__
        tmp=__TMP__
        if ! command -v visudo >/dev/null 2>&1; then
            echo 'visudo was not found; sudo does not seem to be installed.' >&2
            exit 70
        fi
        include=0
        for s in /etc/sudoers /usr/etc/sudoers; do
            if [ -f "$s" ] && grep -Eq '^[[:space:]]*[@#]includedir[[:space:]]+/etc/sudoers\.d/?[[:space:]]*$' "$s"; then
                include=1
            fi
        done
        if [ "$include" != 1 ]; then
            echo 'The sudoers configuration does not include /etc/sudoers.d.' >&2
            exit 76
        fi
        if [ ! -d /etc/sudoers.d ]; then
            mkdir -m 0750 /etc/sudoers.d
        fi
        test ! -L /etc/sudoers.d
        test ! -e "$final"
        test ! -L "$final"
        rm -f -- "$tmp"
        trap 'rm -f -- "$tmp"' EXIT
        printf '%s\n' \
            '# Temporary sudo grant by SSH Key Deployer; removed automatically.' \
            "Defaults:$user !targetpw, !rootpw, !runaspw" \
            "$user ALL=(ALL:ALL) ALL" > "$tmp"
        chown root:root "$tmp"
        chmod 0440 "$tmp"
        visudo -cf "$tmp" >/dev/null
        mv -f -- "$tmp" "$final"
        trap - EXIT
        if ! visudo -c >/dev/null 2>&1; then
            rm -f -- "$final"
            echo 'sudoers did not validate with the temporary grant; it was removed again.' >&2
            exit 77
        fi
        echo created
        """;

    private const string RemoveSudoersTemplate =
        """
        set -eu
        final=__FINAL__
        tmp=__TMP__
        rm -f -- "$final" "$tmp"
        test ! -e "$final"
        echo removed
        """;

    public static string Reload(bool restartSocket) =>
        RootPath + ReloadTemplate.Replace("__SOCKET__", restartSocket ? "1" : "0", StringComparison.Ordinal);

    public static string SelinuxPortCheck(int port) => RootPath + WithPort(SelinuxPortCheckTemplate, port);

    public static string SelinuxPortAdd(int port) => RootPath + WithPort(SelinuxPortAddTemplate, port);

    public static string SelinuxPortRemove(int port) => RootPath + WithPort(SelinuxPortRemoveTemplate, port);

    public static string UfwCheck(int port) => RootPath + WithPort(UfwCheckTemplate, port);

    public static string UfwAdd(int port) => RootPath + WithPort(UfwAddTemplate, port);

    public static string UfwRemove(int port) => RootPath + WithPort(UfwRemoveTemplate, port);

    public static string FirewalldCheck(int port) => RootPath + WithPort(FirewalldCheckTemplate, port);

    public static string FirewalldChange(int port, bool runtime, bool permanent, bool add) =>
        RootPath + WithPort(FirewalldChangeTemplate, port)
            .Replace("__RUNTIME__", runtime ? "1" : "0", StringComparison.Ordinal)
            .Replace("__PERMANENT__", permanent ? "1" : "0", StringComparison.Ordinal)
            .Replace("__ACTION__", add ? "add" : "remove", StringComparison.Ordinal);

    public static string InstallPackages(PackageManager manager, IReadOnlyList<string> packages)
    {
        foreach (var package in packages)
        {
            if (package.Length == 0 || !package.All(c => char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c is '-' or '.' or '+'))
            {
                throw new ArgumentException($"Unexpected package name '{package}'.", nameof(packages));
            }
        }

        var list = string.Join(' ', packages);
        var command = manager switch
        {
            PackageManager.Apt =>
                $"DEBIAN_FRONTEND=noninteractive apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q {list}",
            PackageManager.Dnf => $"dnf install -y {list}",
            PackageManager.Yum => $"yum install -y {list}",
            PackageManager.Zypper => $"zypper --non-interactive install --no-recommends {list}",
            PackageManager.Pacman => $"pacman -S --needed --noconfirm {list}",
            PackageManager.Apk => $"apk update -q && apk add -q {list}",
            _ => throw new ArgumentOutOfRangeException(nameof(manager), manager, null)
        };
        return RootPath + InstallPackagesTemplate.Replace("__INSTALL__", command, StringComparison.Ordinal);
    }

    public static string CreateSudoersDropIn(string username, string finalPath, string temporaryPath)
    {
        EnsureSudoersPath(finalPath, temporaryPath);
        return RootPath + CreateSudoersTemplate
            .Replace("__USER__", ShellQuote(username), StringComparison.Ordinal)
            .Replace("__FINAL__", finalPath, StringComparison.Ordinal)
            .Replace("__TMP__", temporaryPath, StringComparison.Ordinal);
    }

    public static string RemoveSudoersDropIn(string finalPath, string temporaryPath)
    {
        EnsureSudoersPath(finalPath, temporaryPath);
        return RootPath + RemoveSudoersTemplate
            .Replace("__FINAL__", finalPath, StringComparison.Ordinal)
            .Replace("__TMP__", temporaryPath, StringComparison.Ordinal);
    }

    /// <summary>Paths for a new temporary sudoers grant. sudo ignores names that contain a dot.</summary>
    public static (string Final, string Temporary) NewSudoersPaths()
    {
        var id = Guid.NewGuid().ToString("N");
        return ($"/etc/sudoers.d/zz-ssh-key-deployer-{id}", $"/etc/sudoers.d/.ssh-key-deployer-{id}.tmp");
    }

    /// <summary>Every script with sample values, for syntax checks in the self-tests.</summary>
    public static IEnumerable<(string Name, string Script)> SamplesForSyntaxCheck()
    {
        var (final, temporary) = NewSudoersPaths();
        yield return ("reload", Reload(false));
        yield return ("reload-socket", Reload(true));
        yield return ("selinux-check", SelinuxPortCheck(2222));
        yield return ("selinux-add", SelinuxPortAdd(2222));
        yield return ("selinux-remove", SelinuxPortRemove(2222));
        yield return ("ufw-check", UfwCheck(2222));
        yield return ("ufw-add", UfwAdd(2222));
        yield return ("ufw-remove", UfwRemove(2222));
        yield return ("firewalld-check", FirewalldCheck(2222));
        yield return ("firewalld-add", FirewalldChange(2222, true, true, add: true));
        yield return ("firewalld-remove", FirewalldChange(2222, true, false, add: false));
        foreach (var manager in Enum.GetValues<PackageManager>())
        {
            yield return ($"packages-{manager}", InstallPackages(manager, ["sudo"]));
        }

        yield return ("sudoers-create", CreateSudoersDropIn("deploy-user", final, temporary));
        yield return ("sudoers-remove", RemoveSudoersDropIn(final, temporary));
        yield return ("probe-unprivileged", ServerInspection.UnprivilegedProbeScript);
        yield return ("probe-root", RootPath + ServerInspection.RootProbeScript);
    }

    private static string WithPort(string template, int port)
    {
        if (port is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port));
        }

        return template.Replace("__PORT__", port.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);
    }

    private static void EnsureSudoersPath(string finalPath, string temporaryPath)
    {
        if (!IsHexSuffixed(finalPath, "/etc/sudoers.d/zz-ssh-key-deployer-", string.Empty) ||
            !IsHexSuffixed(temporaryPath, "/etc/sudoers.d/.ssh-key-deployer-", ".tmp"))
        {
            throw new ArgumentException("Unexpected sudoers drop-in path.");
        }
    }

    private static bool IsHexSuffixed(string value, string prefix, string suffix)
    {
        if (!value.StartsWith(prefix, StringComparison.Ordinal) ||
            !value.EndsWith(suffix, StringComparison.Ordinal))
        {
            return false;
        }

        var middle = value[prefix.Length..^suffix.Length];
        return middle.Length == 32 && middle.All(c => char.IsAsciiDigit(c) || c is >= 'a' and <= 'f');
    }

    internal static string ShellQuote(string value) =>
        $"'{value.Replace("'", "'\"'\"'", StringComparison.Ordinal)}'";
}
