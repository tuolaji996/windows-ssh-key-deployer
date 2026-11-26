import Foundation

/// POSIX shell programs executed on the Linux server (GNU coreutils or BusyBox).
///
/// Each program is wrapped in `sh -c '<script>'` so it behaves the same whatever
/// the account's login shell is. Values are never interpolated into scripts except
/// through `shellQuote`; keys and configuration travel on standard input.
enum RemoteScripts {
    static let managedConfigPath = "/etc/ssh/sshd_config.d/00-ssh-key-deployer.conf"
    static let managedConfigMarker = "# Managed by SSH Key Deployer. Local edits will be replaced."
    static let sshdPath = "/usr/sbin/sshd"

    static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    static func shell(_ script: String) -> String {
        "sh -c " + shellQuote(script.replacingOccurrences(of: "\r", with: ""))
    }

    /// Runs `command` as root with the password supplied as the first stdin line.
    static func sudo(_ command: String) -> String {
        "sudo -k -S -p '' -- \(command)"
    }

    /// Runs `command` as root when it also needs its own standard input: the password
    /// line is consumed first and the remaining input is staged in a private temp file.
    static func sudoWithPayload(_ command: String) -> String {
        let outer =
            "set -eu; umask 077; " +
            "work=$(mktemp -d /tmp/ssh-key-deployer-sudo.XXXXXXXXXX); " +
            "trap 'rm -f -- \"$work/payload\"; rmdir -- \"$work\"' EXIT; " +
            "IFS= read -r password; cat > \"$work/payload\"; " +
            "printf '%s\\n' \"$password\" | " +
            "sudo -k -S -p '' -- sh -c \"$1\" sh \"$work/payload\""
        let privileged = "exec \(command) < \"$1\""
        return "sh -c \(shellQuote(outer)) sh \(shellQuote(privileged))"
    }

    // MARK: - sshd configuration

    /// - Parameter ports: `Port` lines to add. Empty keeps sshd's existing ports.
    static func managedConfig(rootLogin: RootLoginPolicy, allowPasswordLogin: Bool, ports: [Int] = []) -> String {
        var text = """
        \(managedConfigMarker)
        # Loaded early so these verified authentication settings take precedence.
        PubkeyAuthentication yes
        PasswordAuthentication \(allowPasswordLogin ? "yes" : "no")
        KbdInteractiveAuthentication no
        PermitRootLogin \(rootLogin.sshdValue)

        """
        var seen = Set<Int>()
        for port in ports where (1...65_535).contains(port) && seen.insert(port).inserted {
            text += "Port \(port)\n"
        }
        return text
    }

    /// Checks that the managed path is ours to replace and backs it up.
    /// Prints `BACKUP` when an earlier managed file was copied, `NEW` when none existed.
    /// Replaces five separate round trips in the original implementation.
    static func inspectManagedConfig(backupPath: String) -> String {
        shell("""
        set -eu
        cfg=\(shellQuote(managedConfigPath))
        backup=\(shellQuote(backupPath))
        install -d -o root -g root -m 0755 -- /etc/ssh/sshd_config.d
        if test -L "$cfg"; then
            printf '%s\\n' "Refusing to replace the symbolic link at $cfg." >&2
            exit 80
        fi
        if test -e "$cfg"; then
            if ! test -f "$cfg"; then
                printf '%s\\n' "Refusing to replace a non-regular file at $cfg." >&2
                exit 81
            fi
            if test "$(head -n 1 -- "$cfg")" != \(shellQuote(managedConfigMarker)); then
                printf '%s\\n' "Refusing to replace $cfg because it is not owned by SSH Key Deployer." >&2
                exit 82
            fi
            test ! -e "$backup" && test ! -L "$backup" || exit 1
            cp -a -- "$cfg" "$backup"
            printf 'BACKUP\\n'
        else
            printf 'NEW\\n'
        fi
        """)
    }

    /// Writes the configuration from stdin to a private temp file and atomically
    /// activates it. The temp file is removed on any failure.
    static let activateManagedConfig = shell("""
    set -eu
    umask 077
    tmp=$(mktemp /etc/ssh/sshd_config.d/.ssh-key-deployer.XXXXXXXXXX)
    trap 'rm -f -- "$tmp"' EXIT
    cat > "$tmp"
    chown root:root -- "$tmp"
    chmod 0644 -- "$tmp"
    cfg=\(shellQuote(managedConfigPath))
    if test -d "$cfg" || test -L "$cfg"; then
        printf '%s\\n' "Refusing to replace the directory or symbolic link at $cfg." >&2
        exit 83
    fi
    mv -f -- "$tmp" "$cfg"
    trap - EXIT
    """)

    static func restoreManagedConfig(originalExisted: Bool, backupPath: String) -> String {
        originalExisted
            ? shell("""
            set -eu
            cfg=\(shellQuote(managedConfigPath))
            test ! -d "$cfg" || exit 83
            test ! -L "$cfg" || rm -f -- "$cfg"
            mv -f -- \(shellQuote(backupPath)) "$cfg"
            """)
            : "rm -f -- \(shellQuote(managedConfigPath))"
    }

    static func removeFile(_ path: String) -> String {
        "rm -f -- \(shellQuote(path))"
    }

    /// A fixed PATH: an unprivileged login (Debian) or `su` may not include the sbin directories.
    static let systemPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH"

    /// Reloads sshd on systemd, OpenRC, SysV-style `service`, or a bare sshd (containers).
    ///
    /// With `restartSocket`, a socket-activated sshd (Ubuntu 22.10+) also gets its
    /// listening ports regenerated: `daemon-reload` reruns the sshd socket generator and
    /// restarting `ssh.socket` rebinds. Established connections survive both.
    static func reloadSshd(restartSocket: Bool = false) -> String {
        let socket = restartSocket ? """
        if test -d /run/systemd/system && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ssh.socket; then
            systemctl daemon-reload || exit 1
            systemctl restart ssh.socket || exit 1
            if systemctl is-active --quiet ssh.service; then systemctl reload ssh.service || true; fi
            exit 0
        fi
        """ : ":"
        return shell("""
        set -u
        \(systemPath)
        \(socket)
        if test -d /run/systemd/system && command -v systemctl >/dev/null 2>&1; then
            for unit in ssh.service sshd.service; do
                if systemctl is-active --quiet "$unit"; then
                    systemctl reload "$unit"
                    exit $?
                fi
            done
        fi
        if command -v rc-service >/dev/null 2>&1 && rc-service sshd status >/dev/null 2>&1; then
            rc-service sshd reload
            exit $?
        fi
        if command -v service >/dev/null 2>&1; then
            for name in ssh sshd; do
                if service "$name" status >/dev/null 2>&1; then
                    service "$name" reload
                    exit $?
                fi
            done
        fi
        for pidfile in /run/sshd.pid /var/run/sshd.pid; do
            if test -f "$pidfile" && test ! -L "$pidfile"; then
                pid=$(head -n 1 -- "$pidfile")
                case "$pid" in ''|*[!0-9]*) continue ;; esac
                kill -HUP "$pid"
                exit $?
            fi
        done
        # Some sshd builds (e.g. openSUSE in -D mode) write no pid file: signal the
        # listener, which is the oldest process named exactly sshd.
        if command -v pgrep >/dev/null 2>&1; then
            pid=$(pgrep -o -x sshd || true)
            case "$pid" in ''|*[!0-9]*) ;; *) kill -HUP "$pid"; exit $? ;; esac
        fi
        printf '%s\\n' 'No running SSH service was found to reload.' >&2
        exit 1
        """)
    }

    // MARK: - Server inspection

    /// Unprivileged, read-only probe. Prints `KEY=VALUE` lines; os-release lines are
    /// passed through with an `OS_` prefix and parsed (with their quoting) locally.
    static let inspectServer = shell("""
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}; export PATH
    printf 'UID=%s\\n' "$(id -u)"
    for file in /etc/os-release /usr/lib/os-release; do
        if test -r "$file"; then
            sed -n 's/^\\([A-Z_][A-Z0-9_]*\\)=/OS_\\1=/p' "$file"
            break
        fi
    done
    for tool in sudo su visudo apt-get dnf yum zypper pacman apk restorecon semanage getenforce systemctl rc-service; do
        if command -v "$tool" >/dev/null 2>&1; then printf 'HAS=%s\\n' "$tool"; fi
    done
    if test -d /run/systemd/system; then
        printf 'INIT=systemd\\n'
    elif command -v rc-service >/dev/null 2>&1; then
        printf 'INIT=openrc\\n'
    else
        printf 'INIT=other\\n'
    fi
    """)

    /// Root, read-only probe: sshd ports and drop-in support, SELinux, firewall, socket activation.
    /// Only `Include`/`Port` lines before the first `Match` of the main config are reported.
    static let inspectServerAsRoot = shell("""
    set -u
    \(systemPath)
    if test -x \(sshdPath); then printf 'SSHD=yes\\n'; else printf 'SSHD=no\\n'; fi
    if effective=$(\(sshdPath) -T 2>&1); then
        printf '%s\\n' "$effective" | awk 'tolower($1) == "port" { print "PORT=" $2 }'
    else
        printf '%s\\n' "$effective" | head -n 5 | sed 's/^/SSHD_T_ERROR=/'
    fi
    if test -f /etc/ssh/sshd_config; then
        main=/etc/ssh/sshd_config
    elif test -f /usr/etc/ssh/sshd_config; then
        main=/usr/etc/ssh/sshd_config
    else
        main=
    fi
    printf 'MAIN_CONFIG=%s\\n' "$main"
    if test -n "$main"; then
        awk '
            { sub(/^[ \\t]+/, "") }
            /^#/ || NF == 0 { next }
            { key = tolower($1); sub(/=.*/, "", key) }
            key == "match" { exit }
            key == "include" { line = $0; sub(/^[^ \\t=]+[ \\t=]+/, "", line); print "INCLUDE=" line }
            key == "port" { line = $0; sub(/^[^ \\t=]+[ \\t=]+/, "", line); print "MAIN_PORT=" line }
        ' "$main"
    fi
    managed=\(shellQuote(managedConfigPath))
    if test -f "$managed" && test ! -L "$managed"; then
        awk 'tolower($1) == "port" { print "MANAGED_PORT=" $2 }' "$managed"
    fi
    if command -v getenforce >/dev/null 2>&1; then
        printf 'SELINUX=%s\\n' "$(getenforce 2>/dev/null)"
    fi
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        printf 'FIREWALL=ufw\\n'
    elif command -v firewall-cmd >/dev/null 2>&1 && test "$(firewall-cmd --state 2>/dev/null)" = running; then
        printf 'FIREWALL=firewalld\\n'
    fi
    if test -d /run/systemd/system && command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet ssh.socket; then printf 'SOCKET=active\\n'; fi
        if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then printf 'SOCKET_ENABLED=yes\\n'; fi
    fi
    exit 0
    """)

    // MARK: - Privileges through su

    /// Printed by root's shell before the script, so output before it is su's own
    /// (prompt or error) and output after it belongs to the script.
    static let suStartMarker = "SKD-SU-BEGIN"

    /// Runs `script` (a complete `sh -c` command) as root through `su`. The root
    /// password is typed into the terminal by `InteractiveProcess`, never put here.
    static func su(_ script: String) -> String {
        let rootCommand = "printf '%s\\n' \(suStartMarker) && \(script)"
        return "env LC_ALL=C su root -c \(shellQuote(rootCommand))"
    }

    /// Installs packages non-interactively. Packages are persistent and never removed.
    static func installPackages(_ manager: PackageManager, _ packages: [String]) -> String {
        let list = packages.map(shellQuote).joined(separator: " ")
        let command: String
        switch manager {
        case .apt:
            command = """
            apt-get update -q || true
            apt-get install -y -q --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \(list)
            """
        case .dnf: command = "dnf -y install \(list)"
        case .yum: command = "yum -y install \(list)"
        case .zypper: command = "zypper --non-interactive install --no-recommends \(list)"
        case .pacman: command = "pacman -S --noconfirm --needed \(list)"
        case .apk: command = "apk add --no-progress --update-cache \(list)"
        }
        return shell("""
        set -eu
        \(systemPath)
        DEBIAN_FRONTEND=noninteractive
        export DEBIAN_FRONTEND
        \(command)
        """)
    }

    static let temporarySudoersPrefix = "/etc/sudoers.d/zz-ssh-key-deployer-"

    /// Grants `username` sudo with its own password through a validated drop-in.
    /// The name has no dot so sudo's includedir reads it; `zz-` makes its Defaults win.
    static func createTemporarySudoers(path: String, username: String) -> String {
        shell("""
        set -eu
        \(systemPath)
        umask 077
        dropin=\(shellQuote(path))
        user=\(shellQuote(username))
        case "$dropin" in \(temporarySudoersPrefix)[0-9a-f]*) ;; *) exit 66 ;; esac
        if test -f /etc/sudoers; then
            main=/etc/sudoers
        elif test -f /usr/etc/sudoers; then
            main=/usr/etc/sudoers
        else
            printf '%s\\n' 'sudo is not configured: /etc/sudoers does not exist.' >&2
            exit 90
        fi
        if ! grep -Eq '^[[:space:]]*[#@]includedir[[:space:]]+/etc/sudoers\\.d/?[[:space:]]*$' "$main"; then
            printf '%s\\n' "$main does not include /etc/sudoers.d (#includedir or @includedir)." >&2
            exit 91
        fi
        if ! command -v visudo >/dev/null 2>&1; then
            printf '%s\\n' 'visudo is not installed, so the sudo rule cannot be validated.' >&2
            exit 92
        fi
        if ! test -d /etc/sudoers.d; then
            mkdir -m 0750 /etc/sudoers.d
        fi
        test ! -e "$dropin" && test ! -L "$dropin" || exit 1
        tmp=$(mktemp /etc/sudoers.d/.ssh-key-deployer.XXXXXXXXXX)
        trap 'rm -f -- "$tmp"' EXIT
        write_rule() {
            chmod 0600 "$tmp"
            {
                printf '%s\\n' '# Temporary rule from SSH Key Deployer; removed when the deployment ends.'
                printf 'Defaults:%s %s\\n' "$user" "$1"
                printf '%s ALL=(ALL:ALL) ALL\\n' "$user"
            } > "$tmp"
            chown root:root "$tmp"
            chmod 0440 "$tmp"
        }
        # sudo-rs (Ubuntu 25.10+) knows only a subset of the Defaults options.
        write_rule '!targetpw, !rootpw, !runaspw'
        if ! visudo -cf "$tmp" >/dev/null 2>&1; then
            write_rule '!targetpw, !rootpw'
            visudo -cf "$tmp" >/dev/null
        fi
        mv -f -- "$tmp" "$dropin"
        trap - EXIT
        if ! visudo -c >/dev/null 2>&1; then
            rm -f -- "$dropin"
            printf '%s\\n' 'The sudo configuration did not validate with the temporary rule; it was removed.' >&2
            exit 93
        fi
        printf 'SUDOERS=ok\\n'
        """)
    }

    static func removeTemporarySudoers(path: String) -> String {
        shell("""
        set -eu
        dropin=\(shellQuote(path))
        case "$dropin" in \(temporarySudoersPrefix)[0-9a-f]*) ;; *) exit 66 ;; esac
        rm -f -- "$dropin"
        test ! -e "$dropin"
        """)
    }

    // MARK: - Port change: SELinux and firewall

    /// Prints `TYPE=<selinux type>` for every SELinux label on tcp `port`.
    static func selinuxPortTypes(_ port: Int) -> String {
        shell("""
        set -eu
        \(systemPath)
        listing=$(semanage port -l)
        printf '%s\\n' "$listing" | awk -v want=\(port) '
            $2 == "tcp" { for (i = 3; i <= NF; i++) { p = $i; sub(/,$/, "", p); if (p == want) print "TYPE=" $1 } }
        '
        """)
    }

    static func selinuxAddSshPort(_ port: Int) -> String {
        shell("\(systemPath)\nsemanage port -a -t ssh_port_t -p tcp \(port)")
    }

    static func selinuxRemoveSshPort(_ port: Int) -> String {
        shell("\(systemPath)\nsemanage port -d -t ssh_port_t -p tcp \(port)")
    }

    /// Prints ufw's own report (`Rule added` or `Skipping adding existing rule`).
    static func ufwAllow(_ port: Int) -> String {
        shell("\(systemPath)\nufw allow \(port)/tcp")
    }

    static func ufwDelete(_ port: Int) -> String {
        shell("\(systemPath)\nufw delete allow \(port)/tcp")
    }

    /// Prints `RUNTIME=yes|no` and `PERMANENT=yes|no`.
    static func firewalldQuery(_ port: Int) -> String {
        shell("""
        \(systemPath)
        if firewall-cmd --query-port=\(port)/tcp >/dev/null 2>&1; then echo RUNTIME=yes; else echo RUNTIME=no; fi
        if firewall-cmd --permanent --query-port=\(port)/tcp >/dev/null 2>&1; then echo PERMANENT=yes; else echo PERMANENT=no; fi
        """)
    }

    static func firewalld(add: Bool, permanent: Bool, _ port: Int) -> String {
        shell("\(systemPath)\nfirewall-cmd \(permanent ? "--permanent " : "")--\(add ? "add" : "remove")-port=\(port)/tcp")
    }

    // MARK: - authorized_keys

    private static let snapshotFiles =
        "\"$txn/ready\" \"$txn/file.existed\" \"$txn/directory.existed\" \"$txn/directory.meta\" " +
        "\"$txn/directory.timestamps\" \"$txn/authorized_keys\" \"$txn/expected\" \"$txn/key.added\" \"$txn/key.existed\""

    private static func sshDirectory(root: Bool) -> String {
        root ? "sshdir=/root/.ssh" : "sshdir=\"$HOME/.ssh\""
    }

    /// Records the state of `~/.ssh` and `authorized_keys` so they can be restored exactly.
    static func snapshotAuthorizedKeys(backupPath: String, root: Bool) -> String {
        shell("""
        set -eu
        umask 077
        txn=\(shellQuote(backupPath))
        test ! -e "$txn" && test ! -L "$txn" || exit 1
        mkdir -m 0700 -- "$txn"
        cleanup_partial() {
            rm -f -- \(snapshotFiles)
            rmdir -- "$txn" 2>/dev/null || true
        }
        trap cleanup_partial EXIT
        \(sshDirectory(root: root))
        test ! -L "$sshdir"
        if test -e "$sshdir"; then
            test -d "$sshdir"
            stat -c '%a %u %g' -- "$sshdir" > "$txn/directory.meta"
            touch -r "$sshdir" -- "$txn/directory.timestamps"
            : > "$txn/directory.existed"
            file="$sshdir/authorized_keys"
            test ! -L "$file"
            if test -e "$file"; then
                test -f "$file"
                cp -a -- "$file" "$txn/authorized_keys"
                : > "$txn/file.existed"
            fi
        fi
        : > "$txn/ready"
        trap - EXIT
        """)
    }

    /// Reads the snapshot path and then the public key from stdin and appends the key
    /// unless it is already present. Prints `ADDED` or `EXISTS`.
    static func installPublicKey(root: Bool) -> String {
        let ensureDirectory = root
            ? "install -d -o root -g root -m 0700 -- \"$sshdir\""
            : "install -d -m 0700 -- \"$sshdir\""
        let ownFile = root ? "chown root:root -- \"$file\"" : ":"
        let ownTemp = root ? "chown root:root -- \"$tmp\"" : ":"
        return shell("""
        set -eu
        umask 077
        IFS= read -r txn
        case "$txn" in /tmp/ssh-key-deployer-authorized-[0-9a-f]*) ;; *) exit 66 ;; esac
        PATH="$PATH:/usr/sbin:/sbin"
        # SELinux: authorized_keys must carry the ssh_home_t label. Best effort.
        relabel() {
            if command -v restorecon >/dev/null 2>&1; then
                restorecon -R "$sshdir" >/dev/null 2>&1 || true
            fi
        }
        test -d "$txn" && test ! -L "$txn" || exit 1
        test -f "$txn/ready" && test ! -L "$txn/ready" || exit 1
        \(sshDirectory(root: root))
        test ! -L "$sshdir"
        \(ensureDirectory)
        file="$sshdir/authorized_keys"
        test ! -L "$file"
        if test -e "$file"; then test -f "$file"; fi
        touch -- "$file"
        \(ownFile)
        chmod 0600 -- "$file"
        key=$(cat)
        set -- $key
        test "$#" -ge 2 && test "$1" = ssh-ed25519 || exit 65
        blob=$2
        if awk -v blob="$blob" '$1 == "ssh-ed25519" && $2 == blob { found=1 } END { exit !found }' "$file"; then
            cp -a -- "$file" "$txn/expected"
            : > "$txn/key.existed"
            relabel
            printf 'EXISTS\\n'
            exit 0
        fi
        tmp=$(mktemp "$sshdir/.authorized_keys.XXXXXXXXXX")
        trap 'rm -f -- "$tmp"' EXIT
        cat -- "$file" > "$tmp"
        test ! -s "$tmp" || printf '\\n' >> "$tmp"
        printf '%s\\n' "$key" >> "$tmp"
        \(ownTemp)
        chmod 0600 -- "$tmp"
        cp -a -- "$tmp" "$txn/expected"
        : > "$txn/key.added"
        test ! -d "$file" || exit 74; mv -f -- "$tmp" "$file"
        trap - EXIT
        relabel
        printf 'ADDED\\n'
        """)
    }

    /// Restores the snapshot, or removes only the added key if `authorized_keys` was
    /// changed concurrently. Refuses (exit 73) rather than discard someone else's edit.
    static func restoreAuthorizedKeys(backupPath: String, root: Bool) -> String {
        let restoreOwner = root ? "chown \"$directory_uid:$directory_gid\" -- \"$sshdir\"" : ":"
        let ownTemp = root ? "chown root:root -- \"$tmp\"" : ":"
        // Shared by both branches: drop only our key from a concurrently edited file.
        func removeOnlyOurKey(emptyMeansDelete: String, afterDelete: String) -> String {
            """
            if test -f "$txn/key.added" && test ! -L "$txn/key.added" && test -f "$file"; then
                tmp=$(mktemp "$sshdir/.authorized_keys.rollback.XXXXXXXXXX")
                trap 'rm -f -- "$tmp"' EXIT
                awk -v blob="$blob" '!($1 == "ssh-ed25519" && $2 == blob)' "$file" > "$tmp"
                \(ownTemp)
                chmod 0600 -- "$tmp"
                if \(emptyMeansDelete); then
                    rm -f -- "$tmp" "$file"
                    trap - EXIT
                    \(afterDelete)
                else
                    test ! -d "$file" || exit 74; mv -f -- "$tmp" "$file"
                    trap - EXIT
                fi
                cleanup_snapshot
                exit 0
            fi
            """
        }
        let restoreDirectoryMeta = """
        \(restoreOwner)
        chmod "$directory_mode" -- "$sshdir"
        touch -r "$txn/directory.timestamps" -- "$sshdir"
        """

        let removeFromExistingDirectory = removeOnlyOurKey(
            emptyMeansDelete: #"test "$original_file" = false && test ! -s "$tmp""#,
            afterDelete: restoreDirectoryMeta)
        let removeFromNewDirectory = removeOnlyOurKey(
            emptyMeansDelete: #"test ! -s "$tmp""#,
            afterDelete: #"rmdir -- "$sshdir" 2>/dev/null || true"#)

        return shell("""
        set -eu
        umask 077
        txn=\(shellQuote(backupPath))
        test -d "$txn" && test ! -L "$txn" || exit 1
        test -f "$txn/ready" && test ! -L "$txn/ready" || exit 1
        cleanup_snapshot() {
            rm -f -- \(snapshotFiles)
            rmdir -- "$txn"
        }
        key=$(cat)
        set -- $key
        test "$#" -ge 2 && test "$1" = ssh-ed25519 || exit 65
        blob=$2
        \(sshDirectory(root: root))
        test ! -L "$sshdir"
        file="$sshdir/authorized_keys"
        if test -f "$txn/directory.existed" && test ! -L "$txn/directory.existed"; then
            test -d "$sshdir"
            test -f "$txn/directory.meta" && test ! -L "$txn/directory.meta" || exit 1
            test -f "$txn/directory.timestamps" && test ! -L "$txn/directory.timestamps" || exit 1
            IFS=' ' read -r directory_mode directory_uid directory_gid < "$txn/directory.meta"
            test -n "$directory_mode" && test -n "$directory_uid" && test -n "$directory_gid" || exit 1
            case "$directory_mode$directory_uid$directory_gid" in *[!0-9]*) exit 70 ;; esac
            test ! -L "$file"
            original_file=false
            if test -e "$txn/file.existed"; then
                test -f "$txn/file.existed" && test ! -L "$txn/file.existed" || exit 1
                test -f "$txn/authorized_keys" && test ! -L "$txn/authorized_keys" || exit 1
                original_file=true
            fi
            if test -e "$file"; then test -f "$file"; fi

            exact_state=false
            if test -f "$file" && test -f "$txn/expected" && test ! -L "$txn/expected" && cmp -s -- "$file" "$txn/expected"; then
                exact_state=true
            elif test "$original_file" = true && test -f "$file" && cmp -s -- "$file" "$txn/authorized_keys"; then
                exact_state=true
            elif test "$original_file" = false && test ! -e "$file"; then
                exact_state=true
            fi

            if test "$exact_state" = true; then
                if test "$original_file" = true; then
                    tmp=$(mktemp "$sshdir/.authorized_keys.restore.XXXXXXXXXX")
                    trap 'rm -f -- "$tmp"' EXIT
                    rm -f -- "$tmp"
                    cp -a -- "$txn/authorized_keys" "$tmp"
                    test ! -d "$file" || exit 74; mv -f -- "$tmp" "$file"
                    trap - EXIT
                else
                    rm -f -- "$file"
                fi
                \(restoreDirectoryMeta)
                cleanup_snapshot
                exit 0
            fi

            \(removeFromExistingDirectory)

            printf '%s\\n' 'authorized_keys changed concurrently; refusing to replace it with the old snapshot' >&2
            exit 73
        else
            test ! -e "$txn/directory.existed"
            if test -e "$sshdir"; then
                test -d "$sshdir"
                test ! -L "$file"
                if test -e "$file"; then test -f "$file"; fi

                if { test -f "$file" && test -f "$txn/expected" && test ! -L "$txn/expected" && cmp -s -- "$file" "$txn/expected"; } || test ! -e "$file"; then
                    rm -f -- "$file"
                    rmdir -- "$sshdir" 2>/dev/null || true
                    cleanup_snapshot
                    exit 0
                fi

                \(removeFromNewDirectory)

                printf '%s\\n' 'authorized_keys changed concurrently; refusing to remove the directory' >&2
                exit 73
            else
                cleanup_snapshot
                exit 0
            fi
        fi
        """)
    }

    static func removeSnapshot(backupPath: String) -> String {
        shell("""
        set -eu
        txn=\(shellQuote(backupPath))
        if test ! -e "$txn"; then
            test ! -L "$txn"
            exit 0
        fi
        test -d "$txn" && test ! -L "$txn" || exit 1
        rm -f -- \(snapshotFiles)
        rmdir -- "$txn"
        """)
    }
}
