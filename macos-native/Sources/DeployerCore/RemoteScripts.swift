import Foundation

/// POSIX shell programs executed on the Debian server.
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

    static func managedConfig(rootLogin: RootLoginPolicy, allowPasswordLogin: Bool) -> String {
        """
        \(managedConfigMarker)
        # Loaded early so these verified authentication settings take precedence.
        PubkeyAuthentication yes
        PasswordAuthentication \(allowPasswordLogin ? "yes" : "no")
        KbdInteractiveAuthentication no
        PermitRootLogin \(rootLogin.sshdValue)

        """
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
    mv -fT -- "$tmp" \(shellQuote(managedConfigPath))
    trap - EXIT
    """)

    static func restoreManagedConfig(originalExisted: Bool, backupPath: String) -> String {
        originalExisted
            ? "mv -fT -- \(shellQuote(backupPath)) \(shellQuote(managedConfigPath))"
            : "rm -f -- \(shellQuote(managedConfigPath))"
    }

    static func removeFile(_ path: String) -> String {
        "rm -f -- \(shellQuote(path))"
    }

    static let reloadSsh = shell("""
    if systemctl reload ssh.service; then exit 0
    elif systemctl reload sshd.service; then exit 0
    else service ssh reload
    fi
    """)

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
        test -d "$txn" && test ! -L "$txn" || exit 1
        test -f "$txn/ready" && test ! -L "$txn/ready" || exit 1
        \(sshDirectory(root: root))
        test ! -L "$sshdir"
        \(ensureDirectory)
        file="$sshdir/authorized_keys"
        test ! -L "$file"
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
        mv -fT -- "$tmp" "$file"
        trap - EXIT
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
                    mv -fT -- "$tmp" "$file"
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
                    mv -fT -- "$tmp" "$file"
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
