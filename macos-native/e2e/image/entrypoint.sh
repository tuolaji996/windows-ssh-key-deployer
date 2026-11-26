#!/bin/sh
# Container start: sets the test passwords and runs sshd in the foreground as PID 1
# (no systemd). SIGHUP makes sshd re-execute itself with the new configuration while
# the container keeps running.
#
#   ALICE_PASSWORD, BOB_PASSWORD, ROOT_PASSWORD  (required)
#   SSH_PORT          optional; written as "Port N" into sshd_config. Without it the
#                     distribution's stock configuration is kept (port 22, no Port line).
#   SSHD_NO_INCLUDE=1 remove the "Include /etc/ssh/sshd_config.d/*.conf" line (unsupported server)
set -eu

: "${ALICE_PASSWORD:?}" "${BOB_PASSWORD:?}" "${ROOT_PASSWORD:?}"

printf 'alice:%s\nbob:%s\nroot:%s\n' "$ALICE_PASSWORD" "$BOB_PASSWORD" "$ROOT_PASSWORD" | chpasswd

ssh-keygen -A >/dev/null
mkdir -p /run/sshd /var/empty
chmod 0755 /run/sshd
# Left behind by some images when systemd never ran; would block non-root logins.
rm -f /run/nologin /var/run/nologin /etc/nologin

config=/etc/ssh/sshd_config
if [ ! -f "$config" ] && [ -f /usr/etc/ssh/sshd_config ]; then
  # Distributions that ship the default under /usr/etc (openSUSE): an admin's
  # /etc/ssh/sshd_config is a copy of it.
  cp /usr/etc/ssh/sshd_config "$config"
fi

if [ -n "${SSH_PORT:-}" ]; then
  sed -i '/^[[:space:]]*[Pp][Oo][Rr][Tt][[:space:]]/d' "$config"
  sed -i "1i Port ${SSH_PORT}" "$config"
fi

# OpenSSH 9.8+ penalises a source address after failed logins; the harness logs in
# from one address many times and deliberately tries rejected password logins.
if /usr/sbin/sshd -T 2>/dev/null | grep -qi '^persourcepenalties'; then
  sed -i '1i PerSourcePenalties no' "$config"
fi

if [ "${SSHD_NO_INCLUDE:-0}" = 1 ]; then
  sed -i '/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]]/d' "$config"
fi

echo "entrypoint: $(. /etc/os-release && echo "${PRETTY_NAME:-$ID}"), port: ${SSH_PORT:-stock}, include lines: $(grep -ci '^[[:space:]]*include[[:space:]]' "$config" || true)"
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
