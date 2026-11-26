#!/bin/sh
# Container start: sets the test passwords, puts sshd on $SSH_PORT and runs it in the
# foreground as PID 1 (no systemd). SIGHUP makes sshd re-execute itself with the
# new configuration while the container keeps running.
#
#   SSH_PORT          port sshd listens on (required; the container uses --network host)
#   ALICE_PASSWORD, BOB_PASSWORD, ROOT_PASSWORD
#   SSHD_NO_INCLUDE=1 remove the "Include /etc/ssh/sshd_config.d/*.conf" line (unsupported server)
set -eu

: "${SSH_PORT:?SSH_PORT is required}"
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

# The listening port lives in the main file, as on a typical server.
sed -i '/^[[:space:]]*[Pp][Oo][Rr][Tt][[:space:]]/d' "$config"
sed -i "1i Port ${SSH_PORT}" "$config"

if [ "${SSHD_NO_INCLUDE:-0}" = 1 ]; then
  sed -i '/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]]/d' "$config"
fi

echo "entrypoint: $(. /etc/os-release && echo "${PRETTY_NAME:-$ID}"), sshd on port ${SSH_PORT}, include: $(grep -ci '^[[:space:]]*include[[:space:]]' "$config" || true)"
/usr/sbin/sshd -t
exec /usr/sbin/sshd -D -e
