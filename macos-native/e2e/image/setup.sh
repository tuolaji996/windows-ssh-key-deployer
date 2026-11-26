#!/bin/sh
# Image build step: installs OpenSSH (and sudo unless WITH_SUDO=0) and creates the
# test accounts. Runs on every supported base image, so it is plain POSIX sh.
#   alice - member of the distribution's admin group (sudo with her own password)
#   bob   - no sudo rights at all
# Passwords are not set here; entrypoint.sh sets them when the container starts.
set -eu

WITH_SUDO="${WITH_SUDO:-1}"
. /etc/os-release
family="${ID} ${ID_LIKE:-}"
sudo_pkg=""
[ "$WITH_SUDO" = 1 ] && sudo_pkg="sudo"

case "$family" in
  *alpine*)
    apk add --no-cache openssh-server openssh-keygen bash $sudo_pkg >/dev/null
    # The container image lacks a setuid su ("su: must be suid to work properly");
    # a standard Alpine install has one.
    apk add --no-cache busybox-suid >/dev/null 2>&1 || apk add --no-cache shadow-login >/dev/null
    admin_group=wheel
    ;;
  *debian*|*ubuntu*)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends openssh-server iproute2 procps $sudo_pkg >/dev/null
    # Like a fresh cloud image: no package lists, so installing sudo later needs `apt-get update`.
    apt-get clean
    rm -rf /var/lib/apt/lists/*
    admin_group=sudo
    ;;
  *suse*)
    zypper --non-interactive --quiet install --no-recommends openssh-server iproute2 procps util-linux shadow $sudo_pkg
    zypper clean --all >/dev/null
    admin_group=wheel
    ;;
  *arch*)
    pacman -Syu --noconfirm --needed openssh iproute2 procps-ng util-linux $sudo_pkg >/dev/null
    pacman -Scc --noconfirm >/dev/null 2>&1 || true
    admin_group=wheel
    ;;
  *fedora*|*rhel*|*centos*)
    dnf install -y -q --setopt=install_weak_deps=False openssh-server iproute procps-ng util-linux shadow-utils $sudo_pkg
    dnf clean all >/dev/null
    admin_group=wheel
    ;;
  *)
    echo "setup.sh: unsupported distribution: $family" >&2
    exit 1
    ;;
esac

grep -q "^${admin_group}:" /etc/group || groupadd -r "$admin_group" 2>/dev/null || addgroup -S "$admin_group"

if command -v useradd >/dev/null 2>&1; then
  useradd -m -s /bin/bash alice
  useradd -m -s /bin/bash bob
  usermod -aG "$admin_group" alice
else
  adduser -D -s /bin/bash alice
  adduser -D -s /bin/bash bob
  addgroup alice "$admin_group"
fi

if [ "$WITH_SUDO" = 1 ]; then
  # Grant the admin group sudo where the distribution does not do so by default
  # (Arch, Alpine, openSUSE). Debian/Ubuntu (%sudo) and Fedora/RHEL (%wheel) already do.
  if ! grep -Eq "^[[:space:]]*%${admin_group}[[:space:]]" /etc/sudoers 2>/dev/null; then
    mkdir -p /etc/sudoers.d
    printf '%%%s ALL=(ALL:ALL) ALL\n' "$admin_group" > /etc/sudoers.d/10-e2e-admin-group
    chmod 0440 /etc/sudoers.d/10-e2e-admin-group
  fi
  # openSUSE's default "Defaults targetpw" + "ALL ALL=(ALL) ALL" lets every user sudo
  # with the *root* password. Use the common admin-group model instead, so bob really
  # has no sudo rights and alice uses her own password.
  for file in /etc/sudoers /usr/etc/sudoers; do
    [ -f "$file" ] || continue
    sed -i -e 's/^\(Defaults[[:space:]]\+targetpw\)/# e2e: \1/' \
           -e 's/^\(ALL[[:space:]]\+ALL[[:space:]]*=[[:space:]]*(ALL)[[:space:]]\+ALL\)/# e2e: \1/' "$file"
  done
fi

# pam_loginuid fails without an audit-capable init, which would break every SSH login.
if [ -f /etc/pam.d/sshd ]; then
  sed -i 's/^\(session[[:space:]]\+\)required\([[:space:]]\+pam_loginuid\.so\)/\1optional\2/' /etc/pam.d/sshd
fi

mkdir -p /etc/ssh/sshd_config.d
echo "setup.sh: prepared ${PRETTY_NAME:-$ID} (sudo: $WITH_SUDO, admin group: $admin_group)"
