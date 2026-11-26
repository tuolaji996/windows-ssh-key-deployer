# One systemd-less OpenSSH server image per Linux distribution, used by ../run.sh.
#
#   docker build --build-arg BASE=debian:12 [--build-arg WITH_SUDO=0] -t e2e-debian-12 macos-native/e2e/image
#
# The container runs `sshd -D` as PID 1 on $SSH_PORT (use --network host). Passwords
# are set at start-up from ALICE_PASSWORD, BOB_PASSWORD and ROOT_PASSWORD.
ARG BASE=debian:12
FROM ${BASE}

ARG WITH_SUDO=1
COPY setup.sh entrypoint.sh /usr/local/sbin/
RUN chmod 0755 /usr/local/sbin/setup.sh /usr/local/sbin/entrypoint.sh \
    && WITH_SUDO=${WITH_SUDO} /usr/local/sbin/setup.sh

ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]
