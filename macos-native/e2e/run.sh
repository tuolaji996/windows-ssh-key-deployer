#!/usr/bin/env bash
# End-to-end scenarios for the deployment core against a real, systemd-less OpenSSH
# server of one Linux distribution running in Docker.
#
#   macos-native/e2e/run.sh DISTRO [SCENARIO...]
#   macos-native/e2e/run.sh --list
#
# DISTRO is one of the names printed by --list. SCENARIO is any of a b c d e (default:
# all scenarios that apply to the distribution):
#   a  alice (sudo), root login key-only, password login off
#   b  bob (no sudo) + root password via su; sudo is installed where missing
#   c  alice moves sshd to a new port; the old port must be closed
#   d  bob with a wrong root password: rootPasswordRejected, server unchanged
#   e  sshd_config without the drop-in Include: unsupportedServer, server unchanged
#
# Environment:
#   DEPLOYER_CMD   command that takes the deployer-e2e flags (word-split; default: the
#                  SwiftPM debug or release build of deployer-e2e). Any other client, for
#                  example a C# console runner, can reuse these scenarios by accepting
#                  the same flags, JSON output and exit codes.
#   E2E_BASE_PORT  first port used for containers (default 2200); each scenario uses
#                  its own ports, so containers never collide.
#   E2E_IMAGE_PREFIX  image name prefix (default sshkd-e2e); images are built when missing.
#   E2E_KEEP=1     keep containers after the run for debugging.
set -uo pipefail

e2e_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
package_root="$(cd "$e2e_root/.." && pwd)"

# name|base image|with sudo|default scenarios
distros=(
  "debian-12|debian:12|1|a b c d e"
  "debian-12-nosudo|debian:12|0|b d"
  "debian-13|debian:13|1|a b c d e"
  "ubuntu-22.04|ubuntu:22.04|1|a b c d e"
  "ubuntu-24.04|ubuntu:24.04|1|a b c d e"
  "almalinux-9|almalinux:9|1|a b c d e"
  "fedora|fedora:latest|1|a b c d e"
  "opensuse-leap-15.6|opensuse/leap:15.6|1|a b c d e"
  "archlinux|archlinux:latest|1|a b c d e"
  "alpine|alpine:latest|1|a b c d e"
)

if [[ "${1:-}" == "--list" ]]; then
  for entry in "${distros[@]}"; do printf '%s\n' "${entry%%|*}"; done
  exit 0
fi
if [[ $# -lt 1 ]]; then
  sed -n '2,25p' "$0" >&2
  exit 2
fi

distro="$1"
shift
entry=""
for candidate in "${distros[@]}"; do
  [[ "${candidate%%|*}" == "$distro" ]] && entry="$candidate"
done
if [[ -z "$entry" ]]; then
  printf 'Unknown distribution %s (see --list).\n' "$distro" >&2
  exit 2
fi
IFS='|' read -r _ base_image with_sudo default_scenarios <<<"$entry"
if [[ $# -gt 0 ]]; then scenarios="$*"; else scenarios="$default_scenarios"; fi

image="${E2E_IMAGE_PREFIX:-sshkd-e2e}:${distro}"
base_port="${E2E_BASE_PORT:-2200}"

if [[ -n "${DEPLOYER_CMD:-}" ]]; then
  read -r -a deployer <<<"$DEPLOYER_CMD"
else
  deployer=()
  for candidate in "$package_root/.build/release/deployer-e2e" "$package_root/.build/debug/deployer-e2e"; do
    if [[ -x "$candidate" ]]; then deployer=("$candidate"); break; fi
  done
  if [[ ${#deployer[@]} -eq 0 ]]; then
    printf 'deployer-e2e not built; run "swift build --product deployer-e2e" in %s or set DEPLOYER_CMD.\n' "$package_root" >&2
    exit 2
  fi
fi

for tool in docker ssh ssh-keyscan ssh-keygen jq; do
  command -v "$tool" >/dev/null || { printf 'Missing required tool: %s\n' "$tool" >&2; exit 2; }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/sshkd-e2e.XXXXXX")"
containers=()
cleanup() {
  if [[ "${E2E_KEEP:-0}" != 1 ]]; then
    for container in "${containers[@]}"; do docker rm -f "$container" >/dev/null 2>&1; done
    rm -rf -- "$work"
  fi
}
trap cleanup EXIT

# Test-only passwords, generated per run. The quote and dollar characters make sure
# no layer interprets passwords as shell text.
random_secret() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16; }
alice_password="Alice-$(random_secret)-'q\"\$x"
bob_password="Bob-$(random_secret)-'q\"\$x"
root_password="Root-$(random_secret)-'q\"\$x"
wrong_root_password="Wrong-$(random_secret)"

declare -A password_of=([alice]="$alice_password" [bob]="$bob_password" [root]="$root_password")

log() { printf '[e2e %s] %s\n' "$distro" "$*"; }

results=()
scenario_failed=0
check() {
  # check DESCRIPTION COMMAND... : records one assertion.
  local description="$1"
  shift
  if "$@"; then
    log "  ok: $description"
  else
    log "  FAILED: $description"
    scenario_failed=1
  fi
}

# --- images and containers ---------------------------------------------------------

ensure_image() {
  if docker image inspect "$image" >/dev/null 2>&1; then
    log "using existing image $image"
    return
  fi
  log "building $image from $base_image (sudo: $with_sudo)"
  docker build --quiet \
    --build-arg "BASE=$base_image" \
    --build-arg "WITH_SUDO=$with_sudo" \
    -t "$image" "$e2e_root/image" >/dev/null
}

# start_container NAME PORT [extra docker run args...]
start_container() {
  local name="$1" port="$2"
  shift 2
  docker rm -f "$name" >/dev/null 2>&1
  docker run -d --name "$name" --network host \
    -e "SSH_PORT=$port" \
    -e "ALICE_PASSWORD=$alice_password" \
    -e "BOB_PASSWORD=$bob_password" \
    -e "ROOT_PASSWORD=$root_password" \
    "$@" "$image" >/dev/null || return 1
  containers+=("$name")
  local attempt
  for attempt in $(seq 1 60); do
    if ssh-keyscan -T 2 -p "$port" 127.0.0.1 2>/dev/null | grep -q .; then
      return 0
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null)" != true ]]; then
      break
    fi
    sleep 0.5
  done
  log "sshd in $name did not come up on port $port"
  docker logs "$name" 2>&1 | tail -n 40
  return 1
}

# --- deployer --------------------------------------------------------------------

# run_deployer OUTPUT_PREFIX LOGIN_PASSWORD ROOT_PASSWORD_OR_EMPTY FLAGS...
run_deployer() {
  local prefix="$1" login_password="$2" root_pw="$3"
  shift 3
  local args=("$@" --password-env E2E_LOGIN_PASSWORD)
  [[ -n "$root_pw" ]] && args+=(--root-password-env E2E_ROOT_PASSWORD)
  log "  deployer ${args[*]}"
  E2E_LOGIN_PASSWORD="$login_password" E2E_ROOT_PASSWORD="$root_pw" \
    timeout 900 "${deployer[@]}" "${args[@]}" >"$prefix.json" 2>"$prefix.log"
  local status=$?
  sed 's/^/      /' "$prefix.log"
  sed 's/^/      /' "$prefix.json"
  log "  deployer exit status $status"
  return $status
}

json() { jq -r "$2" "$1.json" 2>/dev/null; }

# --- assertions ------------------------------------------------------------------

ssh_common=(
  -F /dev/null
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o GlobalKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ConnectTimeout=10
)

# key_login_works USER PORT KEY
key_login_works() {
  local output
  output="$(SSH_AUTH_SOCK='' ssh "${ssh_common[@]}" -p "$2" -i "$3" \
    -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
    -o PreferredAuthentications=publickey \
    "$1@127.0.0.1" 'id -un' </dev/null 2>&1)"
  [[ "$output" == "$1" ]] || { log "    key login as $1 on port $2 returned: $output"; return 1; }
}

password_output=""
# password_login_works USER PORT : logs in with the user's correct password.
password_login_works() {
  local askpass="$work/askpass"
  if [[ ! -x "$askpass" ]]; then
    printf '#!/bin/sh\nprintf "%%s\\n" "$E2E_ASKPASS_SECRET"\n' >"$askpass"
    chmod 0700 "$askpass"
  fi
  local output
  output="$(SSH_AUTH_SOCK='' E2E_ASKPASS_SECRET="${password_of[$1]}" SSH_ASKPASS="$askpass" \
    SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
    ssh "${ssh_common[@]}" -p "$2" \
    -o PubkeyAuthentication=no -o IdentityAgent=none \
    -o PreferredAuthentications=password,keyboard-interactive \
    -o NumberOfPasswordPrompts=1 \
    "$1@127.0.0.1" 'id -un' </dev/null 2>&1)"
  password_output="$output"
  [[ "$output" == "$1" ]]
}
# Rejected means the server answered and refused authentication, not a network error.
password_login_rejected() {
  if password_login_works "$@"; then
    log "    password login as $1 on port $2 succeeded"
    return 1
  fi
  [[ "$password_output" == *"Permission denied"* ]] || { log "    password login as $1 failed without an authentication refusal: $password_output"; return 1; }
}

port_closed() { ! timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; }

# Everything the deployer may touch, without timestamps (rollback may legitimately
# touch a directory while restoring identical contents).
server_state() {
  docker exec "$1" sh -c '
    for path in /etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/sudoers.d \
                /root/.ssh /home/alice/.ssh /home/bob/.ssh; do
      [ -e "$path" ] || { echo "absent $path"; continue; }
      find "$path" -maxdepth 1 | sort | while read -r item; do
        stat -c "%n %a %u %g %s" "$item"
        [ -f "$item" ] && cksum < "$item"
      done
    done
    ls -a /tmp | grep ssh-key-deployer || true
    command -v sudo || echo "no sudo"'
}

no_temporary_sudoers() {
  local leftovers
  leftovers="$(docker exec "$1" sh -c 'ls /etc/sudoers.d/ 2>/dev/null | grep "^zz-ssh-key-deployer" || true')"
  [[ -z "$leftovers" ]] || { log "    leftover sudoers drop-ins: $leftovers"; return 1; }
}

# The fingerprints computed by the deployer (portable SHA-256/MD5 on Linux) must
# match OpenSSH's own.
fingerprints_match_openssh() {
  local prefix="$1" port="$2" key="$3" ok=0
  local algorithm expected_sha expected_md5 expected_key
  algorithm="$(json "$prefix" '.hostKey.algorithm')"
  [[ -n "$algorithm" && "$algorithm" != null ]] || { log "    no host key in result"; return 1; }
  local scanned
  scanned="$(ssh-keyscan -p "$port" 127.0.0.1 2>/dev/null | awk -v a="$algorithm" '$2 == a')"
  expected_sha="$(ssh-keygen -lf - -E sha256 <<<"$scanned" | awk '{print $2}')"
  expected_md5="$(ssh-keygen -lf - -E md5 <<<"$scanned" | awk '{print $2}')"
  [[ "$(json "$prefix" '.hostKey.sha256Fingerprint')" == "$expected_sha" ]] || { log "    host SHA-256 mismatch (OpenSSH: $expected_sha)"; ok=1; }
  [[ "$(json "$prefix" '.hostKey.md5Fingerprint')" == "$expected_md5" ]] || { log "    host MD5 mismatch (OpenSSH: $expected_md5)"; ok=1; }
  if [[ "$(json "$prefix" '.outcome')" == success ]]; then
    expected_key="$(ssh-keygen -lf "$key.pub" -E sha256 | awk '{print $2}')"
    [[ "$(json "$prefix" '.publicKeyFingerprint')" == "$expected_key" ]] || { log "    key SHA-256 mismatch (OpenSSH: $expected_key)"; ok=1; }
  fi
  return $ok
}

json_equals() { [[ "$(json "$1" "$2")" == "$3" ]] || { log "    $2 = $(json "$1" "$2"), expected $3"; return 1; }; }

# --- scenarios -------------------------------------------------------------------

scenario_a() {
  local port=$((base_port + 10)) name="sshkd-e2e-$distro-a" dir="$work/a"
  mkdir -p "$dir"
  start_container "$name" "$port" || return 1
  run_deployer "$dir/out" "$alice_password" "" \
    --host 127.0.0.1 --port "$port" --user alice --key "$dir/key" \
    --root-login key --password-login off
  check "deployer succeeded" test $? -eq 0
  check "result port is $port" json_equals "$dir/out" '.sshPort' "$port"
  check "fingerprints match OpenSSH" fingerprints_match_openssh "$dir/out" "$port" "$dir/key"
  check "key login as alice" key_login_works alice "$port" "$dir/key"
  check "key login as root" key_login_works root "$port" "$dir/key"
  check "password login rejected for alice" password_login_rejected alice "$port"
  check "password login rejected for root" password_login_rejected root "$port"
  check "no temporary sudoers drop-in" no_temporary_sudoers "$name"
}

scenario_b() {
  local port=$((base_port + 20)) name="sshkd-e2e-$distro-b" dir="$work/b"
  mkdir -p "$dir"
  start_container "$name" "$port" || return 1
  run_deployer "$dir/out" "$bob_password" "$root_password" \
    --host 127.0.0.1 --port "$port" --user bob --key "$dir/key" \
    --root-login keypass --password-login on
  check "deployer succeeded" test $? -eq 0
  check "plan used su" json_equals "$dir/out" '.server.privilege' su
  check "key login as bob" key_login_works bob "$port" "$dir/key"
  check "key login as root" key_login_works root "$port" "$dir/key"
  check "password login still works for bob" password_login_works bob "$port"
  check "temporary sudoers drop-in removed" no_temporary_sudoers "$name"
  check "bob still has no sudo rights" \
    bash -c "docker exec '$name' sh -c 'command -v sudo >/dev/null || { echo not allowed; exit 0; }; sudo -l -U bob' 2>&1 | grep -qi 'not allowed'"
  if [[ "$with_sudo" == 0 ]]; then
    check "server reported sudo missing" json_equals "$dir/out" '.server.sudoInstalled' false
    check "sudo was installed" docker exec "$name" sh -c 'command -v sudo'
  fi
}

scenario_c() {
  local port=$((base_port + 30)) new_port=$((base_port + 35)) name="sshkd-e2e-$distro-c" dir="$work/c"
  mkdir -p "$dir"
  start_container "$name" "$port" || return 1
  run_deployer "$dir/out" "$alice_password" "" \
    --host 127.0.0.1 --port "$port" --user alice --key "$dir/key" \
    --root-login off --password-login on --new-port "$new_port"
  check "deployer succeeded" test $? -eq 0
  check "result port is $new_port" json_equals "$dir/out" '.sshPort' "$new_port"
  check "key login as alice on new port $new_port" key_login_works alice "$new_port" "$dir/key"
  check "old port $port refused" port_closed "$port"
  check "container still running" bash -c "[ \"\$(docker inspect -f '{{.State.Running}}' '$name')\" = true ]"
}

# Failure scenario: the deployer must fail with KIND and leave the server unchanged.
expect_unchanged_failure() {
  local name="$1" dir="$2" kind="$3" login_password="$4" root_pw="$5"
  shift 5
  local before after
  before="$(server_state "$name")"
  run_deployer "$dir/out" "$login_password" "$root_pw" "$@" --expect-failure "$kind"
  check "deployer failed with $kind" test $? -eq 0
  check "failure kind is $kind" json_equals "$dir/out" '.kind' "$kind"
  after="$(server_state "$name")"
  if [[ "$before" == "$after" ]]; then
    log "  ok: server unchanged"
  else
    log "  FAILED: server changed:"
    diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") | sed 's/^/      /'
    scenario_failed=1
  fi
}

scenario_d() {
  local port=$((base_port + 40)) name="sshkd-e2e-$distro-d" dir="$work/d"
  mkdir -p "$dir"
  start_container "$name" "$port" || return 1
  expect_unchanged_failure "$name" "$dir" rootPasswordRejected "$bob_password" "$wrong_root_password" \
    --host 127.0.0.1 --port "$port" --user bob --key "$dir/key" \
    --root-login off --password-login on
  check "password login still works for bob" password_login_works bob "$port"
}

scenario_e() {
  local port=$((base_port + 50)) name="sshkd-e2e-$distro-e" dir="$work/e"
  mkdir -p "$dir"
  start_container "$name" "$port" -e SSHD_NO_INCLUDE=1 || return 1
  expect_unchanged_failure "$name" "$dir" unsupportedServer "$alice_password" "" \
    --host 127.0.0.1 --port "$port" --user alice --key "$dir/key" \
    --root-login off --password-login on
}

# --- main --------------------------------------------------------------------------

ensure_image || { log "image build failed"; exit 1; }
log "deployer: ${deployer[*]}"

overall=0
for scenario in $scenarios; do
  if ! declare -F "scenario_$scenario" >/dev/null; then
    log "unknown scenario $scenario"
    overall=1
    continue
  fi
  log "=== scenario $scenario ==="
  scenario_failed=0
  "scenario_$scenario" || scenario_failed=1
  if [[ "$scenario_failed" == 0 ]]; then
    results+=("$scenario PASS")
  else
    results+=("$scenario FAIL")
    overall=1
    log "  container log (tail):"
    docker logs "sshkd-e2e-$distro-$scenario" 2>&1 | tail -n 30 | sed 's/^/      /'
  fi
  [[ "${E2E_KEEP:-0}" == 1 ]] || docker rm -f "sshkd-e2e-$distro-$scenario" >/dev/null 2>&1
done

log "=== summary ==="
for result in "${results[@]}"; do log "  $result"; done
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '### E2E %s (%s)\n\n| scenario | result |\n|---|---|\n' "$distro" "$base_image"
    for result in "${results[@]}"; do printf '| %s | %s |\n' "${result% *}" "${result##* }"; done
    printf '\n'
  } >>"$GITHUB_STEP_SUMMARY"
fi
exit $overall
