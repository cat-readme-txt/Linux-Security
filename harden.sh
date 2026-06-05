#!/usr/bin/env bash
#
# harden.sh — Menu-driven Linux security hardening tool
# ============================================================================
# Implements the checks in the "Linux System Checklist", with corrections.
# Fully supports Debian/Ubuntu (apt) and RHEL/Fedora/Alma/Rocky (dnf/yum).
#
# Every change is LOGGED and BACKED UP so it can be undone with revert.sh.
#
# ----------------------------------------------------------------------------
# AUTHORIZED FILE FORMAT  (required only for the "User & Group Audit" section)
# ----------------------------------------------------------------------------
# Create a plain-text file (default: ./authorized.txt, or pass --authorized PATH)
# before running. Lines beginning with '#' are comments; blank lines are ignored.
# It has two sections introduced by [users] and [sudoers]:
#
#     # ---- example authorized.txt ----
#     [users]
#     alice          # every login account that is allowed to exist
#     bob
#     charlie
#     [sudoers]
#     alice          # the subset of users allowed admin (sudo/wheel) access
#     bob
#
#  * Any human account (UID >= 1000) NOT under [users] is flagged as unauthorized.
#  * Any member of the sudo/wheel group NOT under [sudoers] is flagged for removal
#    from that group.
#  * The account currently running the script is never offered for deletion.
# ----------------------------------------------------------------------------
#
# Usage:   sudo ./harden.sh [--authorized PATH] [--state-dir DIR] [--yes-risky] [--competition-safe] [--wordlist PATH]
#          sudo ./harden.sh --show-last        # replay the last run's transcript
#
# The full session is mirrored to <run-dir>/output.log, so even if a task ends
# your session (e.g. a display-manager restart) you can review everything after
# logging back in with:  sudo ./harden.sh --show-last
# Session-disrupting actions (display-manager restart) are deferred to the very
# end, after all other selected sections have completed.
#
# ============================================================================

set -o pipefail

# ----------------------------------------------------------------------------
# Globals / configuration
# ----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUTH_FILE="$SCRIPT_DIR/authorized.txt"
STATE_BASE="/var/backups/security-hardening"
ASSUME_RISKY=0           # if 1, auto-apply risky items without prompting
COMPETITION_SAFE=0       # if 1, run read-only preflight first and never auto-approve risky changes
SHOW_LAST=0              # if 1, just replay the latest run's transcript and exit
PW_WORDLIST="${PW_WORDLIST:-}"   # optional custom wordlist for the password audit
PKG_FAMILY=""            # apt | dnf | yum
DISTRO_FAMILY="unsupported"  # debian | rhel | unsupported
WRITE_SUPPORTED=0        # 1 only for the fully supported distro families
DISTRO_ID=""; DISTRO_VER=""; DISTRO_LIKE=""
ADMIN_GROUP="sudo"       # sudo (debian) or wheel (rhel)
SSHD_CONFIG="/etc/ssh/sshd_config"

declare -A BACKED_UP CREATED      # de-dup file backups (scoped per task)
CURRENT_TASK=""
SELECTED=()                       # output of prompt_selection()
DEFERRED_DESC=(); DEFERRED_CMD=() # session-disrupting actions, run at the very end

# Colors (only when stdout is a terminal)
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_BLU=$'\033[34m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_RST=""
fi

# ----------------------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --authorized) AUTH_FILE="$2"; shift 2;;
    --state-dir)  STATE_BASE="$2"; shift 2;;
    --yes-risky)  ASSUME_RISKY=1; shift;;
    --competition-safe) COMPETITION_SAFE=1; shift;;
    --show-last)  SHOW_LAST=1; shift;;
    --wordlist)   PW_WORDLIST="$2"; shift 2;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -40; exit 0;;
    *) echo "Unknown argument: $1" >&2; exit 1;;
  esac
done

# ----------------------------------------------------------------------------
# Must run as root
# ----------------------------------------------------------------------------
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "${C_RED}This script must be run as root (use sudo).${C_RST}" >&2
  exit 1
fi

# --show-last: replay the most recent run's transcript and exit (no changes).
if [[ $SHOW_LAST -eq 1 ]]; then
  last="$STATE_BASE/latest/output.log"
  # shellcheck disable=SC2012
  [[ -e "$last" ]] || last="$(ls -1dt "$STATE_BASE"/run_*/output.log 2>/dev/null | head -1)"
  if [[ -n "$last" && -r "$last" ]]; then
    if [[ -t 1 ]] && command -v less >/dev/null 2>&1; then less -R "$last"; else cat "$last"; fi
  else
    echo "No previous run transcript found under $STATE_BASE"
  fi
  exit 0
fi

# ----------------------------------------------------------------------------
# Run directory / logging setup
# ----------------------------------------------------------------------------
TS="$(date '+%Y%m%d-%H%M%S')"
RUN_DIR="$STATE_BASE/run_$TS"
BACKUP_DIR="$RUN_DIR/backups"
ACTIONS_LOG="$RUN_DIR/actions.log"      # machine-readable; consumed by revert.sh
OUTPUT_LOG="$RUN_DIR/output.log"        # full human transcript
CREDS_FILE="$RUN_DIR/new-credentials.txt"   # plaintext old/new passwords (root only)
mkdir -p "$BACKUP_DIR"
: > "$ACTIONS_LOG"
: > "$OUTPUT_LOG"
# These can contain passwords and security details -> restrict to root.
chmod 700 "$RUN_DIR" "$BACKUP_DIR" 2>/dev/null || true
chmod 600 "$ACTIONS_LOG" "$OUTPUT_LOG" 2>/dev/null || true

# Stable "latest" pointer so revert.sh / --show-last can find the newest run.
ln -sfn "$RUN_DIR" "$STATE_BASE/latest" 2>/dev/null || true

# Mirror the ENTIRE session (script messages + every command's output) to the
# live terminal AND output.log via tee, so the full record survives a lost
# terminal. After re-login, review it with:  sudo ./harden.sh --show-last
exec > >(tee -a "$OUTPUT_LOG") 2>&1

log()  { echo "${C_BLU}[$(date '+%H:%M:%S')]${C_RST} $*"; }
info() { echo "    $*"; }
ok()   { echo "    ${C_GRN}OK:${C_RST} $*"; }
warn() { echo "    ${C_YEL}WARN:${C_RST} $*"; }
err()  { echo "    ${C_RED}ERROR:${C_RST} $*"; }

# Run a command, echoing the command line; its output flows through the tee.
run() {
  echo "    + $*"
  "$@"
}

# Queue a session-disrupting command to run at the very end of the whole run.
defer() { DEFERRED_DESC+=("$1"); DEFERRED_CMD+=("$2"); }

# Record a machine-readable, revertible action line.  Fields are pipe-delimited.
#   ACTION|<task>|<TYPE>|<arg1>|<arg2>...
record_action() {
  local type="$1"; shift
  local line="ACTION|${CURRENT_TASK}|${type}"
  local a
  for a in "$@"; do line+="|${a}"; done
  echo "$line" >> "$ACTIONS_LOG"
}

start_task() {  # $1 = task id, $2 = human description
  CURRENT_TASK="$1"
  BACKED_UP=(); CREATED=()          # backups are scoped per task for clean revert
  echo "TASK_START|$1|$2|$(date -Iseconds)" >> "$ACTIONS_LOG"
  echo ""
  echo "${C_BLD}${C_GRN}==> $2${C_RST}"
}
end_task() {
  echo "TASK_END|${CURRENT_TASK}" >> "$ACTIONS_LOG"
  CURRENT_TASK=""
}

# ----------------------------------------------------------------------------
# Backup helpers (revertibility)
# ----------------------------------------------------------------------------
# prepare_edit FILE — call before modifying FILE.
#   If FILE exists  -> copy it into the backup tree and record FILE_BACKUP.
#   If FILE absent  -> record FILE_CREATE (revert will delete it) and mkdir parent.
prepare_edit() {
  local f="$1"
  if [[ -e "$f" ]]; then
    [[ -n "${BACKED_UP[$f]:-}" ]] && return 0
    local dest="$BACKUP_DIR/files$f"
    mkdir -p "$(dirname "$dest")"
    cp -a "$f" "$dest"
    record_action "FILE_BACKUP" "$f" "$dest"
    BACKED_UP[$f]=1
  else
    [[ -n "${CREATED[$f]:-}" ]] && return 0
    record_action "FILE_CREATE" "$f"
    CREATED[$f]=1
    mkdir -p "$(dirname "$f")"
  fi
}

# record original permissions/ownership before a chmod/chown.
record_perm() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  local mode owner
  mode=$(stat -c '%a' "$f" 2>/dev/null) || return 0
  owner=$(stat -c '%U:%G' "$f" 2>/dev/null) || return 0
  record_action "PERM" "$f" "$mode" "$owner"
}

# record a service's enabled/active state before changing it.
record_service() {
  local svc="$1" en act
  en=$(systemctl is-enabled "$svc" 2>/dev/null || echo unknown)
  act=$(systemctl is-active  "$svc" 2>/dev/null || echo unknown)
  record_action "SERVICE_STATE" "$svc" "$en" "$act"
}

# Idempotently set "key<sep>value" in a config file (updates or appends).
set_conf_kv() {
  local file="$1" key="$2" val="$3" sep="${4:- }"
  prepare_edit "$file"
  if grep -qE "^[[:space:]]*${key}([[:space:]]|=|$)" "$file" 2>/dev/null; then
    # NOTE: use '#' as the sed delimiter; '|' would collide with the alternation.
    sed -i -E "s#^[[:space:]]*${key}([[:space:]]|=).*#${key}${sep}${val}#" "$file"
  else
    printf '%s%s%s\n' "$key" "$sep" "$val" >> "$file"
  fi
}

# Set an sshd_config directive (handles commented-out defaults).
set_ssh() {
  local key="$1" val="$2"
  prepare_edit "$SSHD_CONFIG"
  if grep -qiE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG"; then
    sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*|${key} ${val}|I" "$SSHD_CONFIG"
  else
    printf '%s %s\n' "$key" "$val" >> "$SSHD_CONFIG"
  fi
}

# ----------------------------------------------------------------------------
# Prompts
# ----------------------------------------------------------------------------
confirm() {  # yes/no, default No
  local prompt="$1" ans
  read -r -p "    ${prompt} [y/N]: " ans
  [[ "${ans,,}" =~ ^(y|yes)$ ]]
}

# Risky-item gate. Returns 0 (apply) / 1 (skip). Honors --yes-risky.
ask_risky() {
  local desc="$1"
  if [[ $ASSUME_RISKY -eq 1 && $COMPETITION_SAFE -eq 0 ]]; then
    warn "RISKY (auto-approved via --yes-risky): $desc"
    return 0
  fi
  echo "    ${C_YEL}${C_BLD}[RISKY]${C_RST} $desc"
  local ans
  read -r -p "    Apply this risky change? [y/N]: " ans
  if [[ "${ans,,}" =~ ^(y|yes)$ ]]; then
    log "RISKY approved: $desc"; return 0
  fi
  log "RISKY skipped: $desc"; return 1
}

# prompt_selection NOUN item...  — implements the bad-service style prompt.
#   "delete all? [y/N]"; 'all' => ignore everything & skip; 'no' => ask which to ignore.
# Result list is placed in the global array SELECTED.
prompt_selection() {
  local noun="$1"; shift
  local items=("$@")
  SELECTED=()
  if [[ ${#items[@]} -eq 0 ]]; then
    ok "No $noun found."
    return 0
  fi
  echo "    ${C_BLD}Found ${#items[@]} ${noun}:${C_RST}"
  printf '      - %s\n' "${items[@]}"
  echo "    Process ALL of these ${noun}?"
  echo "    Type 'all' to IGNORE every one of them and SKIP this task (nothing changes)."
  local ans
  read -r -p "    [y = process all / n = choose which to ignore / all = skip task]: " ans
  case "${ans,,}" in
    all)
      log "User typed 'all' -> ignoring all $noun; skipping task."
      SELECTED=()
      ;;
    y|yes)
      SELECTED=("${items[@]}")
      ;;
    *)
      local ignore=()
      read -r -p "    Enter ${noun} to IGNORE (space-separated), blank = ignore none: " -a ignore
      local it ig skip
      for it in "${items[@]}"; do
        skip=0
        for ig in "${ignore[@]}"; do [[ "$it" == "$ig" ]] && { skip=1; break; }; done
        [[ $skip -eq 0 ]] && SELECTED+=("$it")
      done
      log "Ignoring: ${ignore[*]:-(none)}"
      ;;
  esac
}

# ----------------------------------------------------------------------------
# Distro detection
# ----------------------------------------------------------------------------
detect_distro() {
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-}"; DISTRO_VER="${VERSION_ID:-}"; DISTRO_LIKE="${ID_LIKE:-}"
  fi
  local id="${DISTRO_ID,,}"
  case "$id" in
    debian|ubuntu)
      DISTRO_FAMILY="debian"
      ADMIN_GROUP="sudo"
      if command -v apt-get >/dev/null 2>&1; then
        PKG_FAMILY="apt"
        WRITE_SUPPORTED=1
      fi
      ;;
    rhel|fedora|almalinux|rocky)
      DISTRO_FAMILY="rhel"
      ADMIN_GROUP="wheel"
      if command -v dnf >/dev/null 2>&1; then
        PKG_FAMILY="dnf"
        WRITE_SUPPORTED=1
      elif command -v yum >/dev/null 2>&1; then
        PKG_FAMILY="yum"
        WRITE_SUPPORTED=1
      fi
      ;;
    *)
      DISTRO_FAMILY="unsupported"
      WRITE_SUPPORTED=0
      if command -v apt-get >/dev/null 2>&1; then PKG_FAMILY="apt"
      elif command -v dnf >/dev/null 2>&1; then PKG_FAMILY="dnf"
      elif command -v yum >/dev/null 2>&1; then PKG_FAMILY="yum"
      else PKG_FAMILY="unknown"; fi
      ;;
  esac

  if [[ $WRITE_SUPPORTED -eq 0 ]]; then
    warn "Unsupported distro for write-hardening tasks: ${DISTRO_ID:-unknown} ${DISTRO_VER:-}."
    warn "Read-only checks can still run. Write-hardening is built for Debian/Ubuntu and RHEL/Fedora/Alma/Rocky only."
  fi
  record_action "META" "distro" "${DISTRO_ID}" "${DISTRO_VER}" "${PKG_FAMILY}" "${DISTRO_FAMILY}" "${WRITE_SUPPORTED}"
  log "Detected: ${C_BLD}${DISTRO_ID:-unknown} ${DISTRO_VER}${C_RST} (family: ${DISTRO_FAMILY}, package manager: ${PKG_FAMILY}, admin group: ${ADMIN_GROUP}${DISTRO_LIKE:+, like: ${DISTRO_LIKE}})"
}

is_debian() { [[ "$DISTRO_FAMILY" == "debian" ]]; }
is_rhel()   { [[ "$DISTRO_FAMILY" == "rhel" ]]; }

require_supported_write() {
  local task="${1:-${CURRENT_TASK:-this task}}"
  if [[ $WRITE_SUPPORTED -eq 1 ]]; then
    return 0
  fi
  warn "Unsupported distro for this task: $task. Skipping write-hardening."
  warn "Detected ${DISTRO_ID:-unknown} ${DISTRO_VER:-}; supported write-hardening distros are Debian/Ubuntu and RHEL/Fedora/Alma/Rocky."
  return 1
}

require_systemd_task() {
  local task="${1:-${CURRENT_TASK:-this task}}"
  if command -v systemctl >/dev/null 2>&1; then
    return 0
  fi
  warn "Unsupported init/service manager for this task: $task. systemd/systemctl is required for this implementation."
  return 1
}

pkg_installed() {  # pkg_installed NAME
  case "$PKG_FAMILY" in
    apt) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed";;
    dnf|yum) rpm -q "$1" >/dev/null 2>&1;;
    *) return 1;;
  esac
}

pkg_available() {
  local p="$1"
  pkg_installed "$p" && return 0
  case "$PKG_FAMILY" in
    apt)
      command -v apt-cache >/dev/null 2>&1 && apt-cache show "$p" >/dev/null 2>&1
      ;;
    dnf)
      dnf -q list --available "$p" >/dev/null 2>&1
      ;;
    yum)
      yum -q list available "$p" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

pkg_install() {
  local p="$1"
  case "$PKG_FAMILY" in
    apt) run env DEBIAN_FRONTEND=noninteractive apt-get install -y "$p";;
    dnf) run dnf install -y "$p";;
    yum) run yum install -y "$p";;
    *) warn "Unsupported package manager for installing $p"; return 1;;
  esac
}

# Purge/remove a package and record it for reinstall on revert.
pkg_remove() {
  local p="$1"
  record_action "PKG_REMOVE" "$PKG_FAMILY" "$p"
  case "$PKG_FAMILY" in
    apt) run env DEBIAN_FRONTEND=noninteractive apt-get purge -y "$p";;
    dnf) run dnf remove -y "$p";;
    yum) run yum remove -y "$p";;
    *) warn "Unsupported package manager for removing $p"; return 1;;
  esac
}

# Install a package we want kept; record so revert can remove it if desired.
pkg_install_tracked() {
  local p="$1"
  if pkg_installed "$p"; then info "$p already installed."; return 0; fi
  if ! pkg_available "$p"; then
    warn "$p is not available from the configured repositories for ${DISTRO_ID:-this distro}; skipping."
    return 1
  fi
  record_action "PKG_INSTALL" "$PKG_FAMILY" "$p"
  if pkg_install "$p"; then
    ok "Installed $p"
    return 0
  else
    warn "Failed to install $p"
    return 1
  fi
}

# Run the platform's package upgrade flow. This is intentionally logged as a
# note rather than a reversible action: package version rollbacks are not safe
# to automate from this toolkit's backup model.
pkg_full_upgrade() {
  record_action "NOTE" "full_package_upgrade_run_not_revertible"
  case "$PKG_FAMILY" in
    apt)
      run apt-get update
      run env DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt-get full-upgrade -y
      if command -v snap >/dev/null 2>&1; then run snap refresh; fi
      ;;
    dnf)
      run dnf upgrade -y
      ;;
    yum)
      run yum update -y
      ;;
  esac
}

# ============================================================================
# SECTION 1 — Scored service health check (READ-ONLY)
# ============================================================================
check_listen_tcp() {
  local port="$1"
  command -v ss >/dev/null 2>&1 || { warn "ss not available; cannot check TCP/${port} listener."; return 1; }
  if ss -ltn 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$" {found=1} END{exit !found}'; then
    ok "TCP/${port} is listening"
  else
    warn "TCP/${port} is NOT listening"
    return 1
  fi
}

check_listen_udp() {
  local port="$1"
  command -v ss >/dev/null 2>&1 || { warn "ss not available; cannot check UDP/${port} listener."; return 1; }
  if ss -lun 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$" {found=1} END{exit !found}'; then
    ok "UDP/${port} is listening"
  else
    warn "UDP/${port} is NOT listening"
    return 1
  fi
}

probe_url() {
  local url="$1" code
  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not available; cannot probe $url"
    return 1
  fi
  info "Probing $url"
  code=$(curl -k -L -sS -o /dev/null -w '%{http_code}' --max-time 8 "$url" 2>>"$OUTPUT_LOG") || {
    warn "$url failed to respond"
    return 1
  }
  if [[ "$code" =~ ^(2|3)[0-9][0-9]$ ]]; then
    ok "$url returned HTTP $code"
  else
    warn "$url returned HTTP $code"
    return 1
  fi
}

run_scored_service_checks() {
  local phase="$1" sshsvc p urls url dns_name
  log "Scored service health check (${phase})"
  warn "This is read-only. It verifies local service health, not external scoring reachability."

  sshsvc="$(ssh_service_name)"
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q "^${sshsvc}\.service"; then
    run systemctl is-active "$sshsvc" || warn "$sshsvc is not active"
  elif command -v systemctl >/dev/null 2>&1; then
    warn "$sshsvc.service not found"
  else
    warn "systemctl not available; skipping SSH service-state check."
  fi
  local -a ssh_ports=()
  if command -v sshd >/dev/null 2>&1; then
    mapfile -t ssh_ports < <(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u)
  fi
  [[ ${#ssh_ports[@]} -eq 0 ]] && ssh_ports=(22)
  for p in "${ssh_ports[@]}"; do check_listen_tcp "$p" || true; done

  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -Eq '^(apache2|httpd|nginx|lighttpd)\.service'; then
    for p in 80 443; do check_listen_tcp "$p" || true; done
  else
    warn "No common HTTP service unit found; still checking TCP/80 and TCP/443."
    check_listen_tcp 80 || true
    check_listen_tcp 443 || true
  fi
  urls="${WEB_CHECK_URLS:-http://127.0.0.1/ http://localhost/}"
  for url in $urls; do probe_url "$url" || true; done
  if [[ -z "${WEB_CHECK_URLS:-}" ]]; then
    warn "Set WEB_CHECK_URLS='http://127.0.0.1/login http://127.0.0.1/app-check' to check real login/functionality paths."
  fi

  check_listen_tcp 53 || true
  check_listen_udp 53 || true
  dns_name="${DNS_TEST_NAME:-rrintel.internal}"
  if command -v dig >/dev/null 2>&1; then
    run dig +time=2 +tries=1 "@127.0.0.1" "$dns_name" A || warn "Local DNS query for $dns_name failed"
    run dig +time=2 +tries=1 "@127.0.0.1" "$dns_name" SOA || true
  else
    warn "dig not available; install dnsutils/bind-utils for DNS query checks."
  fi
}

sec_scored_services() {
  local phase="${1:-manual}"
  start_task "scored_services_${phase}" "Scored Service Health Check (${phase}, read-only)"
  run_scored_service_checks "$phase"
  end_task
}

# ============================================================================
# SECTION 2 — AD / DNS / time dependency check (READ-ONLY)
# ============================================================================
sec_ad_deps() {
  start_task "ad_deps" "AD / DNS / Time Dependency Check (read-only)"
  local domain="${AD_DOMAIN:-rrintel.internal}" svc
  log "Domain target: $domain (override with AD_DOMAIN=example.internal)"
  [[ -r /etc/resolv.conf ]] && { log "/etc/resolv.conf:"; run sed -n '1,40p' /etc/resolv.conf; }
  if command -v resolvectl >/dev/null 2>&1; then run resolvectl status; fi
  run getent hosts "$domain" || warn "getent could not resolve $domain"
  if command -v dig >/dev/null 2>&1; then
    run dig +time=2 +tries=1 "$domain" A || true
    run dig +time=2 +tries=1 "_ldap._tcp.${domain}" SRV || warn "LDAP SRV lookup failed for $domain"
    run dig +time=2 +tries=1 "_kerberos._tcp.${domain}" SRV || true
  else
    warn "dig not available; SRV record checks skipped."
  fi

  if command -v timedatectl >/dev/null 2>&1; then run timedatectl status; fi
  if command -v chronyc >/dev/null 2>&1; then run chronyc sources -v; fi
  if command -v ntpq >/dev/null 2>&1; then run ntpq -p; fi

  for svc in sssd winbind nslcd realmd systemd-timesyncd chronyd; do
    command -v systemctl >/dev/null 2>&1 || { warn "systemctl not available; skipping service-state checks."; break; }
    systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" || continue
    run systemctl is-active "$svc" || warn "$svc is not active"
  done
  if command -v realm >/dev/null 2>&1; then run realm list; fi
  if command -v sssctl >/dev/null 2>&1; then
    run sssctl domain-list || true
    run sssctl domain-status "$domain" || true
  fi
  if command -v wbinfo >/dev/null 2>&1; then run wbinfo -t || true; fi
  if command -v klist >/dev/null 2>&1; then run klist -k || true; fi
  ok "AD/DNS/time dependency check complete; review failures before changing auth, DNS, firewall, or time settings."
  end_task
}

# ============================================================================
# SECTION 3 — DNS service validation (READ-ONLY)
# ============================================================================
sec_dns_validation() {
  start_task "dns_validation" "DNS Service Validation (read-only)"
  local dns_name="${DNS_TEST_NAME:-rrintel.internal}" svc
  for svc in named bind9 unbound dnsmasq systemd-resolved; do
    command -v systemctl >/dev/null 2>&1 || { warn "systemctl not available; skipping DNS service-state checks."; break; }
    systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" || continue
    run systemctl is-active "$svc" || warn "$svc is not active"
  done

  if command -v named-checkconf >/dev/null 2>&1; then
    run named-checkconf || warn "named-checkconf failed"
    run named-checkconf -z || warn "named-checkconf -z failed or no zones were loaded"
  fi
  if command -v unbound-checkconf >/dev/null 2>&1; then run unbound-checkconf || warn "unbound-checkconf failed"; fi
  if command -v dnsmasq >/dev/null 2>&1; then run dnsmasq --test || warn "dnsmasq --test failed"; fi
  if command -v rndc >/dev/null 2>&1; then run rndc status || true; fi

  check_listen_tcp 53 || true
  check_listen_udp 53 || true
  if command -v dig >/dev/null 2>&1; then
    run dig +time=2 +tries=1 "@127.0.0.1" "$dns_name" A || warn "A query failed for $dns_name"
    run dig +time=2 +tries=1 "@127.0.0.1" "$dns_name" SOA || true
    run dig +time=2 +tries=1 "@127.0.0.1" localhost A || true
  else
    warn "dig not available; install dnsutils/bind-utils for local query checks."
  fi
  ok "DNS validation complete."
  end_task
}

# ============================================================================
# SECTION 4 — Webroot malware / permissions sweep (READ-ONLY)
# ============================================================================
discover_web_roots() {
  local -a roots=()
  local d path
  for d in /var/www /var/www/html /srv/www /srv/http /usr/share/nginx/html /opt/lampp/htdocs; do
    [[ -d "$d" ]] && ! in_list "$d" "${roots[@]}" && roots+=("$d")
  done
  while IFS= read -r path; do
    [[ "$path" == /* && -d "$path" ]] || continue
    ! in_list "$path" "${roots[@]}" && roots+=("$path")
  done < <(
    grep -RihE '^[[:space:]]*(DocumentRoot|root)[[:space:]]+' \
      /etc/apache2 /etc/httpd /etc/nginx 2>/dev/null \
      | sed -E 's/^[[:space:]]*(DocumentRoot|root)[[:space:]]+//; s/[;"].*$//; s/"//g' \
      | awk '{print $1}' | sort -u
  )
  printf '%s\n' "${roots[@]}"
}

sec_web_sweep() {
  start_task "web_sweep" "Webroot Malware & Permissions Sweep (read-only)"
  local -a roots=()
  local root ini
  mapfile -t roots < <(discover_web_roots)
  if [[ ${#roots[@]} -eq 0 ]]; then
    warn "No common web roots found."
  else
    log "Web roots found:"
    printf '      - %s\n' "${roots[@]}"
  fi

  for root in "${roots[@]}"; do
    log "World-writable files/dirs under $root:"
    find "$root" -xdev \( -type f -o -type d \) -perm -0002 -ls 2>/dev/null | head -200 || true

    log "Recently modified web files under $root (last 7 days, last 100 shown):"
    find "$root" -xdev -type f -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %p\n' 2>/dev/null \
      | sort | tail -100 || true

    log "Suspicious PHP/webshell patterns under $root (first 200 hits):"
    grep -RInE --include='*.php' --include='*.phtml' --include='*.phar' --include='*.inc' \
      'eval[[:space:]]*\(|base64_decode[[:space:]]*\(|gzinflate[[:space:]]*\(|str_rot13[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|system[[:space:]]*\(|proc_open[[:space:]]*\(|popen[[:space:]]*\(|assert[[:space:]]*\(|preg_replace[[:space:]]*\(.*/e|c99|r57|weevely|/dev/tcp|cmd=' \
      "$root" 2>/dev/null | head -200 || true
  done

  log "PHP security-relevant ini settings:"
  while IFS= read -r ini; do
    [[ -f "$ini" ]] || continue
    echo "== $ini =="
    grep -nE '^[[:space:]]*(disable_functions|allow_url_fopen|allow_url_include|display_errors|expose_php|open_basedir)[[:space:]]*=' "$ini" 2>/dev/null || true
  done < <({ ls /etc/php/*/*/php.ini /etc/php.ini /etc/php/php.ini 2>/dev/null; } | sort -u)

  ok "Webroot sweep complete; investigate hits manually before deleting files."
  end_task
}

# ============================================================================
# SECTION 5 — Forensic / persistence checks (READ-ONLY: nothing to revert)
# ============================================================================
sec_forensics() {
  start_task "forensics" "Forensic / Persistence Checks (read-only)"
  local wl u out
  log "Listening sockets:";                 run ss -tulpen
  log "All active TCP/UDP connections:";    run ss -tunap
  if command -v lsof >/dev/null 2>&1; then
    log "Open network files (lsof -i):";     run lsof -i -P -n
  else
    info "lsof not installed; skipping 'lsof -i' (install 'lsof' for this check)."
  fi
  log "Suspicious reverse-shell processes:"
  # shellcheck disable=SC2009
  ps auww | grep -Ei 'nc |ncat|netcat|socat|bash -i|/dev/tcp|python.*socket|perl.*socket|curl.*sh|wget.*sh' | grep -v grep
  if command -v systemctl >/dev/null 2>&1; then
    log "Enabled systemd services:";         run systemctl list-unit-files --type=service --state=enabled
  else
    warn "systemctl not available; skipping enabled systemd service list."
  fi
  log "systemd unit ExecStart lines:";       find /etc/systemd/system /lib/systemd/system -type f -name "*.service" -exec grep -H "ExecStart" {} \; >> "$OUTPUT_LOG" 2>&1
  log "System crontab + cron.* dirs:";       { cat /etc/crontab; grep -R . /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null; } >> "$OUTPUT_LOG" 2>&1
  log "Per-user crontabs:"
  while IFS=: read -r u _; do
    out=$(crontab -l -u "$u" 2>/dev/null)
    [[ -n "$out" ]] && { echo "== $u =="; echo "$out"; }
  done < /etc/passwd >> "$OUTPUT_LOG" 2>&1
  log "Executable files in tmp/home dirs:";  find /tmp /var/tmp /dev/shm /home /root -type f -perm /111 -ls >> "$OUTPUT_LOG" 2>&1
  log "Hidden files in tmp/home dirs:";       find /tmp /var/tmp /dev/shm /home /root -type f -name '.*' -ls >> "$OUTPUT_LOG" 2>&1
  log "SSH .ssh directories (persistence check):"
  find /root /home -name ".ssh" -type d -exec ls -ld {} \; >> "$OUTPUT_LOG" 2>&1
  log "SSH authorized_keys across users:";    find /root /home -name authorized_keys -exec ls -l {} \; -exec cat {} \; >> "$OUTPUT_LOG" 2>&1
  log "/etc/hosts (review for suspicious / spoofed entries):"; run cat /etc/hosts
  log "Web server logs (tails, if present):"
  for wl in /var/log/apache2/access.log /var/log/apache2/error.log \
            /var/log/httpd/access_log /var/log/httpd/error_log \
            /var/log/nginx/access.log /var/log/nginx/error.log; do
    [[ -f "$wl" ]] && { echo "== $wl (last 20) =="; tail -n 20 "$wl"; } >> "$OUTPUT_LOG" 2>&1
  done
  log "SUID binaries:";                       find / -perm -4000 -type f 2>/dev/null
  log "SGID binaries:";                       find / -perm -2000 -type f 2>/dev/null >> "$OUTPUT_LOG" 2>&1
  if is_rhel; then
    log "SELinux status:"
    if command -v sestatus >/dev/null 2>&1; then run sestatus; else warn "sestatus not available."; fi
  else
    log "AppArmor status:"
    if command -v aa-status >/dev/null 2>&1; then run aa-status; else warn "aa-status not available."; fi
  fi
  ok "Forensic report written to $OUTPUT_LOG (review it manually)."
  end_task
}

# ============================================================================
# SECTION 6 — Web/app backup snapshot
# ============================================================================
archive_existing_paths() {
  local archive="$1"; shift
  local -a rel=()
  local p
  for p in "$@"; do
    [[ -e "$p" ]] || continue
    rel+=("${p#/}")
  done
  if [[ ${#rel[@]} -eq 0 ]]; then
    warn "No existing paths to archive for $archive"
    return 1
  fi
  run tar czf "$archive" -C / "${rel[@]}"
}

dump_mysql_all_databases() {
  local dest="$1" dumper=""
  if command -v mariadb-dump >/dev/null 2>&1; then dumper="mariadb-dump"
  elif command -v mysqldump >/dev/null 2>&1; then dumper="mysqldump"
  else return 1
  fi
  echo "    + $dumper --all-databases --single-transaction --routines --events > $dest"
  "$dumper" --all-databases --single-transaction --routines --events > "$dest"
}

dump_postgres_all_databases() {
  local dest="$1"
  command -v pg_dumpall >/dev/null 2>&1 || return 1
  echo "    + runuser -u postgres -- pg_dumpall > $dest"
  if command -v runuser >/dev/null 2>&1; then
    runuser -u postgres -- pg_dumpall > "$dest"
  else
    su - postgres -c pg_dumpall > "$dest"
  fi
}

sec_backup_snapshot() {
  start_task "backup_snapshot" "Web/App Backup Snapshot"
  require_supported_write "Web/App Backup Snapshot" || { end_task; return; }
  warn "Outcome: creates root-only tar/dump files under this run directory. Risk: can take time and may store secrets from app configs and database dumps."
  local backup_root="$RUN_DIR/app-backups"
  mkdir -p "$backup_root"
  chmod 700 "$backup_root" 2>/dev/null || true

  local -a web_roots=() config_paths=()
  mapfile -t web_roots < <(discover_web_roots)
  config_paths=(/etc/apache2 /etc/httpd /etc/nginx /etc/php /etc/mysql /etc/my.cnf /etc/my.cnf.d /etc/postgresql /etc/letsencrypt)

  if confirm "Archive discovered web roots and common web/app config directories now? Outcome: rollback evidence before hardening. Risk: archive may be large and contain secrets"; then
    if archive_existing_paths "$backup_root/webroots-and-configs.tar.gz" "${web_roots[@]}" "${config_paths[@]}"; then
      ok "Web/app archive written to $backup_root/webroots-and-configs.tar.gz"
    else
      warn "Web/app archive was not created."
    fi
    record_action "NOTE" "web_app_backup_snapshot:$backup_root/webroots-and-configs.tar.gz"
  else
    info "Web/app archive skipped."
  fi

  if command -v mysqldump >/dev/null 2>&1 || command -v mariadb-dump >/dev/null 2>&1; then
    if confirm "Dump all MySQL/MariaDB databases? Outcome: preserves DB state before changes. Risk: may require DB credentials, can be slow, stores sensitive data"; then
      if dump_mysql_all_databases "$backup_root/mysql-all-databases.sql"; then
        chmod 600 "$backup_root/mysql-all-databases.sql" 2>/dev/null || true
        ok "MySQL/MariaDB dump written to $backup_root/mysql-all-databases.sql"
        record_action "NOTE" "mysql_dump_snapshot:$backup_root/mysql-all-databases.sql"
      else
        warn "MySQL/MariaDB dump failed; credentials or socket auth may be required."
      fi
    fi
  fi

  if command -v pg_dumpall >/dev/null 2>&1; then
    if confirm "Dump all PostgreSQL databases? Outcome: preserves DB state before changes. Risk: may be slow and stores sensitive data"; then
      if dump_postgres_all_databases "$backup_root/postgresql-all-databases.sql"; then
        chmod 600 "$backup_root/postgresql-all-databases.sql" 2>/dev/null || true
        ok "PostgreSQL dump written to $backup_root/postgresql-all-databases.sql"
        record_action "NOTE" "postgres_dump_snapshot:$backup_root/postgresql-all-databases.sql"
      else
        warn "PostgreSQL dump failed; run manually if the DB is scored or business-critical."
      fi
    fi
  fi
  ok "Backup snapshot section complete."
  end_task
}

# ============================================================================
# SECTION 7 — User & Group Audit
# ============================================================================
AUTH_USERS=(); AUTH_SUDO=()
parse_authorized() {
  AUTH_USERS=(); AUTH_SUDO=(); local sec="" line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(echo "$line" | xargs 2>/dev/null)"
    [[ -z "$line" ]] && continue
    case "${line,,}" in
      "[users]")   sec="users";   continue;;
      "[sudoers]") sec="sudoers"; continue;;
    esac
    [[ "$sec" == "users"   ]] && AUTH_USERS+=("$line")
    [[ "$sec" == "sudoers" ]] && AUTH_SUDO+=("$line")
  done < "$AUTH_FILE"
}

in_list() { local x="$1"; shift; local i; for i in "$@"; do [[ "$x" == "$i" ]] && return 0; done; return 1; }

sec_user_audit() {
  start_task "user_audit" "User & Group Audit"
  require_supported_write "User & Group Audit" || { end_task; return; }
  if [[ ! -r "$AUTH_FILE" ]]; then
    warn "Authorized file not found at: $AUTH_FILE"
    warn "Skipping user audit. Re-run with --authorized PATH (see header for format)."
    end_task; return
  fi
  parse_authorized
  info "Authorized users:  ${AUTH_USERS[*]:-(none)}"
  info "Authorized admins: ${AUTH_SUDO[*]:-(none)}"

  local me="${SUDO_USER:-root}"

  # --- UID-0 (root-equivalent) accounts other than root ---
  local uid0
  mapfile -t uid0 < <(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
  if [[ ${#uid0[@]} -gt 0 ]]; then
    warn "Accounts with UID 0 (root-equivalent!) besides root: ${uid0[*]}"
    warn "These are highly suspicious. Review them; deletion offered below."
  fi

  # --- Unauthorized human accounts ---
  local humans unauth=()
  mapfile -t humans < <(awk -F: '$3>=1000 && $3<65534 && $1!="nobody"{print $1}' /etc/passwd)
  local u
  for u in "${humans[@]}" "${uid0[@]}"; do
    in_list "$u" "${AUTH_USERS[@]}" && continue
    [[ "$u" == "$me" ]] && { warn "Account '$u' is unauthorized but is the CURRENT user; not offering deletion."; continue; }
    unauth+=("$u")
  done

  prompt_selection "unauthorized user accounts to DELETE" "${unauth[@]}"
  if [[ ${#SELECTED[@]} -gt 0 ]]; then
    # Back up the account databases once so revert can restore the entries.
    prepare_edit /etc/passwd; prepare_edit /etc/shadow
    prepare_edit /etc/group;  prepare_edit /etc/gshadow
    for u in "${SELECTED[@]}"; do
      local home archive
      home="$(getent passwd "$u" | cut -d: -f6)"
      archive=""
      if [[ -n "$home" && -d "$home" ]]; then
        archive="$BACKUP_DIR/home_${u}.tar.gz"
        run tar czf "$archive" -C / "${home#/}"
      fi
      record_action "USER_DELETE" "$u" "${home:-}" "${archive:-}"
      if run userdel -r "$u"; then
        ok "Deleted user $u (home archived)"
      else
        warn "Failed to delete $u"
      fi
    done
  fi

  # --- Unauthorized sudo/wheel members ---
  local admins admin_unauth=()
  mapfile -t admins < <(getent group "$ADMIN_GROUP" | awk -F: '{print $4}' | tr ',' '\n' | sed '/^$/d')
  for u in "${admins[@]}"; do
    [[ "$u" == "root" || "$u" == "$me" ]] && continue
    in_list "$u" "${AUTH_SUDO[@]}" && continue
    admin_unauth+=("$u")
  done
  prompt_selection "unauthorized '${ADMIN_GROUP}' (admin) members to REMOVE from the group" "${admin_unauth[@]}"
  for u in "${SELECTED[@]}"; do
    record_action "GROUP_MEMBER" "$u" "$ADMIN_GROUP"   # user WAS a member; we remove
    if run gpasswd -d "$u" "$ADMIN_GROUP"; then
      ok "Removed $u from $ADMIN_GROUP"
    else
      warn "Failed removing $u from $ADMIN_GROUP"
    fi
  done

  # --- Non-root groups with GID 0 (root-equivalent group) ---
  # The checklist requires that no group other than 'root' carries GID 0.
  local gid0
  mapfile -t gid0 < <(awk -F: '$3==0 && $1!="root"{print $1}' /etc/group)
  if [[ ${#gid0[@]} -gt 0 ]]; then
    warn "Non-root groups with GID 0 (root-equivalent!): ${gid0[*]}"
    warn "These grant root-group privileges. Investigate per your readme; rename/renumber manually with care."
  else
    ok "No non-root groups carry GID 0."
  fi

  # --- Sudoers audit: NOPASSWD / !authenticate / unauthorized entries ---
  sec_sudoers_audit
  end_task
}

# Audit /etc/sudoers and /etc/sudoers.d for dangerous directives and
# unauthorized users/groups. Called as part of the User & Group Audit.
sec_sudoers_audit() {
  log "Auditing sudoers (/etc/sudoers + /etc/sudoers.d)"
  local sfiles=(/etc/sudoers)
  if [[ -d /etc/sudoers.d ]]; then
    local f
    while IFS= read -r f; do sfiles+=("$f"); done \
      < <(find /etc/sudoers.d -maxdepth 1 -type f ! -name 'README' 2>/dev/null)
  fi

  # 1) NOPASSWD / !authenticate — let sudo run without a password. High risk.
  local hits=() ff
  for ff in "${sfiles[@]}"; do
    [[ -r "$ff" ]] || continue
    grep -nEi '(^|[[:space:]])NOPASSWD|!authenticate' "$ff" 2>/dev/null \
      | while IFS= read -r ln; do echo "${ff}: ${ln}"; done
    grep -qEi '(^|[[:space:]])NOPASSWD|!authenticate' "$ff" 2>/dev/null && hits+=("$ff")
  done
  if [[ ${#hits[@]} -gt 0 ]]; then
    warn "NOPASSWD / !authenticate found in: ${hits[*]}"
    if confirm "Comment out NOPASSWD/!authenticate lines (forces password for sudo)?"; then
      for ff in "${hits[@]}"; do
        prepare_edit "$ff"
        # comment offending lines; re-validate, restore on failure
        sed -i -E 's/^([^#].*(NOPASSWD|!authenticate).*)$/# harden.sh disabled: \1/I' "$ff"
        if visudo -cf "$ff" >/dev/null 2>&1; then
          ok "Neutralized NOPASSWD/!authenticate in $ff"
        else
          err "visudo rejected edited $ff; restoring original."
          restore_task_backup "$ff"
        fi
      done
    fi
  else
    ok "No NOPASSWD / !authenticate directives in sudoers."
  fi

  # 2) Risky command-specific grants and group lines — surfaced for review only.
  log "Sudo grants (users/groups with sudo rights) — review against your readme:"
  for ff in "${sfiles[@]}"; do
    [[ -r "$ff" ]] || continue
    grep -nE '^[[:space:]]*[%A-Za-z0-9_].*ALL' "$ff" 2>/dev/null \
      | sed "s#^#      ${ff}: #"
  done

  # 3) Unauthorized members of the admin group vs authorized.txt [sudoers]
  #    (membership removal already handled above; here we also flag direct
  #     user entries inside sudoers files that are not authorized admins).
  if [[ -r "$AUTH_FILE" ]]; then
    local direct=() name
    for ff in "${sfiles[@]}"; do
      [[ -r "$ff" ]] || continue
      while IFS= read -r name; do
        [[ -z "$name" || "$name" == "root" || "$name" == %* ]] && continue
        in_list "$name" "${AUTH_SUDO[@]}" && continue
        getent passwd "$name" >/dev/null 2>&1 && direct+=("$name (in $ff)")
      done < <(grep -E '^[[:space:]]*[A-Za-z0-9_]+[[:space:]].*ALL' "$ff" 2>/dev/null | awk '{print $1}')
    done
    if [[ ${#direct[@]} -gt 0 ]]; then
      warn "Direct sudoers grants to users NOT in authorized [sudoers]: ${direct[*]}"
      warn "Edit with 'visudo' / 'visudo -f <file>' to remove unauthorized grants."
    fi
  fi

  # 4) Sudo command logging (accountability) — checklist's /etc/sudoers.d/logging
  local lf=/etc/sudoers.d/logging
  if confirm "Enable sudo command logging (/etc/sudoers.d/logging)?"; then
    prepare_edit "$lf"
    cat > "$lf" <<'EOF'
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
EOF
    chmod 440 "$lf"
    if visudo -cf "$lf" >/dev/null 2>&1; then
      ok "Sudo logging enabled ($lf -> /var/log/sudo.log)"
    else
      err "visudo rejected $lf; restoring/removing."
      restore_task_backup "$lf"
    fi
  fi
}

# ============================================================================
# SECTION 8 — Package upgrade / Automatic security updates
# ============================================================================
sec_autoupdate() {
  start_task "autoupdate" "Package Upgrade / Automatic Security Updates"
  require_supported_write "Package Upgrade / Automatic Security Updates" || { end_task; return; }
  require_systemd_task "Package Upgrade / Automatic Security Updates" || { end_task; return; }
  warn "A full package upgrade can change package versions and is logged, but not version-rolled-back by revert.sh."
  local do_upgrade=0
  if ask_risky "Run a full package upgrade now. Competition note: upgrades can restart or change scored services; verify HTTP/SSH/DNS after this section"; then
    do_upgrade=1
  else
    warn "Full package upgrade skipped; automatic security update configuration will still be applied."
  fi

  if is_debian; then
    run apt-get update
    if ! pkg_install_tracked unattended-upgrades; then
      warn "unattended-upgrades is not available for this Debian/Ubuntu system; skipping automatic update configuration."
      end_task; return
    fi
    pkg_install_tracked apt-listchanges || warn "apt-listchanges unavailable; continuing without it."
    if [[ $do_upgrade -eq 1 ]]; then
      record_action "NOTE" "full_package_upgrade_run_not_revertible"
      run env DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none apt-get full-upgrade -y
      if command -v snap >/dev/null 2>&1; then run snap refresh; fi
    fi
    local f=/etc/apt/apt.conf.d/20auto-upgrades
    prepare_edit "$f"
    cat > "$f" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
    if command -v dpkg-reconfigure >/dev/null 2>&1; then
      run env DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive unattended-upgrades
    else
      warn "dpkg-reconfigure not available; unattended-upgrades config file was still written."
    fi
    run systemctl enable --now unattended-upgrades 2>/dev/null
    ok "unattended-upgrades and apt-listchanges configured"
  else
    [[ $do_upgrade -eq 1 ]] && pkg_full_upgrade
    if [[ "$PKG_FAMILY" == "dnf" ]]; then
      if ! pkg_install_tracked dnf-automatic; then
        warn "dnf-automatic is not available; skipping automatic update configuration."
        end_task; return
      fi
      local f=/etc/dnf/automatic.conf
      prepare_edit "$f"
      set_conf_kv "$f" upgrade_type security " = "
      set_conf_kv "$f" download_updates yes " = "
      set_conf_kv "$f" apply_updates yes " = "
      record_action "TIMER" "dnf-automatic-install.timer"
      run systemctl enable --now dnf-automatic-install.timer
      ok "dnf-automatic configured (security only)"
    else
      if ! pkg_install_tracked yum-cron; then
        warn "yum-cron is not available; skipping automatic update configuration."
        end_task; return
      fi
      local f=/etc/yum/yum-cron.conf
      prepare_edit "$f"
      set_conf_kv "$f" update_cmd security " = "
      set_conf_kv "$f" download_updates yes " = "
      set_conf_kv "$f" apply_updates yes " = "
      record_service yum-cron
      run systemctl enable --now yum-cron
      ok "yum-cron configured (security only)"
    fi
  fi
  end_task
}

# ============================================================================
# SECTION 9 — Password Policies
# ============================================================================
sec_passwords() {
  start_task "passwords" "Password Policies (aging, complexity)"
  require_supported_write "Password Policies" || { end_task; return; }
  # pwquality module
  local pwquality_available=0
  if is_debian; then
    pkg_install_tracked libpam-pwquality && pwquality_available=1
  else
    pkg_install_tracked libpwquality && pwquality_available=1
  fi

  # login.defs aging defaults
  log "Setting password aging defaults in /etc/login.defs"
  set_conf_kv /etc/login.defs PASS_MAX_DAYS 90 "   "
  set_conf_kv /etc/login.defs PASS_MIN_DAYS 7  "   "
  set_conf_kv /etc/login.defs PASS_WARN_AGE 12 "   "
  ok "login.defs updated"

  # pwquality complexity
  log "Writing /etc/security/pwquality.conf"
  prepare_edit /etc/security/pwquality.conf
  set_conf_kv /etc/security/pwquality.conf minlen    14 " = "
  set_conf_kv /etc/security/pwquality.conf dcredit    -1 " = "
  set_conf_kv /etc/security/pwquality.conf ucredit    -1 " = "
  set_conf_kv /etc/security/pwquality.conf ocredit    -1 " = "
  set_conf_kv /etc/security/pwquality.conf lcredit    -1 " = "
  set_conf_kv /etc/security/pwquality.conf maxrepeat   3 " = "
  set_conf_kv /etc/security/pwquality.conf dictcheck   1 " = "
  ok "pwquality.conf updated (pam_pwquality reads this automatically)"

  # --- PAM enforcement: wire pam_pwquality into the password stack ---
  # pwquality.conf alone does nothing unless pam_pwquality.so is actually called.
  # On Debian, libpam-pwquality registers it via pam-auth-update; we additionally
  # ensure retry=3 is present. On RHEL the system-auth/password-auth stacks call
  # it by default. This is gated risky because a malformed PAM stack can break
  # password changes (login still works); this run backs the files up.
  if [[ $pwquality_available -eq 0 ]]; then
    warn "pwquality PAM package is unavailable; skipping PAM stack enforcement."
  elif ask_risky "Enforce pam_pwquality in the PAM password stack (retry=3). Backs up PAM files; revert.sh can restore them"; then
    if is_debian; then
      local cp=/etc/pam.d/common-password
      if [[ -f "$cp" ]]; then
        prepare_edit "$cp"
        if grep -qE '^[[:space:]]*password.*pam_pwquality\.so' "$cp"; then
          # ensure retry=3 is set on the existing line
          grep -qE 'pam_pwquality\.so.*retry=' "$cp" \
            || sed -i -E 's@(pam_pwquality\.so)@\1 retry=3@' "$cp"
        else
          # insert before the primary pam_unix password line
          sed -i -E '0,/^[[:space:]]*password.*pam_unix\.so/s//password requisite pam_pwquality.so retry=3\n&/' "$cp"
        fi
        ok "pam_pwquality wired into $cp (retry=3)"
      else
        warn "$cp not found; skipped PAM password enforcement."
      fi
    else
      # RHEL/Fedora/Alma/Rocky: authselect-managed PAM files should not be
      # hand-edited. The stock profiles normally include pam_pwquality and read
      # /etc/security/pwquality.conf. If a custom profile omits it, surface that
      # as a manual authselect-profile fix instead of guessing.
      local sa missing_pwquality=0
      if command -v authselect >/dev/null 2>&1; then
        run authselect current || true
        run authselect check || warn "authselect reports local PAM/profile changes; review before changing authentication."
        for sa in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
          [[ -f "$sa" ]] || continue
          if grep -qE 'pam_pwquality\.so' "$sa"; then
            ok "pam_pwquality already present in $sa"
          else
            warn "pam_pwquality is missing from authselect-managed file $sa; not editing it directly."
            missing_pwquality=1
          fi
        done
        [[ $missing_pwquality -eq 1 ]] && warn "Create/select an authselect profile that includes pam_pwquality, then run 'authselect apply-changes'."
      else
        for sa in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
          [[ -f "$sa" ]] || continue
          if grep -qE 'pam_pwquality\.so' "$sa"; then
            ok "pam_pwquality already present in $sa"
          else
            prepare_edit "$sa"
            sed -i -E '0,/^[[:space:]]*password.*pam_unix\.so/s//password    requisite     pam_pwquality.so try_first_pass local_users_only retry=3\n&/' "$sa"
            ok "pam_pwquality inserted into $sa"
          fi
        done
      fi
    fi
  fi

  # Apply aging to existing human accounts (risky: affects all users' expiry)
  if ask_risky "Apply 90/7/12 day aging to ALL existing human accounts (chage)"; then
    local u
    while IFS= read -r u; do
      # record current aging so revert can restore it
      local cur
      cur=$(chage -l "$u" 2>/dev/null | awk -F: '/Maximum/{m=$2} /Minimum/{n=$2} /warning/{w=$2} END{gsub(/ /,"",m);gsub(/ /,"",n);gsub(/ /,"",w);print m":"n":"w}')
      record_action "CHAGE" "$u" "${cur:-:::}"
      run chage -M 90 -m 7 -W 12 "$u"
    done < <(awk -F: '$3>=1000 && $1!="nobody"{print $1}' /etc/passwd)
    ok "Password aging applied to existing accounts"
  fi
  end_task
}

# ============================================================================
# SECTION 10 — Password Strength Audit (detect & reset weak passwords)
# ============================================================================
# Strength of an EXISTING password cannot be derived from its hash; the only
# way to judge it is to test candidate passwords against the hash. We prefer
# John the Ripper + the rockyou wordlist (the most popular tooling for this),
# auto-removing john afterward if we installed it (it is a dual-use cracker and
# is on this toolkit's own purge list). When john/network is unavailable we
# fall back to a built-in crypt-compare (python3) over a common-password list.

# Generate a strong random password: 20 chars, guaranteeing one of each of the
# four character classes (the rest random). LC_ALL=C is required so that tr
# tolerates the binary bytes from /dev/urandom on any locale.
gen_password() {
  local lower upper digit special rest
  lower=$(LC_ALL=C tr -dc '[:lower:]'  </dev/urandom | head -c1)
  upper=$(LC_ALL=C tr -dc '[:upper:]'  </dev/urandom | head -c1)
  digit=$(LC_ALL=C tr -dc '0-9'        </dev/urandom | head -c1)
  special=$(LC_ALL=C tr -dc '!@#%^*_=+-' </dev/urandom | head -c1)
  rest=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#%^*_=+-' </dev/urandom | head -c16)
  printf '%s' "${lower}${upper}${digit}${special}${rest}"
}

# Built-in fallback: try common passwords + username variants against a hash
# using python3's crypt (handles yescrypt/sha512/md5). Echoes the matched
# plaintext if weak, nothing if not cracked.
crack_one_builtin() {
  local user="$1" hash="$2" wordlist="$3"
  python3 - "$user" "$hash" "$wordlist" <<'PY'
import crypt, sys, hmac
user, stored, wl = sys.argv[1], sys.argv[2], sys.argv[3]
cands = set()
try:
    with open(wl, 'r', encoding='latin-1') as f:
        for line in f:
            w = line.rstrip('\n')
            if w:
                cands.add(w)
except OSError:
    pass
# username-derived guesses
for v in (user, user+'123', user+'1', user.capitalize(), user+'2024', user+'2025',
          'password','Password1','password123','123456','12345678','qwerty',
          'letmein','admin','root','toor','changeme','welcome','cyberpatriot',
          'P@ssw0rd','Password123!'):
    cands.add(v)
for w in cands:
    try:
        if hmac.compare_digest(crypt.crypt(w, stored), stored):
            print(w); sys.exit(0)
    except Exception:
        continue
sys.exit(1)
PY
}

sec_pwaudit() {
  start_task "pwaudit" "Password Strength Audit (detect & reset weak passwords)"
  require_supported_write "Password Strength Audit" || { end_task; return; }
  warn "This tests account passwords and RESETS weak ones to a new strong password."
  warn "Old plaintext+hash are logged (revertable); new passwords saved to: $CREDS_FILE (root only)"
  if ! confirm "Proceed with the password strength audit?"; then
    info "Skipped by user."; end_task; return
  fi
  command -v python3 >/dev/null 2>&1 || warn "python3 not found; built-in fallback unavailable."

  # The account running this audit (the competitor's assigned user) is NOT
  # scored for password strength and must keep its password — skip it entirely.
  local me="${SUDO_USER:-root}"

  # Build the in-scope account list: anything with a usable password hash
  # (skip locked '!'/'*' and empty entries). Includes root, excludes the
  # auditing account.
  local -A USERHASH=()
  local u h
  while IFS=: read -r u h _; do
    if [[ "$u" == "$me" ]]; then
      info "Skipping '$u' (the account running this audit) — its password is left unchanged."
      continue
    fi
    case "$h" in ""|"!"|"!!"|"*"|"x"|"!*") continue;; esac
    [[ "$h" == \!* ]] && continue          # locked
    USERHASH["$u"]="$h"
  done < /etc/shadow
  if [[ ${#USERHASH[@]} -eq 0 ]]; then ok "No accounts with a usable password to audit."; end_task; return; fi
  info "Accounts in scope: ${!USERHASH[*]}"

  # ---- obtain a wordlist (rockyou preferred) ----
  local wordlist="" tmpd; tmpd="$BACKUP_DIR/pwaudit"; mkdir -p "$tmpd"
  for w in /usr/share/wordlists/rockyou.txt /usr/share/wordlists/rockyou.txt.gz \
           "${PW_WORDLIST:-}" ; do
    [[ -n "$w" && -e "$w" ]] || continue
    if [[ "$w" == *.gz ]]; then gunzip -c "$w" > "$tmpd/rockyou.txt" 2>/dev/null && wordlist="$tmpd/rockyou.txt"
    else wordlist="$w"; fi
    [[ -n "$wordlist" ]] && break
  done
  if [[ -z "$wordlist" ]] && is_debian; then
    info "Installing 'wordlists' package to obtain rockyou..."
    if pkg_installed wordlists; then
      :
    elif pkg_available wordlists; then
      WL_INSTALLED=1
      pkg_install wordlists || warn "wordlists install failed."
    else
      warn "wordlists package is not available from configured repositories."
    fi
    [[ -f /usr/share/wordlists/rockyou.txt.gz ]] && gunzip -c /usr/share/wordlists/rockyou.txt.gz > "$tmpd/rockyou.txt" 2>/dev/null && wordlist="$tmpd/rockyou.txt"
  fi
  if [[ -z "$wordlist" ]]; then
    info "Trying to download rockyou.txt..."
    local url="https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
    if command -v curl >/dev/null 2>&1 && curl -fsSL --max-time 120 "$url" -o "$tmpd/rockyou.txt" 2>/dev/null && [[ -s "$tmpd/rockyou.txt" ]]; then
      wordlist="$tmpd/rockyou.txt"
    elif command -v wget >/dev/null 2>&1 && wget -q -T 120 "$url" -O "$tmpd/rockyou.txt" 2>/dev/null && [[ -s "$tmpd/rockyou.txt" ]]; then
      wordlist="$tmpd/rockyou.txt"
    fi
  fi
  if [[ -z "$wordlist" ]]; then
    warn "No rockyou wordlist available (offline?). Using built-in common-password list only."
    : > "$tmpd/rockyou.txt"; wordlist="$tmpd/rockyou.txt"
  else
    ok "Using wordlist: $wordlist ($(wc -l < "$wordlist" 2>/dev/null || echo 0) entries)"
  fi

  # ---- determine weak accounts ----
  declare -A WEAK=()        # user -> cracked plaintext
  local JOHN_INSTALLED=0 WL_INSTALLED="${WL_INSTALLED:-0}"
  local john_bin=""
  command -v john >/dev/null 2>&1 && john_bin="john"
  if [[ -z "$john_bin" ]]; then
    info "Attempting to install John the Ripper for hash auditing..."
    if is_debian; then
      if ! pkg_installed john && pkg_available john; then JOHN_INSTALLED=1; pkg_install john || warn "john install failed."; fi
    else
      if ! pkg_installed john && ! pkg_installed john-the-ripper; then
        if pkg_available john; then JOHN_INSTALLED=1; pkg_install john || warn "john install failed."
        elif pkg_available john-the-ripper; then JOHN_INSTALLED=1; pkg_install john-the-ripper || warn "john-the-ripper install failed."
        else warn "John the Ripper package is not available from configured repositories."; fi
      fi
    fi
    command -v john >/dev/null 2>&1 && john_bin="john"
  fi

  if [[ -n "$john_bin" ]]; then
    log "Auditing hashes with John the Ripper (this can take a while)..."
    local combo="$tmpd/combined.txt"
    if command -v unshadow >/dev/null 2>&1; then unshadow /etc/passwd /etc/shadow > "$combo" 2>/dev/null
    else cp /etc/shadow "$combo"; fi
    [[ -s "$wordlist" ]] && run "$john_bin" --wordlist="$wordlist" "$combo"
    run "$john_bin" --single "$combo"           # username-based rules
    # collect cracked user:password pairs
    while IFS=: read -r cu cp _; do
      [[ -n "$cu" && -n "${USERHASH[$cu]:-}" ]] && WEAK["$cu"]="$cp"
    done < <("$john_bin" --show "$combo" 2>/dev/null | grep ':' )
  else
    warn "John unavailable; using built-in crypt-compare fallback."
    if command -v python3 >/dev/null 2>&1; then
      for u in "${!USERHASH[@]}"; do
        local pw; pw="$(crack_one_builtin "$u" "${USERHASH[$u]}" "$wordlist")"
        [[ -n "$pw" ]] && WEAK["$u"]="$pw"
      done
    else
      err "Neither john nor python3 available; cannot audit. Aborting section."
      end_task; return
    fi
  fi

  # ---- report & reset ----
  if [[ ${#WEAK[@]} -eq 0 ]]; then
    ok "No weak passwords detected among ${#USERHASH[@]} account(s)."
  else
    warn "Weak passwords found for: ${!WEAK[*]}"
    prepare_edit /etc/shadow            # whole-file backup (safety net for revert)
    : > "$CREDS_FILE"; chmod 600 "$CREDS_FILE"
    echo "# Generated by harden.sh on $(date)  — KEEP SECRET" >> "$CREDS_FILE"
    for u in "${!WEAK[@]}"; do
      local oldpw="${WEAK[$u]}" oldhash="${USERHASH[$u]}" newpw
      newpw="$(gen_password)"
      # record original hash for precise, granular revert
      record_action "USER_PWHASH" "$u" "$oldhash"
      if printf '%s:%s\n' "$u" "$newpw" | chpasswd; then
        printf '%-20s OLD(weak)=%-20s NEW=%s\n' "$u" "$oldpw" "$newpw" >> "$CREDS_FILE"
        echo "    ${C_GRN}RESET${C_RST} ${C_BLD}$u${C_RST}: old weak password '${oldpw}' -> new strong password: ${C_BLD}${newpw}${C_RST}"
      else
        err "Failed to reset password for $u"
      fi
    done
    ok "Weak passwords reset. Credentials saved to $CREDS_FILE (root-only)."
    info "Distribute the new passwords securely; consider 'chage -d 0 <user>' to force a change at next login."
  fi

  # ---- clean up tools we installed just for the audit (restore original state) ----
  if [[ "$JOHN_INSTALLED" == "1" ]]; then
    info "Removing John the Ripper (installed only for this audit; it's a cracking tool)."
    run pkg_remove_silent john || run pkg_remove_silent john-the-ripper
  fi
  if [[ "$WL_INSTALLED" == "1" ]]; then
    info "Removing 'wordlists' package (installed only for this audit)."
    run pkg_remove_silent wordlists
  fi
  end_task
}

# Remove a package WITHOUT recording it for revert (used to undo our own
# temporary audit-tool installs, so the net change is zero).
pkg_remove_silent() {
  local p="$1"
  case "$PKG_FAMILY" in
    apt) env DEBIAN_FRONTEND=noninteractive apt-get purge -y "$p" >/dev/null 2>&1;;
    dnf) dnf remove -y "$p" >/dev/null 2>&1;;
    yum) yum remove -y "$p" >/dev/null 2>&1;;
    *) return 1;;
  esac
}

# ============================================================================
# SECTION 11 — Account lockout, empty passwords, nullok
# ============================================================================
sec_auth_lockout() {
  start_task "auth_lockout" "Account Lockout / Empty Passwords / nullok"
  require_supported_write "Account Lockout / Empty Passwords / nullok" || { end_task; return; }

  # --- empty password accounts ---
  local empties
  mapfile -t empties < <(awk -F: '($2==""){print $1}' /etc/shadow)
  if [[ ${#empties[@]} -gt 0 ]]; then
    warn "Accounts with EMPTY passwords: ${empties[*]}"
    if confirm "Lock all empty-password accounts (passwd -l)?"; then
      local u
      for u in "${empties[@]}"; do
        record_action "USER_LOCK" "$u"
        run passwd -l "$u" && ok "Locked $u"
      done
    fi
  else
    ok "No empty-password accounts."
  fi

  # --- nullok ---
  local nullfiles
  mapfile -t nullfiles < <(grep -rlw "nullok" /etc/pam.d/ 2>/dev/null)
  if [[ ${#nullfiles[@]} -gt 0 ]]; then
    warn "'nullok' (allows blank passwords) found in: ${nullfiles[*]}"
    if confirm "Remove 'nullok' from these PAM files?"; then
      local f
      for f in "${nullfiles[@]}"; do
        prepare_edit "$f"
        sed -i -E 's/[[:space:]]+nullok(_secure)?//g' "$f"
        ok "Stripped nullok from $f"
      done
    fi
  else
    ok "No 'nullok' directives found."
  fi

  # --- faillock (lockout after failed attempts) ---
  if ask_risky "Enable account lockout after 5 failed logins (pam_faillock). Misconfigured PAM can lock out ALL logins; this run backs up PAM files and revert.sh can restore them"; then
    if is_rhel && command -v authselect >/dev/null 2>&1; then
      prepare_edit /etc/security/faillock.conf
      set_conf_kv /etc/security/faillock.conf deny        5   " = "
      set_conf_kv /etc/security/faillock.conf unlock_time 900 " = "
      set_conf_kv /etc/security/faillock.conf fail_interval 900 " = "
      record_action "AUTHSELECT_FEATURE" "with-faillock"
      run authselect enable-feature with-faillock
      run authselect apply-changes
      ok "faillock enabled via authselect"
    elif is_debian; then
      local af="/etc/pam.d/common-auth" ac="/etc/pam.d/common-account"
      prepare_edit "$af"; prepare_edit "$ac"
      if ! grep -q "pam_faillock.so preauth" "$af"; then
        sed -i '1i auth    required    pam_faillock.so preauth silent deny=5 unlock_time=900 fail_interval=900' "$af"
      fi
      if ! grep -q "pam_faillock.so authfail" "$af"; then
        # place authfail/authsucc after the primary pam_unix line
        sed -i '/pam_unix.so/a auth    [default=die]   pam_faillock.so authfail deny=5 unlock_time=900 fail_interval=900\nauth    sufficient      pam_faillock.so authsucc' "$af"
      fi
      grep -q "pam_faillock.so" "$ac" || echo "account required pam_faillock.so" >> "$ac"
      ok "faillock configured in common-auth/common-account"
    else
      warn "No supported method to configure faillock on this system; skipped."
    fi
  fi

  # --- RISKY: lock the root account for interactive login ---
  # Admins should use named accounts + sudo. Locking root's password disables
  # direct root password login. revert.sh restores it via the USER_LOCK record
  # (passwd -u). Console/single-user root via sulogin may also be affected, so
  # ensure at least one sudo-capable account works before logging out.
  local root_state; root_state="$(passwd -S root 2>/dev/null | awk '{print $2}')"
  if [[ "$root_state" == "L" ]]; then
    ok "root account password is already locked."
  elif ask_risky "Lock the root account password (passwd -l root). Ensure a sudo-capable user works first; revert.sh can unlock it"; then
    record_action "USER_LOCK" "root"
    if run passwd -l root; then
      ok "root password locked (use 'sudo' for admin tasks)"
    else
      err "Failed to lock root"
    fi
  fi
  end_task
}

# ============================================================================
# SECTION 12 — SSH hardening
# ============================================================================
ssh_service_name() { is_debian && echo ssh || echo sshd; }

restart_sshd_safe() {
  if run sshd -t; then
    run systemctl restart "$(ssh_service_name)"
    ok "sshd configuration valid; service restarted."
  else
    err "sshd -t reported a configuration error! Restoring backup and NOT restarting."
    # restore from this run's backup
    local bak="$BACKUP_DIR/files$SSHD_CONFIG"
    [[ -f "$bak" ]] && cp -a "$bak" "$SSHD_CONFIG"
    return 1
  fi
}

sec_ssh() {
  start_task "ssh" "SSH Hardening"
  require_supported_write "SSH Hardening" || { end_task; return; }
  require_systemd_task "SSH Hardening" || { end_task; return; }
  if [[ ! -f "$SSHD_CONFIG" ]]; then warn "$SSHD_CONFIG not found; is OpenSSH installed?"; end_task; return; fi
  prepare_edit "$SSHD_CONFIG"

  # --- safe, non-disruptive directives ---
  log "Applying baseline SSH hardening"
  set_ssh PermitRootLogin no
  set_ssh X11Forwarding no
  set_ssh AllowTcpForwarding no
  set_ssh AllowAgentForwarding no
  set_ssh IgnoreRhosts yes
  set_ssh HostbasedAuthentication no
  set_ssh PermitEmptyPasswords no
  set_ssh MaxAuthTries 3
  set_ssh LoginGraceTime 30
  set_ssh ClientAliveInterval 300
  set_ssh ClientAliveCountMax 2
  set_ssh LogLevel VERBOSE
  ok "Baseline directives set"

  # NOTE: 'Protocol 2' is intentionally NOT written — it is removed/deprecated
  # on OpenSSH >= 7.6 and would make 'sshd -t' fail. Protocol 1 no longer exists.

  # --- key presence check (informs the password-auth decision) ---
  local have_keys=0
  if grep -rqs . /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null; then
    have_keys=1
    info "Existing authorized_keys detected."
  else
    warn "No SSH authorized_keys found on the system."
  fi

  # --- RISKY: disable password authentication ---
  if [[ $have_keys -eq 1 ]]; then
    if ask_risky "Disable SSH password authentication (PasswordAuthentication no). Keys WERE detected, but verify YOUR account has a working key first"; then
      set_ssh PasswordAuthentication no
      set_ssh KbdInteractiveAuthentication no
    fi
  else
    warn "Skipping 'PasswordAuthentication no' automatically — no keys exist (would lock everyone out)."
  fi

  # --- RISKY: change SSH port to 2222 ---
  if ask_risky "Change SSH port from 22 to 2222 (firewall + any external configs must match; may lose points if scoring expects 22)"; then
    set_ssh Port 2222
    record_action "NOTE" "ssh_port_changed_to_2222"
    SSH_PORT_CHANGED=2222
  fi

  # --- RISKY: restrict to an admin group ---
  if ask_risky "Restrict SSH logins to members of group 'sshusers' (AllowGroups sshusers). Users not added to this group lose SSH access"; then
    if ! getent group sshusers >/dev/null; then
      record_action "GROUP_CREATE" "sshusers"
      run groupadd sshusers
    fi
    # add authorized sudoers (best-effort) so they keep access
    if [[ -r "$AUTH_FILE" ]]; then
      parse_authorized
      local u
      for u in "${AUTH_SUDO[@]}"; do
        getent passwd "$u" >/dev/null || continue
        if ! id -nG "$u" | tr ' ' '\n' | grep -qx sshusers; then
          record_action "GROUP_MEMBER_ADD" "$u" "sshusers"
          run usermod -aG sshusers "$u"
        fi
      done
    fi
    set_ssh AllowGroups sshusers
    warn "Ensure your account is in 'sshusers' before logging out."
  fi

  restart_sshd_safe
  end_task
}

# ============================================================================
# SECTION 13 — Firewall (UFW on Debian, firewalld on RHEL)
# ============================================================================
SSH_PORT_CHANGED=""
sec_firewall() {
  start_task "firewall" "Firewall (managed)"
  require_supported_write "Firewall" || { end_task; return; }
  require_systemd_task "Firewall" || { end_task; return; }
  local sshport=22
  [[ -n "$SSH_PORT_CHANGED" ]] && sshport="$SSH_PORT_CHANGED"

  if is_debian; then
    pkg_install_tracked ufw
    # back up rule state so revert can restore it
    prepare_edit /etc/ufw/user.rules
    prepare_edit /etc/ufw/user6.rules
    prepare_edit /etc/default/ufw
    local was_active; was_active=$(ufw status 2>/dev/null | head -1)
    record_action "UFW_STATE" "$was_active"

    log "Setting default deny incoming / allow outgoing"
    run ufw default deny incoming
    run ufw default allow outgoing
    log "Allowing SSH on port $sshport BEFORE enabling (prevents lockout)"
    run ufw allow "${sshport}/tcp"
    [[ "$sshport" != "22" ]] && run ufw deny 22/tcp

    # Web VM preset: open only the standard web ports in addition to SSH.
    if confirm "This is a web VM — allow HTTP(80)/HTTPS(443) through the firewall?"; then
      run ufw allow 80/tcp
      run ufw allow 443/tcp
      ok "Web ports 80/443 allowed"
    fi
    if confirm "This VM provides scored DNS — allow DNS(53/tcp+udp) through the firewall?"; then
      run ufw allow 53/tcp
      run ufw allow 53/udp
      ok "DNS port 53/tcp+udp allowed"
    fi

    if ask_risky "ENABLE the firewall now (ufw enable). SSH (${sshport}/tcp) has been allowed above"; then
      run ufw --force enable
      run ufw logging on
      ok "UFW enabled"
    else
      warn "UFW rules staged but firewall left disabled."
    fi
    run ufw status verbose

  elif is_rhel; then
    pkg_install_tracked firewalld
    # back up zone configs
    [[ -d /etc/firewalld ]] && { mkdir -p "$BACKUP_DIR/files/etc"; cp -a /etc/firewalld "$BACKUP_DIR/files/etc/" 2>/dev/null; record_action "FIREWALLD_BACKUP" "/etc/firewalld" "$BACKUP_DIR/files/etc/firewalld"; }
    record_service firewalld
    run systemctl enable --now firewalld
    log "Allowing SSH, removing telnet/ftp services"
    run firewall-cmd --permanent --add-service=ssh
    [[ "$sshport" != "22" ]] && run firewall-cmd --permanent --add-port="${sshport}/tcp"
    run firewall-cmd --permanent --remove-service=telnet
    run firewall-cmd --permanent --remove-service=ftp 2>/dev/null
    if confirm "This is a web VM — allow HTTP/HTTPS through firewalld?"; then
      run firewall-cmd --permanent --add-service=http
      run firewall-cmd --permanent --add-service=https
      ok "Web services http/https allowed"
    fi
    if confirm "This VM provides scored DNS — allow DNS through firewalld?"; then
      run firewall-cmd --permanent --add-service=dns
      ok "DNS service allowed"
    fi
    run firewall-cmd --reload
    run firewall-cmd --list-all
    ok "firewalld configured"
  fi
  end_task
}

# ============================================================================
# SECTION 14 — Kernel / sysctl hardening
# ============================================================================
sec_kernel() {
  start_task "kernel" "Kernel / sysctl Hardening"
  require_supported_write "Kernel / sysctl Hardening" || { end_task; return; }
  local f="/etc/sysctl.d/99-hardening.conf"
  prepare_edit "$f"
  log "Writing $f"
  cat > "$f" <<'EOF'
# Managed by harden.sh
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.randomize_va_space = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_timestamps = 1
net.ipv4.ip_local_port_range = 2000 65000
kernel.pid_max = 65536
# IPv6 router-advertisement / autoconf hardening (safe even when IPv6 stays on)
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
EOF
  ok "Baseline sysctl settings written"

  # RISKY (checklist value, but a downgrade on a busy web VM): fs.file-max=65535
  # caps the system-wide open-file limit far below modern defaults (often
  # millions). Offered because the checklist lists it, with a clear warning.
  if ask_risky "Set fs.file-max=65535 (checklist value). WARNING: this LOWERS the system-wide open-file limit and can throttle a busy web server"; then
    echo "fs.file-max = 65535" >> "$f"
  fi
  # RISKY (checklist TCP buffer/window tuning — performance, not hardening).
  if ask_risky "Apply checklist TCP buffer/window tuning (net.core.*mem, tcp_rmem/tcp_wmem, netdev_max_backlog, window_scaling). These are performance knobs, not security"; then
    {
      echo "net.core.rmem_max = 8388608"
      echo "net.core.wmem_max = 8388608"
      echo "net.core.netdev_max_backlog = 5000"
      echo "net.ipv4.tcp_rmem = 10240 87380 12582912"
      echo "net.ipv4.tcp_wmem = 10240 87380 12582912"
      echo "net.ipv4.tcp_window_scaling = 1"
    } >> "$f"
  fi

  # RISKY: ignore all ICMP echo (breaks ping / scoring)
  if ask_risky "Block ALL incoming ping (net.ipv4.icmp_echo_ignore_all=1). The checklist warns this can break monitoring/scoring"; then
    echo "net.ipv4.icmp_echo_ignore_all = 1" >> "$f"
  fi
  # RISKY: disable IPv6 entirely
  if ask_risky "Disable IPv6 entirely. Only do this if IPv6 is confirmed unused"; then
    {
      echo "net.ipv6.conf.all.disable_ipv6 = 1"
      echo "net.ipv6.conf.default.disable_ipv6 = 1"
      echo "net.ipv6.conf.lo.disable_ipv6 = 1"
    } >> "$f"
  fi

  # RISKY/LEGACY: /etc/host.conf "nospoof on". The checklist lists it, but modern
  # glibc (NSS) ignores host.conf's nospoof/order directives, so this is largely
  # a no-op on current systems. Offered for checklist completeness only.
  if ask_risky "Add 'nospoof on' to /etc/host.conf (checklist item). NOTE: ignored by modern glibc/NSS — effectively a no-op"; then
    prepare_edit /etc/host.conf
    grep -qiE '^[[:space:]]*nospoof' /etc/host.conf 2>/dev/null \
      || echo "nospoof on" >> /etc/host.conf
    ok "nospoof on written to /etc/host.conf"
  fi

  run sysctl --system
  ok "sysctl settings applied"
  end_task
}

# ============================================================================
# Service config validation / hardening helpers
# ============================================================================
vsftpd_config_path() {
  local f
  for f in /etc/vsftpd/vsftpd.conf /etc/vsftpd.conf; do
    [[ -f "$f" ]] && { echo "$f"; return 0; }
  done
  is_rhel && echo /etc/vsftpd/vsftpd.conf || echo /etc/vsftpd.conf
}

validate_vsftpd_config() {
  local f="$1" out="$BACKUP_DIR/vsftpd-configtest.log" rc
  if grep -qiE '^[[:space:]]*banner-message-enable[[:space:]]*=' "$f" 2>/dev/null; then
    err "Invalid vsftpd directive found: banner-message-enable. Use ftpd_banner instead."
    return 1
  fi

  # vsftpd has no simple configtest flag. When available, run it with listening
  # disabled and treat a timeout as "not rejected"; immediate nonzero exit means
  # it rejected the config.
  if command -v vsftpd >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
    timeout 3 vsftpd -olisten=NO -olisten_ipv6=NO "$f" >"$out" 2>&1
    rc=$?
    if [[ $rc -eq 0 || $rc -eq 124 ]]; then
      ok "vsftpd config sanity check passed"
      return 0
    fi
    err "vsftpd rejected the staged configuration:"
    sed 's/^/      /' "$out" 2>/dev/null || true
    return 1
  fi

  warn "vsftpd binary/timeout unavailable; performed static validation only."
  return 0
}

restore_task_backup() {
  local f="$1"
  local bak="$BACKUP_DIR/files$f"
  if [[ -f "$bak" ]]; then
    cp -a "$bak" "$f"
  elif [[ -n "${CREATED[$f]:-}" && -e "$f" ]]; then
    rm -f "$f"
  fi
}

restart_service_if_present() {
  local svc="$1"
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not available; restart $svc manually if needed."
    return 0
  fi
  systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" || {
    info "$svc.service not found; config updated but service was not restarted."
    return 0
  }
  record_service "$svc"
  run systemctl restart "$svc"
}

restart_service_untracked_if_present() {
  local svc="$1"
  command -v systemctl >/dev/null 2>&1 || return 0
  systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" || return 0
  run systemctl restart "$svc"
}

secure_vsftpd_config() {
  if ! pkg_installed vsftpd && ! command -v vsftpd >/dev/null 2>&1 && [[ ! -f /etc/vsftpd/vsftpd.conf && ! -f /etc/vsftpd.conf ]]; then
    ok "vsftpd not detected; FTP hardening skipped."
    return 0
  fi

  local c
  c="$(vsftpd_config_path)"
  log "Hardening vsftpd config: $c"
  prepare_edit "$c"
  set_conf_kv "$c" anonymous_enable NO "="
  set_conf_kv "$c" local_enable YES "="
  set_conf_kv "$c" write_enable YES "="
  set_conf_kv "$c" chroot_local_user YES "="
  set_conf_kv "$c" allow_writeable_chroot YES "="
  set_conf_kv "$c" ftpd_banner "Authorized access only." "="
  set_conf_kv "$c" xferlog_enable YES "="
  set_conf_kv "$c" log_ftp_protocol YES "="

  if validate_vsftpd_config "$c"; then
    restart_service_if_present vsftpd || { err "vsftpd restart failed; restoring previous config."; restore_task_backup "$c"; restart_service_untracked_if_present vsftpd; return 1; }
    ok "vsftpd hardened"
  else
    restore_task_backup "$c"
    warn "Restored previous vsftpd config; FTP hardening skipped."
  fi
}

apache_config_path() {
  local f
  for f in /etc/apache2/apache2.conf /etc/httpd/conf/httpd.conf; do
    [[ -f "$f" ]] && { echo "$f"; return 0; }
  done
  is_debian && echo /etc/apache2/apache2.conf || echo /etc/httpd/conf/httpd.conf
}

apache_service_name() {
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^apache2\.service'; then
    echo apache2
  else
    echo httpd
  fi
}

validate_apache_config() {
  if command -v apache2ctl >/dev/null 2>&1; then run apache2ctl configtest
  elif command -v apachectl >/dev/null 2>&1; then run apachectl configtest
  elif command -v httpd >/dev/null 2>&1; then run httpd -t
  else warn "No Apache configtest command found; static directive update only."; return 0
  fi
}

secure_apache_config() {
  if ! pkg_installed apache2 && ! pkg_installed httpd && ! pkg_installed apache && \
     ! command -v apache2ctl >/dev/null 2>&1 && ! command -v httpd >/dev/null 2>&1 && \
     [[ ! -f /etc/apache2/apache2.conf && ! -f /etc/httpd/conf/httpd.conf ]]; then
    ok "Apache/httpd not detected; Apache hardening skipped."
    return 0
  fi

  local c svc
  c="$(apache_config_path)"
  log "Hardening Apache config: $c"
  prepare_edit "$c"
  set_conf_kv "$c" ServerSignature Off " "
  set_conf_kv "$c" ServerTokens Prod " "

  if validate_apache_config; then
    svc="$(apache_service_name)"
    restart_service_if_present "$svc" || { err "$svc restart failed; restoring previous config."; restore_task_backup "$c"; validate_apache_config; restart_service_untracked_if_present "$svc"; return 1; }
    ok "Apache server banner hardening applied"
  else
    restore_task_backup "$c"
    warn "Restored previous Apache config; Apache hardening skipped."
  fi
}

# --- Nginx: hide version banner (server_tokens off) ---
secure_nginx_config() {
  local c=/etc/nginx/nginx.conf
  if ! pkg_installed nginx && ! command -v nginx >/dev/null 2>&1 && [[ ! -f "$c" ]]; then
    ok "Nginx not detected; Nginx hardening skipped."
    return 0
  fi
  [[ -f "$c" ]] || { warn "$c not found; Nginx hardening skipped."; return 0; }
  log "Hardening Nginx config: $c"
  prepare_edit "$c"
  if grep -qE '^[[:space:]]*#?[[:space:]]*server_tokens' "$c"; then
    sed -i -E 's@^[[:space:]]*#?[[:space:]]*server_tokens.*@    server_tokens off;@' "$c"
  else
    # insert just inside the http { } block
    sed -i -E '0,/^[[:space:]]*http[[:space:]]*\{/s//&\n    server_tokens off;/' "$c"
  fi
  if command -v nginx >/dev/null 2>&1 && run nginx -t; then
    restart_service_if_present nginx || { err "nginx restart failed; restoring."; restore_task_backup "$c"; restart_service_untracked_if_present nginx; return 1; }
    ok "Nginx server_tokens off applied"
  else
    err "nginx -t rejected the config; restoring previous."
    restore_task_backup "$c"
  fi
}

# --- PHP: hide version (expose_php = Off) and silence display_errors ---
secure_php_config() {
  local inis=() f
  while IFS= read -r f; do inis+=("$f"); done < <( \
    { ls /etc/php/*/*/php.ini /etc/php.ini /etc/php/php.ini 2>/dev/null; } | sort -u)
  if [[ ${#inis[@]} -eq 0 ]]; then
    ok "No php.ini found; PHP hardening skipped."
    return 0
  fi
  for f in "${inis[@]}"; do
    [[ -f "$f" ]] || continue
    log "Hardening PHP ini: $f"
    prepare_edit "$f"
    set_conf_kv "$f" expose_php Off " = "
    set_conf_kv "$f" display_errors Off " = "
    ok "expose_php=Off, display_errors=Off in $f"
  done
  # Reload whatever serves PHP (fpm variants and/or apache).
  local svc
  for svc in php-fpm php7.4-fpm php8.1-fpm php8.2-fpm php8.3-fpm; do
    restart_service_untracked_if_present "$svc"
  done
}

# --- Database: do NOT purge; surface securing recommendations. ---
secure_database_advice() {
  local found=()
  pkg_installed mysql-server   && found+=("mysql")
  pkg_installed mariadb-server && found+=("mariadb")
  pkg_installed postgresql     && found+=("postgresql")
  pkg_installed postgresql-server && found+=("postgresql")
  command -v mysql   >/dev/null 2>&1 && [[ ${#found[@]} -eq 0 ]] && found+=("mysql/mariadb")
  command -v psql    >/dev/null 2>&1 && found+=("postgresql")
  if [[ ${#found[@]} -eq 0 ]]; then
    ok "No database server detected."
    return 0
  fi
  warn "Database server(s) present: ${found[*]} — these are usually scored; NOT removing."
  info "Recommended manual hardening (interactive, not automated here):"
  info "  • MySQL/MariaDB: run 'mysql_secure_installation' (set root pw, drop anon users/test DB)."
  info "  • Bind to localhost if remote DB access is not required:"
  info "      MySQL/MariaDB: bind-address = 127.0.0.1  (in /etc/mysql/**/*.cnf)"
  info "      PostgreSQL:    listen_addresses = 'localhost'  (in postgresql.conf)"
  info "  • If remote access IS required, restrict the DB port by source IP in the firewall."
}

bind_options_files() {
  local f
  for f in /etc/bind/named.conf.options /etc/named.conf /etc/named/named.conf; do
    [[ -f "$f" ]] && echo "$f"
  done
}

set_bind_option() {
  local file="$1" directive="$2" value="$3"
  if grep -qE "^[[:space:]]*${directive}[[:space:]]+" "$file" 2>/dev/null; then
    sed -i -E "s#^[[:space:]]*${directive}[[:space:]]+.*#        ${directive} ${value};#" "$file"
  elif grep -qE '^[[:space:]]*options[[:space:]]*\{' "$file" 2>/dev/null; then
    sed -i -E "0,/^[[:space:]]*options[[:space:]]*\{/s//&\\
        ${directive} ${value};/" "$file"
  else
    return 1
  fi
}

validate_bind_config() {
  if command -v named-checkconf >/dev/null 2>&1; then
    run named-checkconf
  else
    warn "named-checkconf not available; performed static BIND edits only."
    return 0
  fi
}

restart_bind_if_present() {
  restart_service_if_present bind9
  restart_service_if_present named
}

secure_dns_config() {
  local files=() f changed=0
  mapfile -t files < <(bind_options_files)
  if [[ ${#files[@]} -eq 0 ]]; then
    ok "No BIND options config found; DNS config hardening skipped."
    return 0
  fi

  log "BIND config files considered:"
  printf '      - %s\n' "${files[@]}"
  log "Current recursion/transfer directives:"
  grep -RInE '^[[:space:]]*(recursion|allow-recursion|allow-query-cache|allow-transfer)[[:space:]]' "${files[@]}" 2>/dev/null || true

  if confirm "Limit BIND recursion/cache queries to localhost/localnets? Outcome: reduces open resolver abuse. Risk: clients outside localnets may lose DNS recursion"; then
    for f in "${files[@]}"; do
      prepare_edit "$f"
      set_bind_option "$f" recursion "yes" || warn "Could not set recursion in $f"
      set_bind_option "$f" allow-recursion "{ localhost; localnets; }" || warn "Could not set allow-recursion in $f"
      set_bind_option "$f" allow-query-cache "{ localhost; localnets; }" || warn "Could not set allow-query-cache in $f"
    done
    changed=1
  else
    info "BIND recursion/cache ACL hardening skipped."
  fi

  if confirm "Block BIND zone transfers by default (allow-transfer { none; })? Outcome: prevents public AXFR leakage. Risk: legitimate secondary DNS servers stop syncing unless explicitly allowed elsewhere"; then
    for f in "${files[@]}"; do
      prepare_edit "$f"
      set_bind_option "$f" allow-transfer "{ none; }" || warn "Could not set allow-transfer in $f"
    done
    changed=1
  else
    info "BIND zone-transfer hardening skipped."
  fi

  if [[ $changed -eq 1 ]]; then
    if validate_bind_config; then
      restart_bind_if_present
      ok "BIND DNS hardening applied."
    else
      err "BIND validation failed; restoring edited files."
      for f in "${files[@]}"; do restore_task_backup "$f"; done
      validate_bind_config || true
      restart_bind_if_present
    fi
  fi
}

secure_apache_extra_config() {
  if ! pkg_installed apache2 && ! pkg_installed httpd && ! command -v apache2ctl >/dev/null 2>&1 && ! command -v httpd >/dev/null 2>&1; then
    ok "Apache/httpd not detected; extra Apache hardening skipped."
    return 0
  fi
  local disable_indexes=0 headers=0 c svc
  if confirm "Disable Apache directory listings (Options -Indexes)? Outcome: prevents directory browsing. Risk: breaks sites that intentionally expose directory indexes"; then
    disable_indexes=1
  fi
  if confirm "Add Apache security headers (nosniff, frame policy, referrer policy)? Outcome: reduces browser-side abuse. Risk: may break embedded pages or unusual cross-origin workflows"; then
    headers=1
  fi
  [[ $disable_indexes -eq 0 && $headers -eq 0 ]] && { info "Extra Apache hardening skipped."; return 0; }

  if is_debian; then c=/etc/apache2/conf-enabled/99-harden-security.conf
  else c=/etc/httpd/conf.d/99-harden-security.conf; fi
  prepare_edit "$c"
  {
    echo "# Managed by harden.sh"
    if [[ $disable_indexes -eq 1 ]]; then
      echo '<Directory /var/www/>'
      echo '    Options -Indexes'
      echo '</Directory>'
    fi
    if [[ $headers -eq 1 ]]; then
      echo 'Header always set X-Content-Type-Options "nosniff"'
      echo 'Header always set X-Frame-Options "SAMEORIGIN"'
      echo 'Header always set Referrer-Policy "strict-origin-when-cross-origin"'
    fi
  } > "$c"

  if [[ $headers -eq 1 ]] && is_debian && command -v a2enmod >/dev/null 2>&1; then
    run a2enmod headers
    record_action "NOTE" "apache_headers_module_enabled"
  fi

  if validate_apache_config; then
    svc="$(apache_service_name)"
    restart_service_if_present "$svc" || { err "$svc restart failed; restoring extra Apache config."; restore_task_backup "$c"; restart_service_untracked_if_present "$svc"; return 1; }
    ok "Extra Apache hardening applied ($c)"
  else
    err "Apache validation failed; restoring extra config."
    restore_task_backup "$c"
    validate_apache_config || true
  fi
}

secure_nginx_extra_config() {
  local c=/etc/nginx/conf.d/99-harden-security.conf
  if ! pkg_installed nginx && ! command -v nginx >/dev/null 2>&1 && [[ ! -d /etc/nginx ]]; then
    ok "Nginx not detected; extra Nginx hardening skipped."
    return 0
  fi
  local disable_indexes=0 headers=0
  if confirm "Disable Nginx directory listings (autoindex off)? Outcome: prevents directory browsing. Risk: breaks sites that intentionally expose indexes"; then
    disable_indexes=1
  fi
  if confirm "Add Nginx security headers (nosniff, frame policy, referrer policy)? Outcome: reduces browser-side abuse. Risk: may break embedded pages or unusual cross-origin workflows"; then
    headers=1
  fi
  [[ $disable_indexes -eq 0 && $headers -eq 0 ]] && { info "Extra Nginx hardening skipped."; return 0; }

  prepare_edit "$c"
  {
    echo "# Managed by harden.sh; expected to be included inside nginx's http context"
    [[ $disable_indexes -eq 1 ]] && echo "autoindex off;"
    if [[ $headers -eq 1 ]]; then
      echo 'add_header X-Content-Type-Options "nosniff" always;'
      echo 'add_header X-Frame-Options "SAMEORIGIN" always;'
      echo 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
    fi
  } > "$c"

  if command -v nginx >/dev/null 2>&1 && run nginx -t; then
    restart_service_if_present nginx || { err "nginx restart failed; restoring extra config."; restore_task_backup "$c"; restart_service_untracked_if_present nginx; return 1; }
    ok "Extra Nginx hardening applied ($c)"
  else
    err "nginx validation failed; restoring extra config."
    restore_task_backup "$c"
    command -v nginx >/dev/null 2>&1 && run nginx -t || true
  fi
}

secure_php_advanced_config() {
  local inis=() f disable_funcs=0 allow_include=0 session_base=0 secure_cookie=0
  while IFS= read -r f; do inis+=("$f"); done < <(
    { ls /etc/php/*/*/php.ini /etc/php.ini /etc/php/php.ini 2>/dev/null; } | sort -u)
  if [[ ${#inis[@]} -eq 0 ]]; then
    ok "No php.ini found; advanced PHP hardening skipped."
    return 0
  fi

  if confirm "Disable dangerous PHP execution functions? Outcome: limits webshell impact. Risk: can break apps/admin panels that legitimately call exec/system/proc APIs"; then
    disable_funcs=1
  fi
  if confirm "Set allow_url_include=Off? Outcome: blocks remote include attacks. Risk: apps using URL includes will fail"; then
    allow_include=1
  fi
  if confirm "Set PHP session.use_strict_mode=1 and session.cookie_httponly=1? Outcome: stronger session handling. Risk: low, but unusual session code may behave differently"; then
    session_base=1
  fi
  if confirm "Set PHP session.cookie_secure=1? Outcome: cookies sent only over HTTPS. Risk: HTTP-only apps lose session cookies"; then
    secure_cookie=1
  fi
  [[ $disable_funcs -eq 0 && $allow_include -eq 0 && $session_base -eq 0 && $secure_cookie -eq 0 ]] && { info "Advanced PHP hardening skipped."; return 0; }

  for f in "${inis[@]}"; do
    [[ -f "$f" ]] || continue
    log "Applying advanced PHP settings to $f"
    prepare_edit "$f"
    [[ $disable_funcs -eq 1 ]] && set_conf_kv "$f" disable_functions "exec,passthru,shell_exec,system,proc_open,popen" " = "
    [[ $allow_include -eq 1 ]] && set_conf_kv "$f" allow_url_include Off " = "
    if [[ $session_base -eq 1 ]]; then
      set_conf_kv "$f" session.use_strict_mode 1 " = "
      set_conf_kv "$f" session.cookie_httponly 1 " = "
      set_conf_kv "$f" session.cookie_samesite Lax " = "
    fi
    [[ $secure_cookie -eq 1 ]] && set_conf_kv "$f" session.cookie_secure 1 " = "
  done

  local svc
  for svc in php-fpm php7.4-fpm php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm; do
    restart_service_untracked_if_present "$svc"
  done
  restart_service_untracked_if_present "$(apache_service_name)"
  ok "Advanced PHP hardening applied."
}

# ============================================================================
# SECTION 15 — Unwanted services & packages
# ============================================================================
sec_services() {
  start_task "services" "Unwanted Services & Packages"
  require_supported_write "Unwanted Services & Packages" || { end_task; return; }
  require_systemd_task "Unwanted Services & Packages" || { end_task; return; }

  # MEGA-BAD: offensive/cracking/exploitation tools and dual-use attack suites.
  local mega_bad_tokens=(aircrack-ng beef beef-xss ettercap ettercap-common ettercap-graphical \
    hashcat hydra john kismet medusa metasploit metasploit-framework msfvenom nikto nmap \
    ophcrack proxychains proxychains4 reaver set setoolkit sqlmap truecrack zenmap)
  # BAD: insecure remote-access daemons, reverse-shell helpers, sniffers, and P2P/games.
  local bad_tokens=(cryptcat netcat netcat-openbsd netcat-traditional ncat socat tcpdump \
    nc rlogind rshd rcmd rexecd rbootd rquotad rstatd rusersd rwalld rexd \
    telnet telnetd telnetd-ssl inetutils-telnetd inetutils-inetd \
    rsh-server rsh rsh-client rsh-redone-server rsh-redone-client rlinetd \
    tightvncserver x11vnc tigervnc-server \
    vsftpd proftpd-basic proftpd pure-ftpd ftp tnftp sftpd tftpd-hpa tftp-server tftpd atftpd \
    nfs-common nfs-kernel-server nfs-utils nis ypbind ypserv \
    snmpd net-snmp talkd ntalk talk pop3 \
    dovecot-pop3d courier-pop \
    wireshark wireshark-common wireshark-qt tor torbrowser-launcher vuze frostwire freeciv \
    minetest minetest-server finger fingerd)
  # POSSIBLY-BAD: legitimate services that may be required by the readme.
  local maybe_tokens=(samba postgresql postgresql-server apache apache2 httpd nginx lighttpd \
    mysql-server mariadb-server php php-fpm libapache2-mod-php bind9 named \
    dovecot-core dovecot-imapd sendmail postfix exim4 snmp)

  local installed_mega=() installed_bad=() installed_maybe=() t
  for t in "${mega_bad_tokens[@]}"; do pkg_installed "$t" && installed_mega+=("$t"); done
  for t in "${bad_tokens[@]}";      do pkg_installed "$t" && installed_bad+=("$t");   done
  for t in "${maybe_tokens[@]}";    do pkg_installed "$t" && installed_maybe+=("$t"); done

  log "Scanning for MEGA-BAD offensive / cracking packages"
  prompt_selection "MEGA-BAD packages (offensive tools) to PURGE" "${installed_mega[@]}"
  for t in "${SELECTED[@]}"; do pkg_remove "$t" && ok "Purged $t"; done

  log "Scanning for BAD insecure / unwanted packages"
  prompt_selection "BAD packages (attack tools / insecure daemons) to PURGE" "${installed_bad[@]}"
  for t in "${SELECTED[@]}"; do pkg_remove "$t" && ok "Purged $t"; done

  # --- Scored-service protection: shield critical services from accidental purge. ---
  # In the eCitadel orientation, SSH/HTTP/DNS are scored, and web functionality
  # may depend on PHP and a database. Offer to protect these from removal here;
  # they should be SECURED instead (see Service Config section).
  local web_stack=(apache apache2 httpd nginx lighttpd php php-fpm libapache2-mod-php \
    mysql-server mariadb-server postgresql postgresql-server bind9 named unbound dnsmasq)
  if [[ ${#installed_maybe[@]} -gt 0 ]] && \
     confirm "Protect scored service stack (web server / PHP / database / DNS) from removal in this section?"; then
    local kept=() protected=() m w kept_one
    for m in "${installed_maybe[@]}"; do
      kept_one=0
      for w in "${web_stack[@]}"; do [[ "$m" == "$w" ]] && { kept_one=1; break; }; done
      if [[ $kept_one -eq 1 ]]; then protected+=("$m"); else kept+=("$m"); fi
    done
    if [[ ${#protected[@]} -gt 0 ]]; then
      ok "Protected from purge (secure these via the Service Config section): ${protected[*]}"
    fi
    installed_maybe=("${kept[@]}")
  fi

  log "Scanning for POSSIBLY-unwanted server packages (may be required by your readme)"
  prompt_selection "POSSIBLY-unwanted packages to PURGE" "${installed_maybe[@]}"
  for t in "${SELECTED[@]}"; do pkg_remove "$t" && ok "Purged $t"; done

  # Optional daemons to disable (not remove): cups, avahi, rpcbind, bluetooth, nfs
  local svc_candidates=(cups avahi-daemon rpcbind bluetooth nfs-server nfs-kernel-server)
  local running_svcs=() s
  for s in "${svc_candidates[@]}"; do
    systemctl list-unit-files 2>/dev/null | grep -q "^${s}\.service" || continue
    [[ "$(systemctl is-active "$s" 2>/dev/null)" == "active" || "$(systemctl is-enabled "$s" 2>/dev/null)" == "enabled" ]] && running_svcs+=("$s")
  done
  log "Scanning for commonly-unnecessary running services"
  prompt_selection "running services to DISABLE+STOP" "${running_svcs[@]}"
  for s in "${SELECTED[@]}"; do
    record_service "$s"
    run systemctl disable --now "$s" && ok "Disabled $s"
  done

  # --- Full running-service review (beyond the known candidate list) ---
  # Every running service is attack surface. Offer the complete list so the user
  # can disable anything unexpected, not just the hard-coded candidates above.
  if confirm "Review the FULL list of running services and disable selected ones?"; then
    log "All running services:"
    run systemctl list-units --type=service --state=running --no-legend --no-pager
    # Build a clean name list, skipping ones we already handled.
    local all_running=() name
    while IFS= read -r name; do
      [[ -z "$name" ]] && continue
      # never offer core plumbing that would brick the box.
      # NOTE: 'systemd-*' already covers systemd-journald/logind/udevd etc.
      case "$name" in
        systemd-*|dbus*|*getty*|polkit*|ssh|sshd|networkd*|NetworkManager*|\
        cron|crond|rsyslog*|auditd|wpa_supplicant*|\
        apache2|httpd|nginx|lighttpd|php-fpm|php*-fpm|\
        mysql|mysqld|mariadb|postgresql|postgres|\
        named|bind9|unbound|dnsmasq) continue;;
      esac
      in_list "$name" "${running_svcs[@]}" && continue
      all_running+=("$name")
    done < <(systemctl list-units --type=service --state=running --no-legend --no-pager \
              2>/dev/null | awk '{print $1}' | sed 's/\.service$//')
    prompt_selection "additional running services to DISABLE+STOP" "${all_running[@]}"
    for s in "${SELECTED[@]}"; do
      record_service "$s"
      if run systemctl disable --now "$s"; then
        ok "Disabled $s"
      else
        warn "Could not disable $s"
      fi
    done
  fi

  log "Listening sockets after changes:"
  run ss -tulpen
  end_task
}

# ============================================================================
# SECTION 16 — Critical service config hardening
# ============================================================================
sec_service_configs() {
  start_task "service_configs" "Service Config Hardening (FTP / Apache / Nginx / PHP / DB)"
  require_supported_write "Service Config Hardening" || { end_task; return; }
  warn "Only harden service configs here if the service is authorized and should remain installed; every optional hardening item validates before restart when tooling exists."
  if confirm "Apply vsftpd FTP hardening if vsftpd is present?"; then
    secure_vsftpd_config
  else
    info "FTP config hardening skipped by user."
  fi
  if confirm "Apply Apache banner hardening if Apache/httpd is present?"; then
    secure_apache_config
  else
    info "Apache config hardening skipped by user."
  fi
  if confirm "Apply extra Apache hardening prompts (directory listing and browser headers)? Outcome/risk shown per option"; then
    secure_apache_extra_config
  else
    info "Extra Apache hardening skipped by user."
  fi
  if confirm "Apply Nginx banner hardening (server_tokens off) if Nginx is present?"; then
    secure_nginx_config
  else
    info "Nginx config hardening skipped by user."
  fi
  if confirm "Apply extra Nginx hardening prompts (directory listing and browser headers)? Outcome/risk shown per option"; then
    secure_nginx_extra_config
  else
    info "Extra Nginx hardening skipped by user."
  fi
  if confirm "Apply PHP hardening (expose_php Off, display_errors Off) if PHP is present?"; then
    secure_php_config
  else
    info "PHP config hardening skipped by user."
  fi
  if confirm "Apply advanced PHP hardening prompts (dangerous functions, URL includes, session cookies)? Outcome/risk shown per option"; then
    secure_php_advanced_config
  else
    info "Advanced PHP hardening skipped by user."
  fi
  if confirm "Apply BIND DNS hardening prompts (recursion ACLs and zone-transfer default)? Outcome/risk shown per option"; then
    secure_dns_config
  else
    info "DNS config hardening skipped by user."
  fi
  # Always surface DB advice (read-only; never purges a scored database).
  secure_database_advice
  end_task
}

# ============================================================================
# SECTION 17 — File permissions & umask
# ============================================================================
sec_perms() {
  start_task "perms" "File Permissions & umask"
  require_supported_write "File Permissions & umask" || { end_task; return; }
  local f
  for f in /etc/passwd /etc/group; do
    [[ -e "$f" ]] || continue; record_perm "$f"; run chmod 644 "$f"; run chown root:root "$f"
  done
  for f in /etc/shadow /etc/gshadow; do
    [[ -e "$f" ]] || continue; record_perm "$f"; run chmod 640 "$f"; run chown root:root "$f"
  done
  if [[ -e "$SSHD_CONFIG" ]]; then record_perm "$SSHD_CONFIG"; run chmod 600 "$SSHD_CONFIG"; fi
  if [[ -d /tmp ]]; then record_perm /tmp; run chmod 1777 /tmp; fi

  # per-user .ssh
  local d
  while IFS= read -r d; do
    [[ -d "$d" ]] || continue; record_perm "$d"; run chmod 700 "$d"
  done < <(find /home /root -maxdepth 2 -name .ssh -type d 2>/dev/null)
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue; record_perm "$f"; run chmod 600 "$f"
  done < <(find /home /root -maxdepth 3 -name authorized_keys -type f 2>/dev/null)
  ok "Key file permissions tightened"

  # umask 027 via profile.d (revertible: it's a new file)
  local uf="/etc/profile.d/99-umask-hardening.sh"
  prepare_edit "$uf"
  echo "umask 027" > "$uf"
  run chmod 644 "$uf"
  ok "umask 027 set for new shells ($uf)"
  end_task
}

# ============================================================================
# SECTION 18 — Display manager (guest / autologin)
# ============================================================================
sec_displaymgr() {
  start_task "displaymgr" "Display Manager (guest / autologin)"
  require_supported_write "Display Manager" || { end_task; return; }
  require_systemd_task "Display Manager" || { end_task; return; }
  local dm=""
  [[ -f /etc/X11/default-display-manager ]] && dm="$(cat /etc/X11/default-display-manager)"
  if   systemctl is-active lightdm >/dev/null 2>&1 || [[ "$dm" == *lightdm* ]]; then dm=lightdm
  elif systemctl is-active gdm3    >/dev/null 2>&1; then dm=gdm3
  elif systemctl is-active gdm     >/dev/null 2>&1 || [[ "$dm" == *gdm* ]]; then dm=gdm
  elif systemctl is-active sddm    >/dev/null 2>&1 || [[ "$dm" == *sddm* ]]; then dm=sddm
  else dm=""; fi

  if [[ -z "$dm" ]]; then ok "No graphical display manager detected (likely a server). Nothing to do."; end_task; return; fi
  log "Detected display manager: $dm"

  case "$dm" in
    lightdm)
      local c=/etc/lightdm/lightdm.conf
      prepare_edit "$c"
      grep -q '^\[Seat:\*\]' "$c" 2>/dev/null || echo '[Seat:*]' >> "$c"
      set_conf_kv "$c" allow-guest false "="
      set_conf_kv "$c" greeter-hide-users true "="
      set_conf_kv "$c" greeter-show-manual-login true "="
      set_conf_kv "$c" autologin-user none "="
      defer "Restart lightdm (this ENDS your graphical session)" "systemctl restart lightdm"
      ;;
    gdm3|gdm)
      local custom; custom=$([[ "$dm" == gdm3 ]] && echo /etc/gdm3/custom.conf || echo /etc/gdm/custom.conf)
      prepare_edit "$custom"
      grep -q '^\[daemon\]' "$custom" 2>/dev/null || echo '[daemon]' >> "$custom"
      set_conf_kv "$custom" AutomaticLoginEnable False "="
      set_conf_kv "$custom" TimedLoginEnable False "="
      local gd=/etc/dconf/db/gdm.d/00-login-screen
      prepare_edit "$gd"
      printf '[org/gnome/login-screen]\ndisable-user-list=true\n' > "$gd"
      run dconf update
      defer "Restart $dm (this ENDS your graphical session)" "systemctl restart $dm"
      ;;
    sddm)
      local c=/etc/sddm.conf.d/10-security.conf
      prepare_edit "$c"
      cat > "$c" <<'EOF'
[Users]
MinimumUid=1000
MaximumUid=60000
HideUsers=root,nobody
HideShells=/usr/sbin/nologin,/sbin/nologin,/bin/false
[Autologin]
Relogin=false
EOF
      defer "Restart sddm (this ENDS your graphical session)" "systemctl restart sddm"
      ;;
  esac
  ok "$dm hardened (guest disabled, autologin off, user list hidden)"
  info "The display-manager restart is DEFERRED to the end so it won't kill this run."
  end_task
}

# ============================================================================
# SECTION 19 — auditd
# ============================================================================
sec_auditd() {
  start_task "auditd" "Auditd"
  require_supported_write "Auditd" || { end_task; return; }
  require_systemd_task "Auditd" || { end_task; return; }
  if is_debian; then
    if ! pkg_install_tracked auditd; then
      warn "auditd is not available; skipping Auditd section."
      end_task; return
    fi
    pkg_install_tracked audispd-plugins || warn "audispd-plugins unavailable; continuing with auditd base package."
  else
    if ! pkg_install_tracked audit; then
      warn "audit package is not available; skipping Auditd section."
      end_task; return
    fi
  fi
  record_service auditd
  run systemctl enable --now auditd

  local rf=/etc/audit/rules.d/99-hardening.rules
  prepare_edit "$rf"
  cat > "$rf" <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /var/log/sudo.log -p wa -k sudoaction
EOF
  # Watch the platform's authentication log (Debian: auth.log, RHEL: secure).
  [[ -e /var/log/auth.log ]] && echo '-w /var/log/auth.log -p wa -k authlog' >> "$rf"
  [[ -e /var/log/secure   ]] && echo '-w /var/log/secure -p wa -k authlog'   >> "$rf"

  run augenrules --load 2>/dev/null
  run auditctl -e 1        # enable auditing (the checklist's 'auditctl -e 1')
  run auditctl -l
  ok "auditd enabled with identity/sudoers/sshd/authlog watch rules"
  end_task
}

# ============================================================================
# SECTION 24 — Package integrity audit
# ============================================================================
sec_integrity_audit() {
  start_task "integrity_audit" "Package Integrity Audit"
  require_supported_write "Package Integrity Audit" || { end_task; return; }
  warn "Outcome: compares installed package files against package-manager metadata. Risk: can be noisy and slow; config-file changes may appear even when legitimate."
  if is_debian; then
    if ! command -v debsums >/dev/null 2>&1; then
      if confirm "Install debsums for stronger Debian package verification? Outcome: enables checksum audit. Risk: installs a package and may take time"; then
        pkg_install_tracked debsums
      else
        info "debsums install skipped; dpkg -V will still run."
      fi
    fi
    if command -v debsums >/dev/null 2>&1; then
      run debsums -s || warn "debsums reported changed/missing package files; review output."
    fi
    run dpkg -V || warn "dpkg -V reported changed package-managed files; review output."
  else
    run rpm -Va || warn "rpm -Va reported changed package-managed files; review output."
  fi
  ok "Package integrity audit complete."
  end_task
}

# ============================================================================
# SECTION 25 — AIDE file integrity baseline
# ============================================================================
sec_aide() {
  start_task "aide" "AIDE File Integrity Baseline"
  require_supported_write "AIDE File Integrity Baseline" || { end_task; return; }
  warn "Outcome: creates a file-integrity baseline for later tamper checks. Risk: if the system is still compromised, AIDE will trust the compromised state; initialization can be slow and disk-heavy."
  if ! command -v aide >/dev/null 2>&1; then
    if confirm "Install AIDE now? Outcome: enables file integrity monitoring. Risk: installs package and may pull dependencies"; then
      pkg_install_tracked aide
    else
      warn "AIDE not installed; baseline skipped."
      end_task; return
    fi
  fi
  if ! command -v aide >/dev/null 2>&1; then
    warn "AIDE command still unavailable after install attempt; skipping baseline."
    end_task; return
  fi

  if confirm "Initialize a new AIDE baseline now? Outcome: records current filesystem as trusted. Risk: do this only after malware cleanup and scored-service verification"; then
    record_action "NOTE" "aide_baseline_initialized_not_revertible"
    if command -v aideinit >/dev/null 2>&1; then
      run aideinit || warn "aideinit failed; try 'aide --init' manually."
    else
      run aide --init || warn "aide --init failed; review AIDE config."
    fi
  else
    info "AIDE baseline initialization skipped."
    end_task; return
  fi

  local newdb dest=/var/lib/aide/aide.db.gz
  newdb=$(find /var/lib/aide -maxdepth 1 \( -name 'aide.db.new*' -o -name 'aide.db.gz.new' \) 2>/dev/null | head -1)
  if [[ -n "$newdb" ]]; then
    if confirm "Promote $newdb to $dest for future AIDE checks? Outcome: activates baseline. Risk: overwrites current AIDE baseline"; then
      prepare_edit "$dest"
      run cp -a "$newdb" "$dest"
      ok "AIDE baseline promoted to $dest"
    else
      info "AIDE baseline left at $newdb; promote manually before using aide --check."
    fi
  else
    warn "No new AIDE database found under /var/lib/aide."
  fi
  end_task
}

# ============================================================================
# SECTION 22 — Security audit tools (install + run, mostly read-only)
# ============================================================================
sec_tools() {
  start_task "tools" "Security Audit Tools (ClamAV / rkhunter / Lynis / Stacer)"
  require_supported_write "Security Audit Tools" || { end_task; return; }
  if confirm "Install & run ClamAV, rkhunter, chkrootkit (downloads signatures, can be slow)?"; then
    pkg_install_tracked clamav || warn "ClamAV unavailable; freshclam scan prep skipped."
    pkg_install_tracked rkhunter || warn "rkhunter unavailable; rkhunter checks skipped."
    pkg_install_tracked chkrootkit || warn "chkrootkit unavailable; chkrootkit checks skipped."
    if command -v freshclam >/dev/null 2>&1; then
      log "Updating ClamAV signatures (freshclam)"; run freshclam
    else
      warn "freshclam command not available; ClamAV signature update skipped."
    fi
    if command -v chkrootkit >/dev/null 2>&1; then
      log "Running chkrootkit"; run chkrootkit -q
    else
      warn "chkrootkit command not available; skipped."
    fi
    if command -v rkhunter >/dev/null 2>&1; then
      log "Updating & running rkhunter"; run rkhunter --update; run rkhunter --propupd; run rkhunter -c --sk
      info "rkhunter log: /var/log/rkhunter.log"
    else
      warn "rkhunter command not available; skipped."
    fi
  fi
  if confirm "Run a Lynis audit (read-only, produces a report)?"; then
    if ! command -v lynis >/dev/null 2>&1; then pkg_install_tracked lynis; fi
    if command -v lynis >/dev/null 2>&1; then
      run lynis audit system --quick
      info "Lynis report: /var/log/lynis-report.dat  (grep for warning[]/suggestion[])"
    else
      warn "lynis not available via package manager; skip or install from upstream."
    fi
  fi
  if confirm "Install Logwatch and produce a one-shot log summary?"; then
    pkg_install_tracked logwatch
    if command -v logwatch >/dev/null 2>&1; then
      log "Running logwatch (today, high detail) — summary follows:"
      run logwatch --detail high --range today --output stdout 2>/dev/null \
        || warn "logwatch run failed (may need an MTA or a populated log range)."
      info "Logwatch can mail daily summaries via cron.daily once an MTA is configured."
    else
      warn "logwatch not available via package manager; skipped."
    fi
  fi
  if confirm "Install Stacer GUI system monitor if available?"; then
    pkg_install_tracked stacer
    info "Stacer installed/requested. Launch it from the desktop session if needed."
  fi
  end_task
}

# ============================================================================
# SECTION 23 — Remove unauthorized media (.mp3) — DESTRUCTIVE / NOT REVERTIBLE
# ============================================================================
sec_mp3() {
  start_task "mp3" "Remove unauthorized .mp3 files (DESTRUCTIVE)"
  require_supported_write "Remove unauthorized .mp3 files" || { end_task; return; }
  warn "This deletes files PERMANENTLY and CANNOT be undone by revert.sh."
  warn "Per the checklist, only do this AFTER any forensics is complete."
  local files
  mapfile -t files < <(find / -iname "*.mp3" 2>/dev/null)
  prompt_selection ".mp3 files to DELETE" "${files[@]}"
  if [[ ${#SELECTED[@]} -gt 0 ]] && ask_risky "PERMANENTLY delete the ${#SELECTED[@]} selected .mp3 file(s)"; then
    local fpath
    for fpath in "${SELECTED[@]}"; do
      record_action "FILE_DELETED_PERMANENT" "$fpath"
      run rm -f -- "$fpath"
    done
    ok "Deleted ${#SELECTED[@]} .mp3 file(s)"
  fi
  end_task
}

# ============================================================================
# SECTION 20 — Fail2ban (brute-force protection)
# ============================================================================
sec_fail2ban() {
  start_task "fail2ban" "Fail2ban (SSH brute-force protection)"
  require_supported_write "Fail2ban" || { end_task; return; }
  require_systemd_task "Fail2ban" || { end_task; return; }

  # Fail2ban watches auth logs and bans IPs that fail repeatedly. Valuable even
  # with key-only SSH because it also slows protocol-level probes.
  warn "Competition note: scored services are checked from changing external IPs. Misconfigured fail2ban can block scoring or Orange Team logins."
  if ! ask_risky "Enable fail2ban for SSH now. Verify service scoring after enabling, and unban any legitimate source immediately if needed"; then
    warn "Fail2ban configuration skipped."
    end_task; return
  fi

  if is_rhel && ! pkg_installed fail2ban; then
    # fail2ban lives in EPEL on RHEL-likes.
    pkg_installed epel-release || pkg_install_tracked epel-release
  fi
  pkg_install_tracked fail2ban
  if ! command -v fail2ban-server >/dev/null 2>&1 && ! pkg_installed fail2ban; then
    warn "fail2ban not available from the package manager; skipping."
    end_task; return
  fi

  # Choose a ban action that matches the active firewall.
  local banaction="iptables-multiport"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'Status: active'; then
    banaction="ufw"
  elif is_rhel && systemctl is-active firewalld >/dev/null 2>&1; then
    banaction="firewallcmd-ipset"
  fi

  # SSH port + log backend differ per distro.
  local sshport="ssh"
  [[ -n "$SSH_PORT_CHANGED" ]] && sshport="$SSH_PORT_CHANGED"
  local ignoreip="${FAIL2BAN_IGNOREIP:-}" entered_ignoreip
  info "Optional fail2ban ignore list outcome: trusted IPs/CIDRs are never banned. Risk: any listed source can brute-force without fail2ban blocking it."
  if [[ -n "$ignoreip" ]]; then
    info "Using FAIL2BAN_IGNOREIP from environment: $ignoreip"
  else
    read -r -p "    Enter trusted admin/scoring/Orange Team IPs or CIDRs for fail2ban ignoreip (space-separated, blank = none): " entered_ignoreip
    ignoreip="$entered_ignoreip"
  fi
  local jail=/etc/fail2ban/jail.local
  prepare_edit "$jail"
  {
    echo "# Managed by harden.sh — local overrides (never edit jail.conf directly)"
    echo "[DEFAULT]"
    echo "bantime  = 3600"
    echo "findtime = 600"
    echo "maxretry = 3"
    echo "banaction = ${banaction}"
    if [[ -n "$ignoreip" ]]; then
      echo "ignoreip = 127.0.0.1/8 ::1 ${ignoreip}"
    fi
    echo ""
    echo "[sshd]"
    echo "enabled = true"
    echo "port    = ${sshport}"
    if is_debian; then
      echo "backend = auto"
      echo "logpath = /var/log/auth.log"
    else
      # RHEL logs ssh to the journal on modern systems.
      echo "backend = systemd"
    fi
  } > "$jail"

  # Optional web-auth jails if those servers are present.
  if pkg_installed apache2 || pkg_installed httpd || command -v httpd >/dev/null 2>&1 || command -v apache2ctl >/dev/null 2>&1; then
    if confirm "Apache detected — enable the [apache-auth] fail2ban jail?"; then
      { echo ""; echo "[apache-auth]"; echo "enabled = true"; } >> "$jail"
    fi
  fi
  if pkg_installed nginx || command -v nginx >/dev/null 2>&1; then
    if confirm "Nginx detected — enable the [nginx-http-auth] fail2ban jail?"; then
      { echo ""; echo "[nginx-http-auth]"; echo "enabled = true"; } >> "$jail"
    fi
  fi

  record_service fail2ban
  run systemctl enable --now fail2ban
  # Reload to pick up jail.local if it was already running.
  run systemctl restart fail2ban 2>/dev/null
  if command -v fail2ban-client >/dev/null 2>&1; then
    run fail2ban-client status 2>/dev/null || true
    run fail2ban-client status sshd 2>/dev/null || true
  fi
  ok "Fail2ban configured (sshd jail; bantime 1h / 3 retries / banaction ${banaction})"
  end_task
}

# ============================================================================
# SECTION 21 — Mandatory Access Control (AppArmor / SELinux enforcement)
# ============================================================================
sec_mac() {
  start_task "mac" "Mandatory Access Control (AppArmor / SELinux)"
  require_supported_write "Mandatory Access Control" || { end_task; return; }
  if is_rhel; then
    if ! command -v getenforce >/dev/null 2>&1; then
      warn "SELinux tooling not present; skipping."
      end_task; return
    fi
    local mode; mode="$(getenforce 2>/dev/null)"
    info "Current SELinux mode: ${mode:-unknown}"
    run sestatus 2>/dev/null || true
    if [[ "$mode" == "Enforcing" ]]; then
      ok "SELinux already enforcing."
    elif ask_risky "Set SELinux to ENFORCING now and persist it in /etc/selinux/config. Misconfigured policy can block services — verify your readme does not require permissive"; then
      run setenforce 1 2>/dev/null || warn "setenforce failed (SELinux may be disabled at boot; a relabel/reboot may be required)."
      if [[ -f /etc/selinux/config ]]; then
        prepare_edit /etc/selinux/config
        set_conf_kv /etc/selinux/config SELINUX enforcing "="
      fi
      record_action "NOTE" "selinux_set_enforcing"
      ok "SELinux set to enforcing (config persisted)."
    fi
  else
    require_systemd_task "AppArmor" || { end_task; return; }
    if ! command -v aa-status >/dev/null 2>&1 && ! pkg_installed apparmor; then
      warn "AppArmor not installed; skipping (install 'apparmor' to use it)."
      end_task; return
    fi
    record_service apparmor
    run systemctl enable --now apparmor 2>/dev/null || true
    run aa-status 2>/dev/null || true
    if ask_risky "Set all COMPLAIN-mode AppArmor profiles to ENFORCE. A bad profile can block a service — review aa-status output first"; then
      if command -v aa-enforce >/dev/null 2>&1 && [[ -d /etc/apparmor.d ]]; then
        record_action "NOTE" "apparmor_profiles_set_to_enforce"
        run aa-enforce /etc/apparmor.d/* 2>/dev/null || warn "Some profiles could not be enforced."
        ok "AppArmor profiles set to enforce mode."
      else
        warn "aa-enforce / profiles directory unavailable; skipped."
      fi
    fi
  fi
  end_task
}

# ============================================================================
# Menu / dispatch
# ============================================================================
SECTION_FUNCS=(sec_scored_services sec_ad_deps sec_dns_validation sec_web_sweep sec_forensics sec_backup_snapshot sec_user_audit sec_autoupdate sec_passwords sec_pwaudit sec_auth_lockout sec_ssh sec_firewall sec_kernel sec_services sec_service_configs sec_perms sec_displaymgr sec_auditd sec_fail2ban sec_mac sec_tools sec_mp3 sec_integrity_audit sec_aide)
SECTION_DESC=(
  "Scored Service Health Check (read-only)"
  "AD / DNS / Time Dependency Check (read-only)"
  "DNS Service Validation (read-only)"
  "Webroot Malware & Permissions Sweep (read-only)"
  "Forensic / Persistence Checks (read-only)"
  "Web/App Backup Snapshot"
  "User & Group Audit (needs authorized.txt)"
  "Package Upgrade / Automatic Security Updates"
  "Password Policies (aging + complexity)"
  "Password Strength Audit (detect & reset weak passwords)"
  "Account Lockout / Empty Passwords / nullok"
  "SSH Hardening"
  "Firewall (UFW / firewalld)"
  "Kernel / sysctl Hardening"
  "Unwanted Services & Packages"
  "Service Config Hardening (FTP / Apache / Nginx / PHP / DB)"
  "File Permissions & umask"
  "Display Manager (guest / autologin)"
  "Auditd"
  "Fail2ban (SSH brute-force protection)"
  "Mandatory Access Control (AppArmor / SELinux)"
  "Security Audit Tools (ClamAV / rkhunter / Lynis / Logwatch / Stacer)"
  "Remove unauthorized .mp3 files (DESTRUCTIVE)"
  "Package Integrity Audit"
  "AIDE File Integrity Baseline"
)

print_menu() {
  echo
  echo "${C_BLD}Select sections to run:${C_RST}"
  local i
  for i in "${!SECTION_DESC[@]}"; do
    printf "  %2d) %s\n" "$((i+1))" "${SECTION_DESC[$i]}"
  done
  echo "   a) Run ALL sections in order"
  echo "   q) Quit"
  echo
  echo "Enter space-separated numbers (e.g. '1 4 6'), 'a' for all, or 'q' to quit."
}

run_section() { local idx="$1"; "${SECTION_FUNCS[$idx]}"; }

run_competition_preflight() {
  local -a preflight=(0 1 2 3 4)
  local idx
  echo
  warn "Competition-safe mode: running read-only scored-service, AD, DNS, webroot, and forensic checks first."
  for idx in "${preflight[@]}"; do
    run_section "$idx"
  done
}

drop_competition_preflight_from_todo() {
  local -n todo_ref=$1
  local -a filtered=()
  local idx
  for idx in "${todo_ref[@]}"; do
    case "$idx" in
      0|1|2|3|4) continue;;
    esac
    filtered+=("$idx")
  done
  todo_ref=("${filtered[@]}")
}

# Run any session-disrupting actions that were deferred (e.g. display-manager
# restart). This is the LAST thing the script does, so losing the terminal here
# costs nothing — the full transcript is already saved.
run_deferred() {
  [[ ${#DEFERRED_CMD[@]} -eq 0 ]] && return 0
  echo
  echo "${C_YEL}${C_BLD}=== Deferred actions (these may END your session) ===${C_RST}"
  echo "Everything else is complete. Full transcript saved to:"
  echo "  ${C_BLD}$OUTPUT_LOG${C_RST}"
  echo "After you log back in, review it with:  ${C_BLD}sudo $0 --show-last${C_RST}"
  echo "Pending:"
  local i
  for i in "${!DEFERRED_CMD[@]}"; do echo "  - ${DEFERRED_DESC[$i]}"; done
  if ! confirm "Run these now? (No = leave them; they take effect on next reboot)"; then
    warn "Deferred actions NOT run."
    return 0
  fi
  for i in "${!DEFERRED_CMD[@]}"; do
    log "Deferred: ${DEFERRED_DESC[$i]}"
    eval "${DEFERRED_CMD[$i]}"
  done
}

main() {
  echo "${C_BLD}=== Linux Hardening Tool ===${C_RST}"
  detect_distro
  log "Run directory: $RUN_DIR"
  log "Actions log:   $ACTIONS_LOG   (feed this to revert.sh)"
  if [[ $COMPETITION_SAFE -eq 1 ]]; then
    warn "Competition-safe mode active: --yes-risky auto-approval is disabled, read-only preflight runs first, and scored-service health runs again before deferred actions."
  fi
  echo

  print_menu
  local choice
  read -r -p "> " choice
  local -a todo=()
  case "${choice,,}" in
    q|quit) echo "Nothing to do."; exit 0;;
    a|all)  todo=("${!SECTION_DESC[@]}");;
    *)
      local tok
      for tok in $choice; do
        if [[ "$tok" =~ ^[0-9]+$ ]] && (( tok>=1 && tok<=${#SECTION_DESC[@]} )); then
          todo+=("$((tok-1))")
        else
          warn "Ignoring invalid selection: $tok"
        fi
      done
      ;;
  esac
  [[ ${#todo[@]} -eq 0 ]] && { echo "No valid sections selected."; exit 0; }

  local idx
  if [[ $COMPETITION_SAFE -eq 1 ]]; then
    run_competition_preflight
    drop_competition_preflight_from_todo todo
  fi
  for idx in "${todo[@]}"; do
    run_section "$idx"
  done

  echo
  if [[ $COMPETITION_SAFE -eq 1 ]]; then
    sec_scored_services "post"
    echo
  fi
  log "${C_GRN}${C_BLD}All selected sections complete.${C_RST}"
  log "Transcript: $OUTPUT_LOG   (replay later: sudo $0 --show-last)"
  log "To undo changes: sudo ./revert.sh --log \"$ACTIONS_LOG\""

  # Disruptive actions (display-manager restart) happen here, dead last.
  run_deferred
}

main "$@"
