#!/usr/bin/env bash
#
# harden.sh — Menu-driven Linux security hardening tool
# ============================================================================
# Implements the checks in the "Linux System Checklist", with corrections.
# Fully supports Debian/Ubuntu (apt), RHEL-family (dnf/yum), and SUSE-family
# (zypper) systems listed in README.md.
#
# Every change is LOGGED and BACKED UP so it can be undone with revert.sh.
#
# ----------------------------------------------------------------------------
# AUTHORIZED FILE FORMAT  (required only for the "User & Group Audit" section)
# ----------------------------------------------------------------------------
# Create a plain-text file (default: ./authorized.txt, or pass --authorized PATH)
# before running. Lines beginning with '#' are comments; blank lines are ignored.
# It has three sections introduced by [users], [sudoers], and [groups]:
#
#     # ---- example authorized.txt ----
#     [users]
#     alice          # every login account that is allowed to exist
#     bob
#     charlie
#     [sudoers]
#     alice          # the subset of users allowed admin (sudo/wheel) access
#     bob
#     [groups]
#     www-data: alice bob      # add-only: ensure alice/bob are members
#     developers: charlie      # missing entries do NOT remove existing members
#
#  * Any human account (UID >= 1000) NOT under [users] is flagged as unauthorized.
#  * Any user under [users] that does not exist can be created after confirmation;
#    the generated password is saved to the root-only new-credentials.txt.
#  * Any member of the sudo/wheel group NOT under [sudoers] is flagged for removal
#    from that group.
#  * [groups] is add-only for non-admin groups. It never removes existing members.
#    Missing groups can be created after confirmation, then listed users are
#    added. Use [sudoers], not [groups], to authorize sudo/wheel membership.
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
PKG_FAMILY=""            # apt | dnf | yum | zypper
DISTRO_FAMILY="unsupported"  # debian | rhel | suse | unsupported
WRITE_SUPPORTED=0        # 1 only for the fully supported distro families
DISTRO_ID=""; DISTRO_VER=""; DISTRO_LIKE=""
ADMIN_GROUP="sudo"       # sudo (debian) or wheel (rhel/suse)
SSHD_CONFIG="/etc/ssh/sshd_config"

declare -A BACKED_UP CREATED      # per-task staging backups for same-task rollback
declare -A ORIGINAL_BACKED_UP ORIGINAL_CREATED  # first-seen state for the full session
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
EASY_CREDS_FILE="$SCRIPT_DIR/harden-generated-credentials.txt" # easy-to-find copy (root only)
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

run_deferred_command() {
  local cmd="$1" svc
  case "$cmd" in
    "systemctl restart "*)
      svc="${cmd#systemctl restart }"
      if [[ "$svc" =~ ^[A-Za-z0-9_.@:-]+$ ]]; then
        run systemctl restart "$svc"
      else
        warn "Refusing unsupported deferred service name: $svc"
        return 1
      fi
      ;;
    *)
      warn "Unsupported deferred command skipped: $cmd"
      return 1
      ;;
  esac
}

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
  BACKED_UP=(); CREATED=()          # staging snapshots are scoped per task
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
#   FILE_BACKUP records a task-local pre-edit snapshot, so reverting one task can
#   restore the state before that task. A separate original-files copy preserves
#   the first-seen session state without being overwritten by later tasks.
#   If FILE absent -> record FILE_CREATE (revert will delete it) and mkdir parent.
prepare_edit() {
  local f="$1" dest original_dest task_id
  task_id="${CURRENT_TASK:-global}"
  if [[ -e "$f" ]]; then
    [[ -n "${CREATED[$f]:-}" ]] && return 0
    if [[ -z "${ORIGINAL_BACKED_UP[$f]:-}" && -z "${ORIGINAL_CREATED[$f]:-}" ]]; then
      original_dest="$BACKUP_DIR/original-files$f"
      mkdir -p "$(dirname "$original_dest")"
      cp -a "$f" "$original_dest"
      ORIGINAL_BACKED_UP[$f]="$original_dest"
    fi
    [[ -n "${BACKED_UP[$f]:-}" ]] && return 0
    dest="$BACKUP_DIR/files/${task_id}$f"
    mkdir -p "$(dirname "$dest")"
    cp -a "$f" "$dest"
    record_action "FILE_BACKUP" "$f" "$dest"
    BACKED_UP[$f]="$dest"
  else
    [[ -z "${ORIGINAL_BACKED_UP[$f]:-}" && -z "${ORIGINAL_CREATED[$f]:-}" ]] && ORIGINAL_CREATED[$f]=1
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
escape_ere_literal() {
  printf '%s' "$1" | sed 's/[][(){}.^$*+?|\\/]/\\&/g'
}

escape_sed_replacement() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//&/\\&}"
  s="${s//#/\\#}"
  printf '%s' "$s"
}

set_conf_kv() {
  local file="$1" key="$2" val="$3" sep="${4:- }"
  local key_re repl
  key_re="$(escape_ere_literal "$key")"
  repl="$(escape_sed_replacement "${key}${sep}${val}")"
  prepare_edit "$file"
  if grep -qE "^[[:space:]]*${key_re}([[:space:]]|=|$)" "$file" 2>/dev/null; then
    sed -i -E "s#^[[:space:]]*${key_re}([[:space:]]|=).*#${repl}#" "$file"
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

pam_module_exists() {
  local module="$1"
  find /lib /usr/lib /usr/lib64 -path "*/security/${module}" -print -quit 2>/dev/null | grep -q .
}

debian_common_auth_supports_faillock_rewrite() {
  local af="$1"
  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    /^[[:space:]]*auth[[:space:]]+/ {
      if ($0 ~ /pam_faillock\.so/) { existing=1 }
      if ($0 ~ /pam_deny\.so/) { deny=1 }
      if (!deny && $0 ~ /\[[^]]*success=[0-9]+[^]]*default=ignore[^]]*\]/) { primary=1 }
    }
    END { exit ((primary && deny && !existing) ? 0 : 1) }
  ' "$af"
}

rewrite_debian_common_auth_for_faillock() {
  local af="$1" tmp
  tmp="$(mktemp)" || return 1
  awk '
    function bump_success(line,   old, n) {
      if (match(line, /success=[0-9]+/)) {
        old = substr(line, RSTART, RLENGTH)
        n = substr(old, 9) + 1
        return substr(line, 1, RSTART - 1) "success=" n substr(line, RSTART + RLENGTH)
      }
      return line
    }
    {
      if (!inserted_pre && $0 ~ /^[[:space:]]*auth[[:space:]]+/ && $0 !~ /^[[:space:]]*#/) {
        print "auth    required    pam_faillock.so preauth silent"
        inserted_pre = 1
      }
      if ($0 ~ /^[[:space:]]*auth[[:space:]]+requisite[[:space:]]+pam_deny\.so([[:space:]]|$)/) {
        print "auth    [default=die]   pam_faillock.so authfail"
        inserted_fail = 1
        print
        next
      }
      if (!inserted_fail && $0 ~ /^[[:space:]]*auth[[:space:]]+\[[^]]*success=[0-9]+[^]]*default=ignore[^]]*\]/ && $0 !~ /pam_faillock\.so/) {
        print bump_success($0)
        next
      }
      print
    }
    END { if (!inserted_pre || !inserted_fail) exit 3 }
  ' "$af" > "$tmp" || { rm -f "$tmp"; return 1; }
  cat "$tmp" > "$af"
  rm -f "$tmp"
}

insert_debian_common_account_faillock() {
  local ac="$1" tmp
  tmp="$(mktemp)" || return 1
  awk '
    {
      if (!inserted && $0 ~ /^[[:space:]]*account[[:space:]]+/ && $0 !~ /^[[:space:]]*#/) {
        print "account required pam_faillock.so"
        inserted = 1
      }
      print
    }
    END { if (!inserted) exit 3 }
  ' "$ac" > "$tmp" || { rm -f "$tmp"; return 1; }
  cat "$tmp" > "$ac"
  rm -f "$tmp"
}

print_debian_faillock_manual_plan() {
  local reason="$1" af="${2:-/etc/pam.d/common-auth}" ac="${3:-/etc/pam.d/common-account}" fc="${4:-/etc/security/faillock.conf}"
  warn "Debian-family pam_faillock was not applied automatically."
  warn "Reason: $reason"
  info "Intended manual update to review before editing:"
  info "1. Confirm pam_faillock.so exists under /lib, /usr/lib, or /usr/lib64 security module paths."
  info "2. In $fc, set:"
  info "   deny = 5"
  info "   unlock_time = 900"
  info "   fail_interval = 900"
  info "3. In $af, only if the stack has '[success=N default=ignore]' before 'auth requisite pam_deny.so':"
  info "   - Insert before the first active auth line:"
  info "     auth    required    pam_faillock.so preauth silent"
  info "   - Increase that pam_unix success=N value by 1, so the success path skips both authfail and pam_deny."
  info "   - Insert immediately before 'auth requisite pam_deny.so':"
  info "     auth    [default=die]   pam_faillock.so authfail"
  info "   - Do NOT add an 'authsucc' line on Debian/Kali common-auth."
  info "4. In $ac, insert before the first active account line:"
  info "     account required pam_faillock.so"
  info "5. Keep a root/rescue shell open and test TTY, GUI, sudo, and SSH before logging out."
}

configure_debian_faillock() {
  local af="/etc/pam.d/common-auth" ac="/etc/pam.d/common-account" fc="/etc/security/faillock.conf"
  if ! pam_module_exists pam_faillock.so; then
    print_debian_faillock_manual_plan "pam_faillock.so was not found, so the module cannot be wired safely." "$af" "$ac" "$fc"
    return 1
  fi
  if [[ ! -f "$af" || ! -f "$ac" ]]; then
    print_debian_faillock_manual_plan "$af or $ac was not found." "$af" "$ac" "$fc"
    return 1
  fi
  if grep -q "pam_faillock.so" "$af" "$ac" 2>/dev/null; then
    print_debian_faillock_manual_plan "Existing pam_faillock lines were found in $af or $ac; refusing to rewrite an unknown PAM stack." "$af" "$ac" "$fc"
    warn "If this is the old authsucc-based harden.sh layout, restore those files from backup/revert first, then rerun."
    grep -n "pam_faillock.so" "$af" "$ac" 2>/dev/null || true
    return 1
  fi
  if ! debian_common_auth_supports_faillock_rewrite "$af"; then
    print_debian_faillock_manual_plan "$af did not match the expected Debian/Kali control-flow shape. Expected '[success=N default=ignore]' before 'auth requisite pam_deny.so'." "$af" "$ac" "$fc"
    return 1
  fi

  prepare_edit "$fc"
  set_conf_kv "$fc" deny 5 " = "
  set_conf_kv "$fc" unlock_time 900 " = "
  set_conf_kv "$fc" fail_interval 900 " = "

  prepare_edit "$af"
  prepare_edit "$ac"
  if rewrite_debian_common_auth_for_faillock "$af" && insert_debian_common_account_faillock "$ac"; then
    ok "faillock configured using Debian-family no-authsucc layout in common-auth/common-account"
    info "Correct-password path: pam_unix success=N is increased by 1, so it skips authfail and pam_deny."
  else
    err "Failed to rewrite Debian-family PAM faillock stack; restoring task backups."
    restore_task_backup "$af"
    restore_task_backup "$ac"
    restore_task_backup "$fc"
    print_debian_faillock_manual_plan "The rewrite command failed after safety checks; task backups were restored." "$af" "$ac" "$fc"
    return 1
  fi
}

# Best-effort list of the non-root human account(s) tied to this session. This
# protects the competitor/operator account even when the script was launched
# from a root shell where SUDO_USER is unavailable.
detect_invoking_human_accounts() {
  local -a candidates=()
  local cand entry uid
  local -A seen=()

  for cand in "${SUDO_USER:-}" "${LOGNAME:-}" "${USER:-}"; do
    [[ -n "$cand" ]] && candidates+=("$cand")
  done

  cand="$(logname 2>/dev/null || true)"
  [[ -n "$cand" ]] && candidates+=("$cand")

  cand="$(who am i 2>/dev/null | awk '{print $1}')"
  [[ -n "$cand" ]] && candidates+=("$cand")

  cand="$(id -un 2>/dev/null || true)"
  [[ -n "$cand" ]] && candidates+=("$cand")

  for cand in "${candidates[@]}"; do
    [[ -n "$cand" && "$cand" != "root" ]] || continue
    [[ -n "${seen[$cand]:-}" ]] && continue
    entry="$(getent passwd "$cand" 2>/dev/null || true)"
    uid="$(printf '%s\n' "$entry" | awk -F: '{print $3}')"
    [[ "$uid" =~ ^[0-9]+$ && "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
    seen["$cand"]=1
    printf '%s\n' "$cand"
  done
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
  local id="${DISTRO_ID,,}" like=" ${DISTRO_LIKE,,} "
  case "$id" in
    debian|ubuntu)
      DISTRO_FAMILY="debian"
      ADMIN_GROUP="sudo"
      if command -v apt-get >/dev/null 2>&1; then
        PKG_FAMILY="apt"
        WRITE_SUPPORTED=1
      fi
      ;;
    rhel|fedora|almalinux|rocky|centos|ol|amzn)
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
    opensuse*|sles|sled|sle_hpc|suse)
      DISTRO_FAMILY="suse"
      ADMIN_GROUP="wheel"
      if command -v zypper >/dev/null 2>&1; then
        PKG_FAMILY="zypper"
        WRITE_SUPPORTED=1
      fi
      ;;
    *)
      if [[ "$like" == *" debian "* || "$like" == *" ubuntu "* ]] && command -v apt-get >/dev/null 2>&1; then
        DISTRO_FAMILY="debian"
        ADMIN_GROUP="sudo"
        PKG_FAMILY="apt"
        WRITE_SUPPORTED=1
      elif [[ "$like" == *" rhel "* || "$like" == *" fedora "* || "$like" == *" centos "* ]] && { command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; }; then
        DISTRO_FAMILY="rhel"
        ADMIN_GROUP="wheel"
        if command -v dnf >/dev/null 2>&1; then
          PKG_FAMILY="dnf"
        else
          PKG_FAMILY="yum"
        fi
        WRITE_SUPPORTED=1
      elif [[ "$like" == *" suse "* || "$like" == *" opensuse "* ]] && command -v zypper >/dev/null 2>&1; then
        DISTRO_FAMILY="suse"
        ADMIN_GROUP="wheel"
        PKG_FAMILY="zypper"
        WRITE_SUPPORTED=1
      else
        DISTRO_FAMILY="unsupported"
        WRITE_SUPPORTED=0
        if command -v apt-get >/dev/null 2>&1; then PKG_FAMILY="apt"
        elif command -v dnf >/dev/null 2>&1; then PKG_FAMILY="dnf"
        elif command -v yum >/dev/null 2>&1; then PKG_FAMILY="yum"
        elif command -v zypper >/dev/null 2>&1; then PKG_FAMILY="zypper"
        else PKG_FAMILY="unknown"; fi
      fi
      ;;
  esac

  if [[ $WRITE_SUPPORTED -eq 0 ]]; then
    warn "Unsupported distro for write-hardening tasks: ${DISTRO_ID:-unknown} ${DISTRO_VER:-}."
    warn "Read-only checks can still run. Write-hardening is built for Debian/Ubuntu, RHEL/Fedora-family, and SUSE-family systems only."
  fi
  record_action "META" "distro" "${DISTRO_ID}" "${DISTRO_VER}" "${PKG_FAMILY}" "${DISTRO_FAMILY}" "${WRITE_SUPPORTED}"
  log "Detected: ${C_BLD}${DISTRO_ID:-unknown} ${DISTRO_VER}${C_RST} (family: ${DISTRO_FAMILY}, package manager: ${PKG_FAMILY}, admin group: ${ADMIN_GROUP}${DISTRO_LIKE:+, like: ${DISTRO_LIKE}})"
}

is_debian() { [[ "$DISTRO_FAMILY" == "debian" ]]; }
is_rhel()   { [[ "$DISTRO_FAMILY" == "rhel" ]]; }
is_suse()   { [[ "$DISTRO_FAMILY" == "suse" ]]; }

require_supported_write() {
  local task="${1:-${CURRENT_TASK:-this task}}"
  if [[ $WRITE_SUPPORTED -eq 1 ]]; then
    return 0
  fi
  warn "Unsupported distro for this task: $task. Skipping write-hardening."
  warn "Detected ${DISTRO_ID:-unknown} ${DISTRO_VER:-}; supported write-hardening distros are Debian/Ubuntu, RHEL/Fedora-family, and SUSE-family systems."
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
    dnf|yum|zypper) rpm -q "$1" >/dev/null 2>&1;;
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
    zypper)
      zypper --non-interactive --quiet info "$p" >/dev/null 2>&1
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
    zypper) run zypper --non-interactive install "$p";;
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
    zypper) run zypper --non-interactive remove "$p";;
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

pkg_install_any_tracked() {
  local p
  for p in "$@"; do
    if pkg_installed "$p"; then
      info "$p already installed."
      return 0
    fi
  done
  for p in "$@"; do
    if pkg_available "$p"; then
      record_action "PKG_INSTALL" "$PKG_FAMILY" "$p"
      if pkg_install "$p"; then
        ok "Installed $p"
        return 0
      fi
      warn "Failed to install $p"
      return 1
    fi
  done
  warn "None of these packages are available from configured repositories for ${DISTRO_ID:-this distro}: $*"
  return 1
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
    zypper)
      run zypper --non-interactive refresh
      run zypper --non-interactive update
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
  local wl u out mp authlog count twf svc
  local -a scan_roots=() recent_roots=()
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
  log "World-writable files on local filesystems (first 200):"
  while IFS= read -r mp; do
    find "$mp" -xdev -type f -perm -0002 -ls 2>/dev/null
  done < <(df --local -P 2>/dev/null | awk 'NR>1 {print $6}') | head -200
  log "World-writable directories missing sticky bit on local filesystems (first 200):"
  while IFS= read -r mp; do
    find "$mp" -xdev -type d -perm -0002 ! -perm -1000 -ls 2>/dev/null
  done < <(df --local -P 2>/dev/null | awk 'NR>1 {print $6}') | head -200
  log "Filesystem layout for /, /home, /tmp, /var, /var/log, /dev/shm:"
  if command -v findmnt >/dev/null 2>&1; then
    run findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS / /home /tmp /var /var/log /dev/shm 2>/dev/null || true
  else
    run df -h / /home /tmp /var /var/log /dev/shm 2>/dev/null || true
  fi
  log "Files/directories with no owning user or group on local filesystems (first 200):"
  while IFS= read -r mp; do
    find "$mp" -xdev \( -nouser -o -nogroup \) -ls 2>/dev/null
  done < <(df --local -P 2>/dev/null | awk 'NR>1 {print $6}') | head -200
  log "Script/archive/package files under /home and /root (first 200):"
  find /home /root -xdev -type f \( -iname '*.sh' -o -iname '*.bash' -o -iname '*.py' \
    -o -iname '*.pl' -o -iname '*.php' -o -iname '*.cgi' -o -iname '*.deb' \
    -o -iname '*.rpm' -o -iname '*.zip' -o -iname '*.tgz' -o -iname '*.tar.gz' \) \
    -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %p\n' 2>/dev/null | sort | head -200
  for mp in /etc /usr/local /var/www /srv/www /srv/http /home /root /tmp /var/tmp /dev/shm; do
    [[ -d "$mp" ]] && recent_roots+=("$mp")
  done
  if [[ ${#recent_roots[@]} -gt 0 ]]; then
    log "Recently changed files in sensitive trees (ctime <= 7 days, first 200):"
    find "${recent_roots[@]}" -xdev -type f -ctime -7 \
      -printf '%TY-%Tm-%Td %TH:%TM %m %u:%g %p\n' 2>/dev/null | sort | head -200
  fi
  for mp in /var/www /srv/www /srv/http /home /root /tmp /var/tmp /dev/shm; do
    [[ -d "$mp" ]] && scan_roots+=("$mp")
  done
  if [[ ${#scan_roots[@]} -gt 0 ]]; then
    log "Suspicious long base64-like strings in web/script files (first 200):"
    grep -RInE --include='*.php' --include='*.phtml' --include='*.phar' \
      --include='*.inc' --include='*.js' --include='*.sh' --include='*.py' \
      --include='*.pl' --include='*.cgi' '[A-Za-z0-9+/]{120,}={0,2}' \
      "${scan_roots[@]}" 2>/dev/null | head -200 || true
  fi
  if command -v findmnt >/dev/null 2>&1; then
    log "Mount options for temp/shared-memory paths:"
    run findmnt -no TARGET,OPTIONS /tmp /var/tmp /dev/shm /run/shm 2>/dev/null || true
  fi
  log "/etc/resolv.conf (resolver configuration):"
  if [[ -r /etc/resolv.conf ]]; then
    run sed -n '1,80p' /etc/resolv.conf
  else
    warn "/etc/resolv.conf is not readable."
  fi
  log "TCP Wrappers files (/etc/hosts.allow and /etc/hosts.deny):"
  for twf in /etc/hosts.allow /etc/hosts.deny; do
    if [[ -r "$twf" ]]; then
      echo "== $twf =="
      sed -n '1,120p' "$twf"
    else
      info "$twf is absent or not readable."
    fi
  done
  log "Passwordless sudo grants (NOPASSWD / !authenticate):"
  grep -RInE 'NOPASSWD|!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null || true
  for authlog in /var/log/auth.log /var/log/secure; do
    [[ -f "$authlog" ]] || continue
    count=$(grep -Eci 'Failed password|authentication failure|Invalid user' "$authlog" 2>/dev/null || true)
    info "$authlog failed-login style events: ${count:-0}"
  done
  log "Account database validation:"
  if command -v pwck >/dev/null 2>&1; then
    run pwck -r || warn "pwck reported account database issues."
  else
    warn "pwck not available."
  fi
  if command -v grpck >/dev/null 2>&1; then
    run grpck -r || warn "grpck reported group database issues."
  else
    warn "grpck not available."
  fi
  log "UID 0 accounts:"
  awk -F: '$3==0{print "      " $0}' /etc/passwd 2>/dev/null || true
  log "System/service accounts with interactive shells:"
  awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /(nologin|false)$/){print "      " $1 ":" $3 ":" $7}' /etc/passwd 2>/dev/null || true
  log "Potential shell/environment injection lines:"
  grep -RInE 'LD_PRELOAD|LD_LIBRARY_PATH|(^|[[:space:]])PATH=|alias[[:space:]]+|curl[[:space:]].*\||wget[[:space:]].*\||nc[[:space:]]|ncat[[:space:]]|/dev/tcp' \
    /etc/environment /etc/profile /etc/bash.bashrc /etc/profile.d 2>/dev/null | head -200 || true
  log "FTP account and /var/ftp permissions:"
  if getent passwd ftp >/dev/null 2>&1; then
    run getent passwd ftp || true
  else
    info "No ftp account found."
  fi
  [[ -d /var/ftp ]] && run ls -ld /var/ftp || true
  log "Mail daemon/open-relay quick check:"
  for svc in postfix sendmail exim4; do
    command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" && run systemctl is-active "$svc" || true
  done
  [[ -f /etc/postfix/main.cf ]] && grep -nE '^(mynetworks|inet_interfaces|smtpd_recipient_restrictions)[[:space:]]*=' /etc/postfix/main.cf || true
  log "NTP/chrony restriction quick check:"
  grep -RInE '^[[:space:]]*(restrict|allow|cmdallow|port|acquisitionport)[[:space:]]' /etc/ntp.conf /etc/chrony.conf /etc/chrony/chrony.conf 2>/dev/null || true
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
  log "Non-standard SUID/SGID binaries on root filesystem (first 100):"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls 2>/dev/null \
    | grep -vE '/(bin|sbin|usr/(bin|sbin|lib(exec)?)|lib(64)?|snap)/' \
    | head -100 || true
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
AUTH_USERS=(); AUTH_SUDO=(); AUTH_GROUP_SPECS=()
parse_authorized() {
  AUTH_USERS=(); AUTH_SUDO=(); AUTH_GROUP_SPECS=(); local sec="" line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(echo "$line" | xargs 2>/dev/null)"
    [[ -z "$line" ]] && continue
    case "${line,,}" in
      "[users]")   sec="users";   continue;;
      "[sudoers]") sec="sudoers"; continue;;
      "[groups]")  sec="groups";  continue;;
    esac
    [[ "$sec" == "users"   ]] && AUTH_USERS+=("$line")
    [[ "$sec" == "sudoers" ]] && AUTH_SUDO+=("$line")
    if [[ "$sec" == "groups" ]]; then
      if [[ "$line" != *:* ]]; then
        warn "Invalid [groups] line '$line' (expected: group: user1 user2); skipping."
        continue
      fi
      local group members member
      group="$(echo "${line%%:*}" | xargs 2>/dev/null)"
      members="$(echo "${line#*:}" | tr ',' ' ' | xargs 2>/dev/null)"
      if [[ -z "$group" || -z "$members" ]]; then
        warn "Invalid [groups] line '$line' (missing group or users); skipping."
        continue
      fi
      for member in $members; do
        AUTH_GROUP_SPECS+=("${group}:${member}")
      done
    fi
  done < "$AUTH_FILE"
}

in_list() { local x="$1"; shift; local i; for i in "$@"; do [[ "$x" == "$i" ]] && return 0; done; return 1; }

ensure_creds_file() {
  if [[ ! -s "$CREDS_FILE" ]]; then
    : > "$CREDS_FILE"
    chmod 600 "$CREDS_FILE"
    echo "# Generated by harden.sh on $(date)  -- KEEP SECRET" >> "$CREDS_FILE"
  fi
  if [[ ! -s "$EASY_CREDS_FILE" ]]; then
    : > "$EASY_CREDS_FILE"
    chmod 600 "$EASY_CREDS_FILE"
    echo "# Generated by harden.sh on $(date)  -- KEEP SECRET" >> "$EASY_CREDS_FILE"
  fi
}

save_credential_line() {
  local line="$1"
  ensure_creds_file
  printf '%s\n' "$line" >> "$CREDS_FILE"
  printf '%s\n' "$line" >> "$EASY_CREDS_FILE"
}

ensure_authorized_group_memberships() {
  local spec group user pu
  local -A protected_map=()
  local -A skipped_groups=()
  local -a protected_users=()
  mapfile -t protected_users < <(detect_invoking_human_accounts)
  for pu in "${protected_users[@]}"; do protected_map["$pu"]=1; done
  if [[ ${#AUTH_GROUP_SPECS[@]} -eq 0 ]]; then
    info "Authorized group additions: (none)"
    return 0
  fi
  info "Authorized group additions requested: ${AUTH_GROUP_SPECS[*]}"
  for spec in "${AUTH_GROUP_SPECS[@]}"; do
    group="${spec%%:*}"
    user="${spec#*:}"
    if [[ "$group" == "$ADMIN_GROUP" || "$group" == "sudo" || "$group" == "wheel" ]]; then
      warn "Ignoring [groups] entry '${group}: ${user}'. Use [sudoers] to authorize admin-group membership."
      continue
    fi
    if ! in_list "$user" "${AUTH_USERS[@]}"; then
      warn "Ignoring [groups] entry '${group}: ${user}' because '$user' is not listed under [users]."
      continue
    fi
    if [[ -n "${protected_map[$user]:-}" ]]; then
      warn "Skipping [groups] change for protected invoking/session account '$user'."
      continue
    fi
    if ! getent passwd "$user" >/dev/null 2>&1; then
      warn "User '$user' listed for group '$group' does not exist; skipping."
      continue
    fi
    if ! getent group "$group" >/dev/null 2>&1; then
      if [[ -n "${skipped_groups[$group]:-}" ]]; then
        warn "Group '$group' still does not exist; skipping '$user'."
        continue
      fi
      warn "Group '$group' listed under [groups] does not exist."
      if [[ ! "$group" =~ ^[A-Za-z_][A-Za-z0-9_.-]*[$]?$ ]]; then
        warn "Skipping invalid group name '$group'."
        skipped_groups["$group"]=1
        continue
      fi
      if confirm "Create group '$group' and add listed authorized users to it? Outcome: creates a local group and applies matching [groups] memberships. Risk: wrong groups can grant unintended app/file access or be scored unauthorized"; then
        record_action "GROUP_CREATE" "$group"
        if run groupadd "$group"; then
          ok "Created group $group"
        else
          warn "Failed creating group '$group'; skipping matching [groups] memberships."
          skipped_groups["$group"]=1
          continue
        fi
      else
        warn "Group '$group' creation declined; skipping matching [groups] memberships."
        skipped_groups["$group"]=1
        continue
      fi
    fi
    if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fxq "$group"; then
      ok "$user is already a member of $group."
      continue
    fi
    record_action "GROUP_MEMBER_ADD" "$user" "$group"
    if run gpasswd -a "$user" "$group"; then
      ok "Added $user to $group"
    else
      warn "Failed adding $user to $group"
    fi
  done
}

create_missing_authorized_users() {
  local missing=() u
  for u in "${AUTH_USERS[@]}"; do
    [[ "$u" == "root" ]] && continue
    getent passwd "$u" >/dev/null 2>&1 || missing+=("$u")
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "No missing authorized users."
    return 0
  fi

  warn "Authorized users listed in $AUTH_FILE but missing from this system: ${missing[*]}"
  if ! confirm "Create these missing authorized users now? Outcome: creates login accounts with home dirs and generated passwords saved to $CREDS_FILE. Risk: extra accounts can be scored unauthorized if your readme is wrong"; then
    info "Missing authorized-user creation skipped."
    return 0
  fi

  prepare_edit /etc/passwd; prepare_edit /etc/shadow
  prepare_edit /etc/group;  prepare_edit /etc/gshadow
  ensure_creds_file

  local shell newpw
  shell="/bin/bash"
  [[ -x "$shell" ]] || shell="/bin/sh"
  for u in "${missing[@]}"; do
    if [[ ! "$u" =~ ^[A-Za-z_][A-Za-z0-9_.-]*[$]?$ ]]; then
      warn "Skipping invalid username '$u'."
      continue
    fi
    if ! newpw="$(gen_password)"; then
      warn "Failed generating password for authorized user $u; user was not created."
      continue
    fi
    if run useradd -m -s "$shell" "$u"; then
      record_action "USER_CREATE" "$u"
    else
      warn "Failed creating authorized user $u"
      continue
    fi
    if printf '%s:%s\n' "$u" "$newpw" | chpasswd; then
      save_credential_line "$(printf '%-20s CREATED NEW=%s' "$u" "$newpw")"
      ok "Created authorized user $u (password: $newpw; saved to $CREDS_FILE and $EASY_CREDS_FILE)"
    else
      warn "Created $u but failed to set the generated password; locking account until manually fixed."
      run passwd -l "$u" >/dev/null 2>&1 || true
    fi
  done
}


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

  local -A PROTECTED_USERS=()
  local -a protected_users=()
  local pu
  mapfile -t protected_users < <(detect_invoking_human_accounts)
  if [[ ${#protected_users[@]} -gt 0 ]]; then
    for pu in "${protected_users[@]}"; do PROTECTED_USERS["$pu"]=1; done
    info "Protected invoking account(s), not offered for deletion: ${protected_users[*]}"
  else
    warn "Could not identify a non-root invoking account; review deletion prompts carefully."
  fi

  # --- Missing authorized users ---
  create_missing_authorized_users

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
    [[ -n "${PROTECTED_USERS[$u]:-}" ]] && { warn "Account '$u' is unauthorized but appears to be tied to this session; not offering deletion."; continue; }
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
    [[ "$u" == "root" ]] && continue
    [[ -n "${PROTECTED_USERS[$u]:-}" ]] && { warn "Admin '$u' is not listed in authorized [sudoers] but appears to be tied to this session; not offering removal from ${ADMIN_GROUP}."; continue; }
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

  # --- Authorized non-admin group memberships (add-only) ---
  ensure_authorized_group_memberships

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
  elif is_rhel; then
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
  elif is_suse; then
    [[ $do_upgrade -eq 1 ]] && pkg_full_upgrade
    local zbin svc timer
    zbin="$(command -v zypper || true)"
    if [[ -z "$zbin" ]]; then
      warn "zypper not found; skipping SUSE automatic security patch timer."
      end_task; return
    fi
    svc=/etc/systemd/system/harden-zypper-security.service
    timer=/etc/systemd/system/harden-zypper-security.timer
    prepare_edit "$svc"
    cat > "$svc" <<EOF
[Unit]
Description=Apply SUSE security patches with zypper
Documentation=man:zypper(8)

[Service]
Type=oneshot
ExecStart=${zbin} --non-interactive refresh
ExecStart=${zbin} --non-interactive patch -g security
EOF
    prepare_edit "$timer"
    cat > "$timer" <<'EOF'
[Unit]
Description=Daily SUSE security patch check

[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF
    run systemctl daemon-reload
    record_action "TIMER" "harden-zypper-security.timer"
    run systemctl enable --now harden-zypper-security.timer
    ok "SUSE zypper security-patch timer configured"
  else
    warn "Unsupported distro for automatic update configuration; skipped."
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
  elif is_suse; then
    if pkg_install_any_tracked pam_pwquality libpwquality-tools libpwquality; then
      pam_module_exists pam_pwquality.so && pwquality_available=1
      [[ $pwquality_available -eq 0 ]] && warn "pwquality package installed, but pam_pwquality.so was not found; PAM enforcement will be skipped."
    fi
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
    elif is_suse; then
      warn "SUSE-family PAM stacks are maintained with pam-config; harden.sh will not hand-edit common-password/common-*-pc."
      if command -v pam-config >/dev/null 2>&1; then
        run pam-config --list-modules || true
        warn "Use pam-config to review/enable pam_pwquality only after testing the exact stack on this image."
      else
        warn "pam-config not found; skipped SUSE PAM password-stack enforcement."
      fi
    else
      # RHEL/Fedora-family: authselect-managed PAM files should not be
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

  # Apply aging to existing human accounts, excluding the active operator account.
  local -A PROTECTED_USERS=()
  local -a protected_users=()
  local pu
  mapfile -t protected_users < <(detect_invoking_human_accounts)
  if [[ ${#protected_users[@]} -gt 0 ]]; then
    for pu in "${protected_users[@]}"; do PROTECTED_USERS["$pu"]=1; done
    info "Password aging will skip protected invoking/session account(s): ${protected_users[*]}"
  else
    warn "Could not identify a non-root invoking account; review the chage scope before approving."
  fi
  if ask_risky "Apply 90/7/12 day aging to existing human accounts except protected invoking/session accounts (chage)"; then
    local u
    while IFS= read -r u; do
      if [[ -n "${PROTECTED_USERS[$u]:-}" ]]; then
        info "Skipping password aging for protected invoking/session account '$u'."
        continue
      fi
      # record current aging so revert can restore it
      local cur
      cur=$(chage -l "$u" 2>/dev/null | awk -F: '/Maximum/{m=$2} /Minimum/{n=$2} /warning/{w=$2} END{gsub(/ /,"",m);gsub(/ /,"",n);gsub(/ /,"",w);print m":"n":"w}')
      record_action "CHAGE" "$u" "${cur:-:::}"
      run chage -M 90 -m 7 -W 12 "$u"
    done < <(awk -F: '$3>=1000 && $1!="nobody"{print $1}' /etc/passwd)
    ok "Password aging applied to non-protected existing accounts"
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
# fall back to a built-in crypt-compare when python3 still provides crypt.

# Generate a strong random password: 20 chars, guaranteeing one of each of the
# four character classes (the rest random). LC_ALL=C is required so that tr
# tolerates the binary bytes from /dev/urandom on any locale.
gen_password() {
  local lower upper digit special rest pw _attempt
  for _attempt in {1..10}; do
    lower=$(LC_ALL=C tr -dc '[:lower:]'  </dev/urandom | head -c1)
    upper=$(LC_ALL=C tr -dc '[:upper:]'  </dev/urandom | head -c1)
    digit=$(LC_ALL=C tr -dc '0-9'        </dev/urandom | head -c1)
    special=$(LC_ALL=C tr -dc '!@#%^*_=+-' </dev/urandom | head -c1)
    rest=$(LC_ALL=C tr -dc 'A-Za-z0-9!@#%^*_=+-' </dev/urandom | head -c16)
    pw="${lower}${upper}${digit}${special}${rest}"
    if [[ ${#pw} -eq 20 ]]; then
      printf '%s' "$pw"
      return 0
    fi
  done
  printf 'ERROR: gen_password failed to produce a 20-character password after retries\n' >&2
  return 1
}

# Built-in fallback: try common passwords + username variants against a hash
# using python3's crypt (handles yescrypt/sha512/md5). This must only be called
# after python_crypt_available passes; Python 3.13+ removed crypt.
# Echoes the matched plaintext if weak, nothing if not cracked.
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

python_crypt_available() {
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - <<'PY' >/dev/null 2>&1
import crypt
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
  local builtin_crypt_ok=0 pyver=""
  if command -v python3 >/dev/null 2>&1; then
    if python_crypt_available; then
      builtin_crypt_ok=1
    else
      pyver="$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' 2>/dev/null || true)"
      warn "python3 crypt module unavailable${pyver:+ (python $pyver)}; built-in fallback disabled. Python 3.13+ removed crypt, so use John the Ripper for password auditing."
    fi
  else
    warn "python3 not found; built-in fallback unavailable."
  fi

  # The competitor/operator account is NOT scored for password strength and must
  # keep its password. Detect it from sudo and login-session hints, not SUDO_USER
  # alone, because root shells often drop SUDO_USER.
  local -A PROTECTED_USERS=()
  local -a protected_users=()
  local pu
  mapfile -t protected_users < <(detect_invoking_human_accounts)
  local detected_human_count="${#protected_users[@]}"
  for pu in "${protected_users[@]}"; do PROTECTED_USERS["$pu"]=1; done
  if [[ -z "${SUDO_USER:-}" || "${SUDO_USER:-}" == "root" ]]; then
    PROTECTED_USERS["root"]=1
    protected_users+=("root")
    warn "SUDO_USER is not set to a non-root account; protecting root from password resets for this run."
  fi
  if [[ $detected_human_count -eq 0 ]]; then
    warn "Could not identify a non-root invoking account. If you are using a root shell, verify your operator account is not listed in 'Accounts in scope' before proceeding."
  fi
  if [[ ${#protected_users[@]} -gt 0 ]]; then
    info "Password audit will not change protected account(s): ${protected_users[*]}"
  fi

  # Build the in-scope account list: anything with a usable password hash
  # (skip locked '!'/'*' and empty entries). Includes root unless this was
  # launched from a root shell with no non-root SUDO_USER.
  local -A USERHASH=()
  local u h
  while IFS=: read -r u h _; do
    if [[ -n "${PROTECTED_USERS[$u]:-}" ]]; then
      info "Skipping '$u' (protected invoking/session account) — its password is left unchanged."
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
    if command -v unshadow >/dev/null 2>&1; then
      (umask 077; unshadow /etc/passwd /etc/shadow > "$combo" 2>/dev/null)
    else
      (umask 077; cp /etc/shadow "$combo")
    fi
    chmod 600 "$combo" 2>/dev/null || true
    [[ -s "$wordlist" ]] && run "$john_bin" --wordlist="$wordlist" "$combo"
    run "$john_bin" --single "$combo"           # username-based rules
    # collect cracked user:password pairs
    while IFS=: read -r cu cp _; do
      [[ -n "$cu" && -n "${USERHASH[$cu]:-}" ]] && WEAK["$cu"]="$cp"
    done < <("$john_bin" --show "$combo" 2>/dev/null | grep ':' )
  else
    if [[ $builtin_crypt_ok -eq 1 ]]; then
      warn "John unavailable; using built-in crypt-compare fallback."
      for u in "${!USERHASH[@]}"; do
        local pw; pw="$(crack_one_builtin "$u" "${USERHASH[$u]}" "$wordlist")"
        [[ -n "$pw" ]] && WEAK["$u"]="$pw"
      done
    else
      err "John unavailable and python3 crypt fallback unavailable; cannot audit password hashes. Install John the Ripper or run the audit on a Python version that still ships crypt."
      [[ "$WL_INSTALLED" == "1" ]] && { info "Removing 'wordlists' package (installed only for this audit)."; run pkg_remove_silent wordlists; }
      end_task; return
    fi
  fi

  # ---- report & reset ----
  if [[ ${#WEAK[@]} -eq 0 ]]; then
    ok "No weak passwords detected among ${#USERHASH[@]} account(s)."
  else
    warn "Weak passwords found for: ${!WEAK[*]}"
    if ! confirm "Reset weak passwords for these accounts now? Outcome: new passwords are written to $CREDS_FILE. Risk: affected users cannot log in until given the new password"; then
      info "Skipped weak-password resets; no password hashes changed."
    else
      prepare_edit /etc/shadow            # whole-file backup (safety net for revert)
      ensure_creds_file
      for u in "${!WEAK[@]}"; do
        local oldpw="${WEAK[$u]}" oldhash="${USERHASH[$u]}" newpw
        if ! newpw="$(gen_password)"; then
          err "Failed generating replacement password for $u; leaving password unchanged."
          continue
        fi
        # record original hash for precise, granular revert
        record_action "USER_PWHASH" "$u" "$oldhash"
        if printf '%s:%s\n' "$u" "$newpw" | chpasswd; then
          save_credential_line "$(printf '%-20s OLD(weak)=%-20s NEW=%s' "$u" "$oldpw" "$newpw")"
          echo "    ${C_GRN}RESET${C_RST} ${C_BLD}$u${C_RST}: old weak password '${oldpw}' -> new strong password: ${C_BLD}${newpw}${C_RST}"
        else
          err "Failed to reset password for $u"
        fi
      done
      ok "Weak passwords reset. Credentials saved to $CREDS_FILE (root-only)."
      info "Distribute the new passwords securely; consider 'chage -d 0 <user>' to force a change at next login."
    fi
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
    zypper) zypper --non-interactive remove "$p" >/dev/null 2>&1;;
    *) return 1;;
  esac
}

# ============================================================================
# SECTION 11 — Account lockout, empty passwords, nullok
# ============================================================================
sec_auth_lockout() {
  start_task "auth_lockout" "Account Lockout / Empty Passwords / nullok"
  require_supported_write "Account Lockout / Empty Passwords / nullok" || { end_task; return; }

  local -A PROTECTED_USERS=()
  local -a protected_users=()
  local pu
  mapfile -t protected_users < <(detect_invoking_human_accounts)
  if [[ ${#protected_users[@]} -gt 0 ]]; then
    for pu in "${protected_users[@]}"; do PROTECTED_USERS["$pu"]=1; done
    info "Account lockout tasks will skip protected invoking/session account(s): ${protected_users[*]}"
  else
    warn "Could not identify a non-root invoking account; review account-locking prompts carefully."
  fi

  # --- empty password accounts ---
  local empties lockable_empties=()
  mapfile -t empties < <(awk -F: '($2==""){print $1}' /etc/shadow)
  if [[ ${#empties[@]} -gt 0 ]]; then
    warn "Accounts with EMPTY passwords: ${empties[*]}"
    local u
    for u in "${empties[@]}"; do
      if [[ -n "${PROTECTED_USERS[$u]:-}" ]]; then
        warn "Skipping empty-password lock for protected invoking/session account '$u'. Set a real password manually before logging out."
      else
        lockable_empties+=("$u")
      fi
    done
    if [[ ${#lockable_empties[@]} -eq 0 ]]; then
      ok "No lockable empty-password accounts after protecting invoking/session account(s)."
    elif confirm "Lock empty-password accounts not tied to this session (passwd -l)?"; then
      local u
      for u in "${lockable_empties[@]}"; do
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
  if command -v faillock >/dev/null 2>&1; then
    if [[ ${#protected_users[@]} -gt 0 ]]; then
      for pu in "${protected_users[@]}"; do
        info "Current faillock records for '$pu' (read-only):"
        run faillock --user "$pu" || true
      done
    else
      info "faillock is installed; no protected invoking account was detected for a user-specific read-only check."
    fi
  else
    info "faillock command not found; skipping faillock status check."
  fi

  if ask_risky "Enable account lockout after 5 failed logins (pam_faillock). Debian/Kali uses corrected no-authsucc PAM layout; RHEL/Fedora uses authselect. Keep a root/rescue shell open and test TTY/GUI/sudo before logout"; then
    if is_debian; then
      configure_debian_faillock
    elif is_rhel; then
      if command -v authselect >/dev/null 2>&1; then
        prepare_edit /etc/security/faillock.conf
        set_conf_kv /etc/security/faillock.conf deny 5 " = "
        set_conf_kv /etc/security/faillock.conf unlock_time 900 " = "
        set_conf_kv /etc/security/faillock.conf fail_interval 900 " = "
        run authselect current || true
        local had_faillock=0
        authselect current 2>/dev/null | grep -q 'with-faillock' && had_faillock=1
        if ! run authselect check; then
          warn "authselect reports local PAM/profile changes; not enabling with-faillock automatically."
          restore_task_backup /etc/security/faillock.conf
        elif [[ $had_faillock -eq 1 ]]; then
          ok "authselect with-faillock is already enabled; faillock.conf updated only."
        else
          record_action "AUTHSELECT_FEATURE" "with-faillock"
          if run authselect enable-feature with-faillock && run authselect apply-changes; then
            ok "faillock enabled via authselect with-faillock"
          else
            err "authselect failed to enable/apply with-faillock; attempting to roll back the feature."
            run authselect disable-feature with-faillock || true
            run authselect apply-changes || true
            restore_task_backup /etc/security/faillock.conf
          fi
        fi
      else
        warn "authselect not found; not hand-editing RHEL-family PAM files."
      fi
    elif is_suse; then
      warn "SUSE-family PAM stacks are maintained with pam-config; not enabling pam_faillock automatically."
      if command -v pam-config >/dev/null 2>&1; then
        run pam-config --list-modules || true
        warn "Review pam-config support and test TTY/GUI/sudo from a root/rescue shell before enabling faillock manually."
      else
        warn "pam-config not found; skipped SUSE faillock configuration."
      fi
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
  if [[ ${#protected_users[@]} -eq 0 && "$(id -un 2>/dev/null || true)" == "root" ]]; then
    warn "Running from a root shell with no non-root invoking account detected; skipping root password lock because root is the current operator account."
  elif [[ "$root_state" == "L" ]]; then
    ok "root account password is already locked."
  elif ask_risky "Lock the root account password (passwd -l root). Ensure a sudo-capable user works first; revert.sh can unlock it"; then
    record_action "USER_LOCK" "root"
    if run passwd -l root; then
      ok "root password locked (use 'sudo' for admin tasks)"
    else
      err "Failed to lock root"
    fi
  fi

  # --- RISKY: restrict su to the distro's admin group ---
  local su_pam="/etc/pam.d/su"
  if [[ -f "$su_pam" ]]; then
    if ! pam_module_exists pam_wheel.so; then
      warn "pam_wheel.so not found; cannot safely configure su restriction on this install."
    elif grep -Eq "^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\\.so.*group=${ADMIN_GROUP}([[:space:]]|$)" "$su_pam"; then
      ok "su is already restricted to ${ADMIN_GROUP} via pam_wheel."
    elif ask_risky "Restrict 'su' to members of ${ADMIN_GROUP} via pam_wheel. Outcome: non-admin users cannot su to root. Risk: breaks workflows that rely on su from non-admin accounts; verify sudo/admin access first"; then
      prepare_edit "$su_pam"
      if grep -Eq '^[[:space:]]*#?[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' "$su_pam"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\\.so.*|auth required pam_wheel.so use_uid group=${ADMIN_GROUP}|" "$su_pam"
      else
        printf '%s\n' "auth required pam_wheel.so use_uid group=${ADMIN_GROUP}" >> "$su_pam"
      fi
      ok "su restricted to ${ADMIN_GROUP} in $su_pam"
    fi
  else
    warn "$su_pam not found; su restriction skipped."
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
    local bak="${BACKED_UP[$SSHD_CONFIG]:-$BACKUP_DIR/files/${CURRENT_TASK:-ssh}$SSHD_CONFIG}"
    if [[ -f "$bak" ]]; then
      cp -a "$bak" "$SSHD_CONFIG"
      warn "Restored $SSHD_CONFIG from $bak"
    else
      warn "No SSH task backup found at $bak; inspect $SSHD_CONFIG manually before restarting sshd."
    fi
    return 1
  fi
}

sshd_effective_value() {
  local key="${1,,}"
  sshd -T -f "$SSHD_CONFIG" 2>/dev/null | awk -v key="$key" '$1 == key {print $2; exit}'
}

ssh_user_home() {
  getent passwd "$1" 2>/dev/null | awk -F: '{print $6}'
}

ssh_authorized_keys_file() {
  local home
  home="$(ssh_user_home "$1")"
  [[ -n "$home" ]] && printf '%s/.ssh/authorized_keys\n' "$home"
}

ssh_user_has_authorized_key() {
  local ak
  ak="$(ssh_authorized_keys_file "$1")"
  [[ -f "$ak" ]] || return 1
  grep -Eq '^[[:space:]]*(sk-ssh-ed25519|sk-ecdsa-sha2-nistp256|ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|rsa-sha2-512|rsa-sha2-256|ssh-rsa)[[:space:]]+' "$ak"
}

ssh_audit_user_authorized_keys() {
  local user="$1" home sshdir ak key_count
  home="$(ssh_user_home "$user")"
  if [[ -z "$home" ]]; then
    warn "SSH key audit: user '$user' does not exist."
    return 1
  fi
  sshdir="$home/.ssh"
  ak="$sshdir/authorized_keys"
  info "SSH key audit for $user:"
  if [[ -d "$home" ]]; then
    info "home: $home ($(stat -c '%a %U:%G' "$home" 2>/dev/null || echo 'permissions unknown'))"
  else
    warn "home directory missing: $home"
  fi
  if [[ -d "$sshdir" ]]; then
    info ".ssh: $sshdir ($(stat -c '%a %U:%G' "$sshdir" 2>/dev/null || echo 'permissions unknown'))"
  else
    warn ".ssh directory missing: $sshdir"
  fi
  if [[ -f "$ak" ]]; then
    key_count="$(grep -Ec '^[[:space:]]*(sk-ssh-ed25519|sk-ecdsa-sha2-nistp256|ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|rsa-sha2-512|rsa-sha2-256|ssh-rsa)[[:space:]]+' "$ak" 2>/dev/null || echo 0)"
    info "authorized_keys: $ak ($(stat -c '%a %U:%G' "$ak" 2>/dev/null || echo 'permissions unknown'), valid-looking keys: $key_count)"
    [[ "$key_count" -gt 0 ]] && return 0
  else
    warn "authorized_keys missing: $ak"
  fi
  return 1
}

ssh_repair_authorized_key_permissions() {
  local user="$1" home sshdir ak group
  home="$(ssh_user_home "$user")"
  [[ -n "$home" && -d "$home" ]] || return 1
  sshdir="$home/.ssh"
  ak="$sshdir/authorized_keys"
  group="$(id -gn "$user" 2>/dev/null || echo "$user")"
  if [[ -d "$sshdir" ]]; then record_perm "$sshdir"; else mkdir -p "$sshdir"; fi
  run chown "$user:$group" "$sshdir"
  run chmod 700 "$sshdir"
  [[ -e "$ak" ]] && record_perm "$ak"
  run chown "$user:$group" "$ak"
  run chmod 600 "$ak"
}

ssh_generate_key_for_user() {
  local user="$1" home sshdir ak group keydir priv pub comment publine sshdir_existed=0 ak_existed=0
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    warn "ssh-keygen not found; cannot generate an SSH key."
    return 1
  fi
  home="$(ssh_user_home "$user")"
  if [[ -z "$home" || ! -d "$home" ]]; then
    warn "Cannot generate SSH key for $user because its home directory is missing."
    return 1
  fi
  sshdir="$home/.ssh"
  ak="$sshdir/authorized_keys"
  [[ -d "$sshdir" ]] && sshdir_existed=1
  [[ -e "$ak" ]] && ak_existed=1
  group="$(id -gn "$user" 2>/dev/null || echo "$user")"
  keydir="$RUN_DIR/ssh-keys"
  mkdir -p "$keydir"
  chmod 700 "$keydir"
  priv="$keydir/${user}_ed25519"
  pub="$priv.pub"
  comment="harden-${user}@$(hostname 2>/dev/null || echo linux)-${TS}"
  if run ssh-keygen -q -t ed25519 -N "" -C "$comment" -f "$priv"; then
    chmod 600 "$priv"
    chmod 644 "$pub"
  else
    warn "ssh-keygen failed for $user."
    return 1
  fi
  prepare_edit "$ak"
  [[ $sshdir_existed -eq 1 ]] && record_perm "$sshdir"
  [[ $ak_existed -eq 1 ]] && record_perm "$ak"
  [[ -d "$sshdir" ]] || mkdir -p "$sshdir"
  [[ -e "$ak" ]] || : > "$ak"
  publine="$(sed -n '1p' "$pub")"
  grep -Fxq "$publine" "$ak" 2>/dev/null || printf '%s\n' "$publine" >> "$ak"
  chown "$user:$group" "$sshdir" "$ak"
  chmod 700 "$sshdir"
  chmod 600 "$ak"
  ok "Generated SSH key for $user and installed its public key in $ak"
  info "Public key: $publine"
  warn "Private key saved root-only at $priv. Copy it securely to your SSH client."
  if confirm "Display the generated PRIVATE key now? Outcome: you can copy it into an SSH client. Risk: it will also be saved in this transcript at $OUTPUT_LOG"; then
    sed 's/^/    /' "$priv"
  fi
}

ensure_operator_ssh_key() {
  local user="$1"
  if [[ -z "$user" ]]; then
    warn "No protected invoking/session account detected; refusing to prepare key-only SSH."
    return 1
  fi
  if ssh_audit_user_authorized_keys "$user"; then
    ssh_repair_authorized_key_permissions "$user"
    ok "$user has at least one valid-looking SSH public key."
    return 0
  fi
  if confirm "Generate and install an ed25519 SSH key for $user? Outcome: public key is added to authorized_keys and private key is saved under $RUN_DIR. Risk: generated private key must be copied securely before relying on key-only SSH"; then
    ssh_generate_key_for_user "$user"
  else
    warn "No usable SSH key was confirmed for $user."
    return 1
  fi
}

configure_ssh_authentication_mode() {
  local -a protected_users=("$@")
  local operator="${protected_users[0]:-}"
  local pass kbd pubkey choice
  pass="$(sshd_effective_value PasswordAuthentication)"; pass="${pass:-unknown}"
  kbd="$(sshd_effective_value KbdInteractiveAuthentication)"; kbd="${kbd:-unknown}"
  pubkey="$(sshd_effective_value PubkeyAuthentication)"; pubkey="${pubkey:-unknown}"
  info "Current SSH auth audit: PubkeyAuthentication=$pubkey PasswordAuthentication=$pass KbdInteractiveAuthentication=$kbd"
  if [[ -n "$operator" ]]; then
    ssh_audit_user_authorized_keys "$operator" || true
  else
    warn "No current non-root operator account detected for SSH key audit."
  fi

  echo "    SSH authentication options:"
  echo "      1) Key-only login: enable keys, disable password and keyboard-interactive auth"
  echo "      2) Key + password login: enable both key and password auth"
  echo "      3) Password-only login: enable password auth and disable key auth"
  echo "      4) Audit key login only; leave password-auth setting intact"
  echo "      5) Audit password-auth setting only; leave key setting intact"
  echo "      6) Do nothing"
  read -r -p "    Choose SSH authentication behavior [6]: " choice
  choice="${choice:-6}"

  case "$choice" in
    1)
      if ensure_operator_ssh_key "$operator"; then
        set_ssh PubkeyAuthentication yes
        set_ssh AuthorizedKeysFile ".ssh/authorized_keys"
        set_ssh PasswordAuthentication no
        set_ssh KbdInteractiveAuthentication no
        ok "SSH authentication set to key-only."
      else
        warn "Key-only SSH skipped; password-login settings left intact."
      fi
      ;;
    2)
      if [[ -n "$operator" ]] && ! ssh_user_has_authorized_key "$operator"; then
        ensure_operator_ssh_key "$operator" || warn "Continuing with password auth enabled; key login may not be usable for $operator."
      elif [[ -n "$operator" ]]; then
        ssh_repair_authorized_key_permissions "$operator"
      fi
      set_ssh PubkeyAuthentication yes
      set_ssh AuthorizedKeysFile ".ssh/authorized_keys"
      set_ssh PasswordAuthentication yes
      set_ssh KbdInteractiveAuthentication yes
      ok "SSH authentication set to allow both key and password login."
      ;;
    3)
      set_ssh PasswordAuthentication yes
      set_ssh KbdInteractiveAuthentication yes
      set_ssh PubkeyAuthentication no
      ok "SSH authentication set to password-only."
      ;;
    4)
      if [[ -n "$operator" ]]; then
        ssh_audit_user_authorized_keys "$operator" || true
      else
        warn "No current non-root operator account detected for key audit."
      fi
      ;;
    5)
      info "Password-auth audit only: PasswordAuthentication=$pass KbdInteractiveAuthentication=$kbd"
      ;;
    6)
      info "SSH authentication mode left unchanged."
      ;;
    *)
      warn "Invalid SSH auth option '$choice'; leaving authentication mode unchanged."
      ;;
  esac
}

sec_ssh() {
  start_task "ssh" "SSH Hardening"
  require_supported_write "SSH Hardening" || { end_task; return; }
  require_systemd_task "SSH Hardening" || { end_task; return; }
  if [[ ! -f "$SSHD_CONFIG" ]]; then warn "$SSHD_CONFIG not found; is OpenSSH installed?"; end_task; return; fi
  prepare_edit "$SSHD_CONFIG"
  local -a protected_users=()
  mapfile -t protected_users < <(detect_invoking_human_accounts)

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

  if confirm "Set local and SSH warning banners? Outcome: displays 'authorized use only' notice before local/SSH login. Risk: replaces existing /etc/issue and /etc/issue.net banners"; then
    local banner_text="Authorized use only. Activity may be monitored and reported."
    prepare_edit /etc/issue
    printf '%s\n' "$banner_text" > /etc/issue
    prepare_edit /etc/issue.net
    printf '%s\n' "$banner_text" > /etc/issue.net
    set_ssh Banner /etc/issue.net
    ok "Login banners configured in /etc/issue, /etc/issue.net, and sshd_config."
  fi

  if ask_risky "Restrict SSH Kex/Ciphers/MACs to modern algorithms. Outcome: disables weak SSH crypto. Risk: legacy SSH clients may fail to connect"; then
    set_ssh KexAlgorithms "curve25519-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512"
    set_ssh Ciphers "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    set_ssh MACs "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
    ok "Modern SSH Kex/Ciphers/MACs configured; sshd -t will validate before restart."
  fi

  log "SSH host key audit:"
  local -a weak_hostkeys=()
  if compgen -G "/etc/ssh/ssh_host_*_key.pub" >/dev/null; then
    local hk hk_info hk_bits
    for hk in /etc/ssh/ssh_host_*_key.pub; do
      run ssh-keygen -l -f "$hk" || true
      hk_info="$(ssh-keygen -l -f "$hk" 2>/dev/null || true)"
      hk_bits="${hk_info%% *}"
      case "$hk" in
        *_dsa_key.pub)
          weak_hostkeys+=("$hk")
          ;;
        *_rsa_key.pub)
          if [[ "$hk_bits" =~ ^[0-9]+$ && "$hk_bits" -lt 2048 ]]; then
            weak_hostkeys+=("$hk")
          fi
          ;;
      esac
    done
  else
    warn "No SSH host public keys found under /etc/ssh."
  fi
  if [[ ${#weak_hostkeys[@]} -gt 0 ]]; then
    warn "Weak SSH host public keys detected: ${weak_hostkeys[*]}"
    if ask_risky "Remove DSA or RSA<2048 SSH host keys and ensure an Ed25519 host key exists. Outcome: removes weak server identity keys. Risk: clients may need known_hosts updates if host keys change"; then
      local pub base ed_key=/etc/ssh/ssh_host_ed25519_key ed_pub=/etc/ssh/ssh_host_ed25519_key.pub
      for pub in "${weak_hostkeys[@]}"; do
        base="${pub%.pub}"
        [[ -e "$base" ]] && prepare_edit "$base"
        [[ -e "$pub" ]] && prepare_edit "$pub"
        run rm -f "$base" "$pub"
        ok "Removed weak SSH host key pair for $base"
      done
      if [[ ! -f "$ed_pub" ]]; then
        if [[ -f "$ed_key" ]]; then
          prepare_edit "$ed_pub"
          echo "    + ssh-keygen -y -f $ed_key > $ed_pub"
          if ssh-keygen -y -f "$ed_key" > "$ed_pub"; then
            run chmod 644 "$ed_pub"
            ok "Regenerated missing Ed25519 SSH host public key."
          else
            run rm -f "$ed_pub"
            warn "Could not regenerate $ed_pub from $ed_key; inspect SSH host keys before restarting sshd."
          fi
        else
          prepare_edit "$ed_key"
          prepare_edit "$ed_pub"
          if run ssh-keygen -q -t ed25519 -N "" -f "$ed_key"; then
            run chmod 600 "$ed_key"
            run chmod 644 "$ed_pub"
            ok "Generated Ed25519 SSH host key pair."
          else
            run rm -f "$ed_key" "$ed_pub"
            warn "Failed to generate Ed25519 SSH host key pair; inspect /etc/ssh before restarting sshd."
          fi
        fi
      fi
    else
      info "Weak SSH host key cleanup skipped by user."
    fi
  else
    ok "No DSA or RSA<2048 SSH host public keys detected."
  fi

  # NOTE: 'Protocol 2' is intentionally NOT written — it is removed/deprecated
  # on OpenSSH >= 7.6 and would make 'sshd -t' fail. Protocol 1 no longer exists.

  # --- authentication mode selection ---
  configure_ssh_authentication_mode "${protected_users[@]}"

  # --- RISKY: change SSH port to 2222 ---
  if ask_risky "Change SSH port from 22 to 2222 (firewall + any external configs must match; may lose points if scoring expects 22)"; then
    set_ssh Port 2222
    record_action "NOTE" "ssh_port_changed_to_2222"
    SSH_PORT_CHANGED=2222
  fi

  # --- RISKY: restrict to an admin group ---
  if ask_risky "Restrict SSH logins to members of group 'sshusers' (AllowGroups sshusers). Users not added to this group lose SSH access"; then
    local pu protected_missing=0 sshusers_exists=0
    local -a protected_to_add=()
    getent group sshusers >/dev/null && sshusers_exists=1
    if [[ ${#protected_users[@]} -eq 0 ]]; then
      warn "No protected invoking/session account detected; skipping AllowGroups sshusers to avoid blocking the current operator."
      restart_sshd_safe; end_task; return
    fi
    for pu in "${protected_users[@]}"; do
      if [[ $sshusers_exists -eq 0 ]] || ! id -nG "$pu" 2>/dev/null | tr ' ' '\n' | grep -qx sshusers; then
        protected_to_add+=("$pu")
      fi
    done
    if [[ ${#protected_to_add[@]} -gt 0 ]]; then
      warn "Protected invoking/session account(s) not in sshusers: ${protected_to_add[*]}"
      if confirm "Add protected account(s) to sshusers before enabling AllowGroups? Outcome: preserves SSH access for the current operator. Risk: modifies current user group membership and may require a new login for local shells to show it"; then
        if [[ $sshusers_exists -eq 0 ]]; then
          record_action "GROUP_CREATE" "sshusers"
          run groupadd sshusers && sshusers_exists=1 || protected_missing=1
        fi
        if [[ $sshusers_exists -eq 1 ]]; then
          for pu in "${protected_to_add[@]}"; do
            record_action "GROUP_MEMBER_ADD" "$pu" "sshusers"
            run usermod -aG sshusers "$pu" || protected_missing=1
          done
        fi
      else
        protected_missing=1
      fi
    fi
    if [[ $protected_missing -eq 1 ]]; then
      warn "Skipping AllowGroups sshusers because protected operator account(s) were not added to sshusers; this avoids blocking current SSH access."
      restart_sshd_safe; end_task; return
    fi
    # add authorized sudoers (best-effort) so they keep access
    if [[ -r "$AUTH_FILE" ]]; then
      parse_authorized
      local u
      for u in "${AUTH_SUDO[@]}"; do
        getent passwd "$u" >/dev/null || continue
        if in_list "$u" "${protected_users[@]}"; then
          warn "Skipping sshusers group change for protected invoking/session account '$u'."
          continue
        fi
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
# SECTION 13 — Firewall (UFW on Debian, firewalld on RHEL/SUSE)
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
    if [[ -f /etc/default/ufw ]] && grep -qiE '^[[:space:]]*IPV6[[:space:]]*=[[:space:]]*no' /etc/default/ufw; then
      warn "UFW IPv6 support is disabled in /etc/default/ufw; IPv6 traffic may bypass expected UFW policy if IPv6 is enabled."
      if confirm "Set UFW IPV6=yes before enabling/reloading? Outcome: UFW manages IPv6 rules too. Risk: existing IPv6 service exposure may change"; then
        set_conf_kv /etc/default/ufw IPV6 yes "="
      fi
    else
      ok "UFW IPv6 support is not explicitly disabled."
    fi
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

  elif is_rhel || is_suse; then
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
sysctl_proc_path() {
  local key="$1"
  printf '/proc/sys/%s\n' "${key//./\/}"
}

append_sysctl_if_supported() {
  local file="$1" key="$2" val="$3" path
  path="$(sysctl_proc_path "$key")"
  if [[ -e "$path" ]]; then
    printf '%s = %s\n' "$key" "$val" >> "$file"
    return 0
  fi
  info "Skipping unsupported sysctl $key (no $path)"
  return 1
}

grub_password_tool() {
  if command -v grub-mkpasswd-pbkdf2 >/dev/null 2>&1; then
    command -v grub-mkpasswd-pbkdf2
  elif command -v grub2-mkpasswd-pbkdf2 >/dev/null 2>&1; then
    command -v grub2-mkpasswd-pbkdf2
  fi
}

grub_mkconfig_cmd() {
  if command -v update-grub >/dev/null 2>&1; then
    printf 'update-grub\n'
  elif command -v grub2-mkconfig >/dev/null 2>&1; then
    printf 'grub2-mkconfig\n'
  elif command -v grub-mkconfig >/dev/null 2>&1; then
    printf 'grub-mkconfig\n'
  fi
}

grub_cfg_output_path() {
  local p
  for p in /boot/grub2/grub.cfg /boot/grub/grub.cfg; do
    [[ -e "$p" ]] && { printf '%s\n' "$p"; return 0; }
  done
  if is_rhel || is_suse; then
    printf '/boot/grub2/grub.cfg'
  else
    printf '/boot/grub/grub.cfg'
  fi
}

configure_grub_password() {
  if ! ask_risky "Set a GRUB bootloader superuser password. Outcome: blocks unauthenticated GRUB edit/rescue shell access. Risk: losing the password can block emergency boot edits; generated password will be displayed and saved"; then
    return 0
  fi
  local tool mkconfig out cfg user pw hash tmp
  tool="$(grub_password_tool || true)"
  mkconfig="$(grub_mkconfig_cmd || true)"
  if [[ -z "$tool" ]]; then
    warn "No grub-mkpasswd-pbkdf2/grub2-mkpasswd-pbkdf2 found; GRUB password skipped."
    return 1
  fi
  if [[ -z "$mkconfig" ]]; then
    warn "No update-grub/grub*-mkconfig command found; GRUB password skipped."
    return 1
  fi
  if ! pw="$(gen_password)"; then
    warn "Could not generate GRUB password; skipped."
    return 1
  fi
  hash="$(printf '%s\n%s\n' "$pw" "$pw" | "$tool" 2>/dev/null | awk '/grub\.pbkdf2/ {print $NF; exit}')"
  if [[ -z "$hash" ]]; then
    warn "GRUB password hash generation failed; skipped."
    return 1
  fi
  user="hardenadmin"
  cfg=/etc/grub.d/40_custom
  prepare_edit "$cfg"
  tmp="$(mktemp)" || return 1
  sed '/^# BEGIN harden.sh GRUB password$/,/^# END harden.sh GRUB password$/d' "$cfg" > "$tmp" 2>/dev/null || : > "$tmp"
  cat >> "$tmp" <<EOF
# BEGIN harden.sh GRUB password
set superusers="${user}"
password_pbkdf2 ${user} ${hash}
# END harden.sh GRUB password
EOF
  cat "$tmp" > "$cfg"
  rm -f "$tmp"
  run chmod 755 "$cfg"
  save_credential_line "$(printf '%-20s USER=%s NEW=%s HASH=%s' "GRUB_BOOTLOADER" "$user" "$pw" "$hash")"
  ok "GRUB bootloader password set for user '$user'. Password: $pw"
  ok "GRUB password saved to $CREDS_FILE and $EASY_CREDS_FILE"
  if [[ "$mkconfig" == "update-grub" ]]; then
    run update-grub
  else
    out="$(grub_cfg_output_path)"
    run "$mkconfig" -o "$out"
  fi
}

configure_module_blacklist() {
  if ! ask_risky "Blacklist uncommon filesystems and USB mass storage. Outcome: reduces kernel attack surface. Risk: USB drives or uncommon filesystem mounts may stop working after reboot"; then
    return 0
  fi
  local f=/etc/modprobe.d/99-hardening-blacklist.conf
  prepare_edit "$f"
  cat > "$f" <<'EOF'
# Managed by harden.sh
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install usb-storage /bin/true
EOF
  ok "Kernel module blacklist written to $f (takes effect for future module loads/reboot)."
}

sec_kernel() {
  start_task "kernel" "Kernel / sysctl Hardening"
  require_supported_write "Kernel / sysctl Hardening" || { end_task; return; }
  local f="/etc/sysctl.d/99-hardening.conf"
  prepare_edit "$f"
  log "Boot/Secure Boot status (read-only)"
  if command -v mokutil >/dev/null 2>&1; then
    run mokutil --sb-state || true
  elif command -v bootctl >/dev/null 2>&1; then
    run bootctl status || true
  else
    warn "mokutil/bootctl not found; Secure Boot status check skipped."
  fi
  log "Writing $f"
  cat > "$f" <<'EOF'
# Managed by harden.sh
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.perf_event_paranoid = 2
kernel.sysrq = 0
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
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
  append_sysctl_if_supported "$f" kernel.unprivileged_userns_clone 0 || true
  append_sysctl_if_supported "$f" kernel.unprivileged_bpf_disabled 1 || true
  append_sysctl_if_supported "$f" net.core.bpf_jit_harden 2 || true
  append_sysctl_if_supported "$f" net.ipv6.conf.all.use_tempaddr 2 || true
  append_sysctl_if_supported "$f" net.ipv6.conf.default.use_tempaddr 2 || true
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

  if confirm "Disable core dumps through limits/profile settings? Outcome: reduces leakage of passwords/keys in crash dumps. Risk: makes debugging crashes harder"; then
    local limits_file=/etc/security/limits.d/99-hardening-coredumps.conf profile_file=/etc/profile.d/99-disable-coredumps.sh
    prepare_edit "$limits_file"
    printf '* hard core 0\n* soft core 0\n' > "$limits_file"
    run chmod 644 "$limits_file"
    prepare_edit "$profile_file"
    printf 'ulimit -c 0\n' > "$profile_file"
    run chmod 644 "$profile_file"
    ok "Core dump limits configured."
  fi

  configure_module_blacklist
  configure_grub_password

  if is_rhel && command -v update-crypto-policies >/dev/null 2>&1 && \
     ask_risky "Set system crypto policy to DEFAULT:NO-SHA1. Outcome: blocks SHA-1 in supported TLS/crypto stacks. Risk: legacy clients/services may fail TLS or package validation"; then
    run update-crypto-policies --show || true
    record_action "NOTE" "crypto_policy_set_DEFAULT_NO_SHA1_not_revertible"
    run update-crypto-policies --set DEFAULT:NO-SHA1
    ok "System crypto policy set to DEFAULT:NO-SHA1."
  fi

  local sysctl_log="$BACKUP_DIR/sysctl-apply.log"
  echo "    + sysctl --system"
  if sysctl --system >"$sysctl_log" 2>&1; then
    ok "sysctl --system completed"
  else
    warn "sysctl --system returned nonzero; review $sysctl_log"
  fi
  cat "$sysctl_log"
  if grep -Eiq 'error|invalid|cannot stat|No such file|permission denied|unknown key' "$sysctl_log" 2>/dev/null; then
    warn "sysctl apply warnings/errors detected; review $sysctl_log and remove unsupported keys before rerunning."
  else
    ok "sysctl settings applied without obvious errors"
  fi
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
  local bak="${BACKED_UP[$f]:-}"
  if [[ -n "$bak" && -f "$bak" ]]; then
    cp -a "$bak" "$f"
  elif [[ -n "${CREATED[$f]:-}" && -e "$f" ]]; then
    rm -f "$f"
  else
    warn "No task-local backup recorded for $f; cannot automatically restore this staged edit."
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
  for f in /etc/apache2/apache2.conf /etc/apache2/httpd.conf /etc/httpd/conf/httpd.conf; do
    [[ -f "$f" ]] && { echo "$f"; return 0; }
  done
  if is_debian; then
    echo /etc/apache2/apache2.conf
  elif is_suse; then
    echo /etc/apache2/httpd.conf
  else
    echo /etc/httpd/conf/httpd.conf
  fi
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
     [[ ! -f /etc/apache2/apache2.conf && ! -f /etc/apache2/httpd.conf && ! -f /etc/httpd/conf/httpd.conf ]]; then
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

secure_apache_modsecurity() {
  if ! pkg_installed apache2 && ! pkg_installed httpd && ! command -v apache2ctl >/dev/null 2>&1 && ! command -v httpd >/dev/null 2>&1; then
    ok "Apache/httpd not detected; ModSecurity setup skipped."
    return 0
  fi

  local c svc
  if is_debian; then
    if ! pkg_install_tracked libapache2-mod-security2; then
      warn "libapache2-mod-security2 unavailable; ModSecurity setup skipped."
      return 0
    fi
  elif is_suse; then
    if ! pkg_install_any_tracked apache2-mod_security2 mod_security2 mod_security; then
      warn "SUSE ModSecurity package unavailable; ModSecurity setup skipped."
      return 0
    fi
  else
    if ! pkg_install_tracked mod_security; then
      warn "mod_security unavailable; ModSecurity setup skipped."
      return 0
    fi
  fi

  if { is_debian || is_suse; } && command -v a2enmod >/dev/null 2>&1; then
    run a2enmod security2
    record_action "NOTE" "apache_modsecurity_module_enabled"
  elif is_suse; then
    warn "a2enmod not found; relying on SUSE Apache module packaging/config includes."
  fi

  if is_suse && [[ ! -d /etc/apache2/conf.d ]]; then
    warn "/etc/apache2/conf.d not found; ModSecurity setup skipped."
    return 0
  fi

  if is_debian; then
    if [[ ! -f /etc/modsecurity/modsecurity.conf && -f /etc/modsecurity/modsecurity.conf-recommended ]]; then
      prepare_edit /etc/modsecurity/modsecurity.conf
      run cp -a /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
    fi
    if [[ -f /etc/modsecurity/modsecurity.conf ]]; then
      c=/etc/modsecurity/modsecurity.conf
      prepare_edit "$c"
      set_conf_kv "$c" SecRuleEngine DetectionOnly " "
    else
      c=/etc/apache2/conf-enabled/99-modsecurity-detectiononly.conf
      prepare_edit "$c"
      {
        echo "# Managed by harden.sh"
        echo "<IfModule security2_module>"
        echo "    SecRuleEngine DetectionOnly"
        echo "</IfModule>"
      } > "$c"
    fi
  elif is_suse; then
    c=/etc/apache2/conf.d/99-modsecurity-detectiononly.conf
    prepare_edit "$c"
    {
      echo "# Managed by harden.sh"
      echo "<IfModule security2_module>"
      echo "    SecRuleEngine DetectionOnly"
      echo "</IfModule>"
    } > "$c"
  else
    c=/etc/httpd/conf.d/99-modsecurity-detectiononly.conf
    prepare_edit "$c"
    {
      echo "# Managed by harden.sh"
      echo "<IfModule security2_module>"
      echo "    SecRuleEngine DetectionOnly"
      echo "</IfModule>"
    } > "$c"
  fi

  if validate_apache_config; then
    svc="$(apache_service_name)"
    restart_service_if_present "$svc" || { err "$svc restart failed; restoring ModSecurity config."; restore_task_backup "$c"; restart_service_untracked_if_present "$svc"; return 1; }
    ok "ModSecurity enabled/requested in DetectionOnly mode"
  else
    err "Apache validation failed after ModSecurity setup; restoring staged config."
    restore_task_backup "$c"
    validate_apache_config || true
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

set_ntp_restrict_default() {
  local f="$1" line="restrict default kod nomodify nopeer noquery limited"
  if grep -qE '^[[:space:]]*restrict[[:space:]]+default([[:space:]]|$)' "$f" 2>/dev/null; then
    sed -i -E "s#^[[:space:]]*restrict[[:space:]]+default.*#${line}#" "$f"
  else
    printf '%s\n' "$line" >> "$f"
  fi
}

secure_time_sync_config() {
  local f changed_ntp=0 changed_chrony=0
  local -a ntp_files=() chrony_files=()
  [[ -f /etc/ntp.conf ]] && ntp_files+=("/etc/ntp.conf")
  for f in /etc/chrony.conf /etc/chrony/chrony.conf; do
    [[ -f "$f" ]] && chrony_files+=("$f")
  done

  if [[ ${#ntp_files[@]} -eq 0 && ${#chrony_files[@]} -eq 0 ]]; then
    ok "No ntpd/chrony config files found; time sync hardening skipped."
    return 0
  fi

  if [[ ${#ntp_files[@]} -gt 0 ]] && \
     ask_risky "Apply client-safe ntpd restrictions. Outcome: blocks NTP control/peer queries by default. Risk: breaks this VM if it must serve NTP clients/peers"; then
    for f in "${ntp_files[@]}"; do
      prepare_edit "$f"
      set_ntp_restrict_default "$f"
      ok "Updated ntpd default restrictions in $f"
    done
    changed_ntp=1
  elif [[ ${#ntp_files[@]} -gt 0 ]]; then
    info "ntpd restriction hardening skipped."
  fi

  if [[ ${#chrony_files[@]} -gt 0 ]] && \
     ask_risky "Disable chrony NTP serving and network command ports (port 0, cmdport 0). Outcome: client-only time sync. Risk: breaks this VM if it must serve NTP clients"; then
    for f in "${chrony_files[@]}"; do
      prepare_edit "$f"
      set_conf_kv "$f" port 0 " "
      set_conf_kv "$f" cmdport 0 " "
      ok "Updated chrony client-only settings in $f"
    done
    changed_chrony=1
  elif [[ ${#chrony_files[@]} -gt 0 ]]; then
    info "chrony client-only hardening skipped."
  fi

  if [[ $changed_ntp -eq 1 ]]; then
    restart_service_if_present ntp
    restart_service_if_present ntpd
  fi
  if [[ $changed_chrony -eq 1 ]]; then
    restart_service_if_present chrony
    restart_service_if_present chronyd
  fi
}

secure_tcp_wrappers_config() {
  if ! ask_risky "Configure legacy TCP Wrappers deny-all default. Outcome: libwrap-linked services are denied unless allowed in /etc/hosts.allow. Risk: can block older SSH/FTP/xinetd services; verify required allow rules first"; then
    info "TCP Wrappers deny-all hardening skipped."
    return 0
  fi

  local allow=/etc/hosts.allow deny=/etc/hosts.deny
  warn "No hosts.allow entries are guessed here; add authorized source rules manually when a legacy libwrap-linked service must remain reachable."
  prepare_edit "$allow"
  if [[ ! -s "$allow" ]]; then
    {
      echo "# Managed by harden.sh"
      echo "# Add explicit legacy TCP Wrappers allow rules above /etc/hosts.deny's ALL: ALL when required."
    } > "$allow"
  fi
  prepare_edit "$deny"
  if ! grep -qE '^[[:space:]]*ALL[[:space:]]*:[[:space:]]*ALL([[:space:]]|$)' "$deny" 2>/dev/null; then
    printf 'ALL: ALL\n' >> "$deny"
  fi
  run chmod 644 "$allow" "$deny"
  ok "Legacy TCP Wrappers deny-all default configured in $deny."
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
  elif is_suse; then c=/etc/apache2/conf.d/99-harden-security.conf
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

  if [[ $headers -eq 1 ]] && { is_debian || is_suse; } && command -v a2enmod >/dev/null 2>&1; then
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
    [[ $disable_funcs -eq 1 ]] && set_conf_kv "$f" disable_functions "exec,passthru,shell_exec,system,proc_open,popen,assert,pcntl_exec,pcntl_fork,dl" " = "
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
  local mega_bad_tokens=(aircrack-ng airmon-ng beef beef-xss burp-suite burpsuite \
    ettercap ettercap-common ettercap-graphical fcrackzip hashcat hydra hydra-gtk \
    irpas ipscan john john-data johnny kismet lcrack logkeys maltego medusa \
    metasploit metasploit-framework msfvenom nessus nikto nmap oclhashcat ophcrack \
    ophcrack-cli pdfcrack proxychains proxychains4 pyrit rarcrack reaver sbd set \
    setoolkit sipcrack sqlmap truecrack yersinia zaproxy zenmap)
  # BAD: insecure remote-access daemons, reverse-shell helpers, sniffers, and P2P/games.
  local bad_tokens=(cryptcat netcat netcat-openbsd netcat-traditional ncat socat tcpdump \
    nc pnetcat sock socket rlogind rshd rcmd rexecd rbootd rquotad rstatd rusersd rwalld rexd \
    telnet telnetd telnetd-ssl inetd openbsd-inetd xinetd \
    inetutils-ftp inetutils-ftpd inetutils-inetd inetutils-syslogd \
    inetutils-talk inetutils-talkd inetutils-telnet inetutils-telnetd \
    rsh-server rsh rsh-client rsh-redone-server rsh-redone-client rlinetd \
    tightvnc tightvnc-common tightvncserver vncserver x11vnc tigervnc-server xrdp \
    proftpd-basic proftpd pure-ftpd ftp tnftp sftpd tftpd-hpa tftp-server tftpd atftpd \
    autofs nfs-common nfs-kernel-server nfs-utils nis portmap rpcbind ypbind ypserv \
    snmpd net-snmp talkd ntalk talk pop3 \
    dovecot-pop3d courier-pop \
    vnc4server vncsnapshot vtgrab wireshark wireshark-common wireshark-qt tor \
    torbrowser-launcher deluge vuze frostwire aisleriot five-or-more four-in-a-row \
    freeciv gnome-2048 gnome-chess gnome-games gnome-klotski gnome-mahjongg \
    gnome-mines gnome-nibbles gnome-robots gnome-sudoku gnome-taquin gnome-tetravex \
    hitori iagno lightsoff minetest minetest-server pegsolitaire quadrapassel sl \
    swell-foop tali wesnoth finger fingerd whoopsie \
    zeitgeist zeitgeist-core zeitgeist-datahub python-zeitgeist rhythmbox-plugin-zeitgeist)
  # POSSIBLY-BAD: legitimate services that may be required by the readme.
  local maybe_tokens=(samba samba-common samba-common-bin samba4 postgresql postgresql-server \
    apache apache2 httpd nginx nginx-common lighttpd mysql mysql-client-5.5 mysql-client-5.6 \
    mysql-client-core-5.5 mysql-client-core-5.6 mysql-common-5.5 mysql-common-5.6 \
    mysql-server mysql-server-5.5 mysql-server-5.6 mysql-server-core-5.6 \
    mariadb-server php php-fpm libapache2-mod-php bind bind9 named vsftpd \
    dovecot-core dovecot-imapd sendmail postfix exim4 snmp dnsmasq unbound \
    tomcat tomcat6 tomcat7 tomcat8 tomcat9 tomcat10 php5)

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
  # may depend on PHP and a database. vsftpd is protected here too when it is
  # authorized, because this script has a validated hardening path for it.
  # Protected services should be SECURED instead (see Service Config section).
  local web_stack=(apache apache2 httpd nginx lighttpd php php-fpm libapache2-mod-php \
    mysql-server mariadb-server postgresql postgresql-server bind9 named unbound dnsmasq \
    tomcat tomcat6 tomcat7 tomcat8 tomcat9 tomcat10 vsftpd)
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

  # Optional daemons to disable (not remove): common workstation/remote-access/network daemons.
  local svc_candidates=(cups avahi-daemon rpcbind bluetooth nfs-server nfs-kernel-server \
    xrdp vncserver vino-server whoopsie)
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

  if confirm "Review per-user crontabs and remove selected ones? Outcome: removes user-level scheduled persistence. Risk: can break legitimate user/app jobs"; then
    local cron_users=() cron_user cron_out cron_bak
    while IFS=: read -r cron_user _; do
      cron_out="$(crontab -l -u "$cron_user" 2>/dev/null || true)"
      [[ -n "$cron_out" ]] && cron_users+=("$cron_user")
    done < /etc/passwd
    prompt_selection "per-user crontabs to REMOVE" "${cron_users[@]}"
    for cron_user in "${SELECTED[@]}"; do
      cron_bak="$BACKUP_DIR/crontab-${cron_user}"
      if crontab -l -u "$cron_user" > "$cron_bak" 2>/dev/null; then
        chmod 600 "$cron_bak" 2>/dev/null || true
        record_action "CRONTAB_BACKUP" "$cron_user" "$cron_bak"
        run crontab -u "$cron_user" -r && ok "Removed crontab for $cron_user"
      else
        warn "Could not back up crontab for $cron_user; leaving it unchanged."
      fi
    done
  fi

  if confirm "Restrict cron/at job creation to root only? Outcome: blocks non-root scheduled-job changes. Risk: user/app schedulers may fail"; then
    local access_file
    for access_file in /etc/cron.allow /etc/at.allow; do
      prepare_edit "$access_file"
      printf 'root\n' > "$access_file"
      run chown root:root "$access_file"
      run chmod 400 "$access_file"
    done
    for access_file in /etc/cron.deny /etc/at.deny; do
      if [[ -e "$access_file" ]]; then
        prepare_edit "$access_file"
        run rm -f "$access_file"
      fi
    done
    ok "cron.allow and at.allow restricted to root"
  fi

  if systemctl list-unit-files ctrl-alt-del.target >/dev/null 2>&1 && \
     confirm "Disable Ctrl-Alt-Del reboot on local console? Outcome: blocks key-chord reboot. Risk: removes an emergency console shortcut"; then
    local cad_state
    cad_state="$(systemctl is-enabled ctrl-alt-del.target 2>/dev/null || echo unknown)"
    record_action "CTRL_ALT_DEL_STATE" "$cad_state"
    run systemctl mask ctrl-alt-del.target
    run systemctl daemon-reload
    ok "Ctrl-Alt-Del reboot target masked"
  fi

  log "Listening sockets after changes:"
  run ss -tulpen
  end_task
}

# ============================================================================
# SECTION 16 — Critical service config hardening
# ============================================================================
sec_service_configs() {
  start_task "service_configs" "Service Config Hardening (FTP / Apache / ModSecurity / Nginx / PHP / DNS / Time)"
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
  if confirm "Install/enable Apache ModSecurity in DetectionOnly mode if Apache is present? Outcome: logs WAF matches without blocking the web app. Risk: installs an Apache module and can be noisy; do not switch to blocking mode until the scored app is tested"; then
    secure_apache_modsecurity
  else
    info "Apache ModSecurity setup skipped by user."
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
  secure_time_sync_config
  secure_tcp_wrappers_config
  # Always surface DB advice (read-only; never purges a scored database).
  secure_database_advice
  end_task
}

harden_runtime_temp_mount_options() {
  if ! command -v findmnt >/dev/null 2>&1 || ! command -v mount >/dev/null 2>&1; then
    warn "findmnt/mount not available; temp mount option hardening skipped."
    return 0
  fi
  if ! ask_risky "Remount separate /tmp, /var/tmp, and /dev/shm with noexec,nosuid,nodev for this boot. Outcome: blocks execution/setuid/device files on temp mounts. Risk: apps that execute from temp paths can break; persistent fstab/systemd changes are not guessed"; then
    return 0
  fi

  local target actual current opt opt_csv
  local -a missing_opts=()
  for target in /tmp /var/tmp /dev/shm; do
    [[ -d "$target" ]] || { info "$target is absent; skipping."; continue; }
    actual="$(findmnt -n -T "$target" -o TARGET 2>/dev/null | head -n 1 || true)"
    if [[ -z "$actual" ]]; then
      warn "Could not determine mountpoint for $target; skipping."
      continue
    fi
    if [[ "$actual" != "$target" ]]; then
      warn "$target is backed by parent mount $actual; skipping remount to avoid applying noexec/nosuid/nodev to a broader filesystem."
      continue
    fi
    current="$(findmnt -n -T "$target" -o OPTIONS 2>/dev/null | head -n 1 || true)"
    missing_opts=()
    for opt in noexec nosuid nodev; do
      [[ ",$current," == *",$opt,"* ]] || missing_opts+=("$opt")
    done
    if [[ ${#missing_opts[@]} -eq 0 ]]; then
      ok "$target already has noexec,nosuid,nodev."
      continue
    fi
    opt_csv="$(IFS=,; printf '%s' "${missing_opts[*]}")"
    record_action "NOTE" "runtime_remount_${target}_${opt_csv}_not_revertible"
    if run mount -o "remount,${opt_csv}" "$target"; then
      ok "Runtime remount applied to $target: $opt_csv"
    else
      warn "Runtime remount failed for $target; review current mount options manually."
    fi
  done
}

repair_world_writable_sticky_bits() {
  local d mp
  local -a sticky_missing=()
  while IFS= read -r d; do
    sticky_missing+=("$d")
  done < <(
    while IFS= read -r mp; do
      [[ -d "$mp" ]] || continue
      find "$mp" -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null
    done < <(df --local -P 2>/dev/null | awk 'NR>1 {print $6}') | sort -u | head -200
  )

  if [[ ${#sticky_missing[@]} -eq 0 ]]; then
    ok "No world-writable directories missing sticky bit found on local filesystems."
    return 0
  fi
  warn "Sticky bit repair outcome: prevents users from deleting/renaming each other's files in shared writable directories."
  warn "Sticky bit repair risk: unusual collaboration directories may intentionally allow that behavior; verify selected paths."
  prompt_selection "world-writable directories missing sticky bit to chmod +t" "${sticky_missing[@]}"
  for d in "${SELECTED[@]}"; do
    [[ -d "$d" ]] || { warn "$d disappeared; skipping."; continue; }
    record_perm "$d"
    run chmod +t "$d"
    ok "Added sticky bit to $d"
  done
}

# ============================================================================
# SECTION 17 — File permissions & umask
# ============================================================================
sec_perms() {
  start_task "perms" "File Permissions & umask"
  require_supported_write "File Permissions & umask" || { end_task; return; }
  local f d user uid home log_file log_owner _pw _gid _gecos _shell
  for f in /etc/passwd /etc/group; do
    [[ -e "$f" ]] || continue; record_perm "$f"; run chmod 644 "$f"; run chown root:root "$f"
  done
  for f in /etc/shadow /etc/gshadow; do
    [[ -e "$f" ]] || continue; record_perm "$f"; run chmod 640 "$f"; run chown root:root "$f"
  done
  if [[ -e "$SSHD_CONFIG" ]]; then record_perm "$SSHD_CONFIG"; run chmod 600 "$SSHD_CONFIG"; fi
  for f in /tmp /var/tmp /dev/shm; do
    [[ -d "$f" ]] || continue
    record_perm "$f"
    run chmod 1777 "$f"
  done
  repair_world_writable_sticky_bits
  harden_runtime_temp_mount_options

  # per-user .ssh
  while IFS= read -r d; do
    [[ -d "$d" ]] || continue; record_perm "$d"; run chmod 700 "$d"
  done < <(find /home /root -maxdepth 2 -name .ssh -type d 2>/dev/null)
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue; record_perm "$f"; run chmod 600 "$f"
  done < <(find /home /root -maxdepth 3 -name authorized_keys -type f 2>/dev/null)
  ok "Key file permissions tightened"

  if confirm "Tighten top-level human home directories to 750? Outcome: prevents other local users from browsing homes. Risk: breaks deliberate shared files or web content served from home directories"; then
    while IFS=: read -r user _pw uid _gid _gecos home _shell; do
      [[ "$uid" =~ ^[0-9]+$ && "$uid" -ge 1000 && "$uid" -lt 65534 ]] || continue
      [[ -d "$home" ]] || continue
      record_perm "$home"
      run chmod 750 "$home"
      ok "Tightened $home for $user"
    done < /etc/passwd
  fi

  if confirm "Tighten common log file permissions? Outcome: removes world access from auth/system logs and ensures btmp exists. Risk: non-root log readers or monitoring agents may need group access adjusted"; then
    if [[ ! -e /var/log/btmp ]]; then
      prepare_edit /var/log/btmp
      run touch /var/log/btmp
      if getent group utmp >/dev/null 2>&1; then log_owner="root:utmp"; else log_owner="root:root"; fi
      run chown "$log_owner" /var/log/btmp
      run chmod 600 /var/log/btmp
    fi
    for log_file in /var/log/btmp /var/log/wtmp /var/log/lastlog /var/log/faillog \
      /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages \
      /var/log/audit/audit.log; do
      [[ -e "$log_file" ]] || continue
      record_perm "$log_file"
      run chmod o-rwx "$log_file"
      run chmod g-w "$log_file"
    done
    ok "Common log permissions tightened"
  fi

  # umask 027 via profile.d (revertible: it's a new file)
  local uf="/etc/profile.d/99-umask-hardening.sh"
  prepare_edit "$uf"
  echo "umask 027" > "$uf"
  run chmod 644 "$uf"
  ok "umask 027 set for new shells ($uf)"

  if confirm "Set shell idle timeout TMOUT=600? Outcome: logs out idle interactive shells after 10 minutes. Risk: long idle admin shells may be disconnected"; then
    local tf=/etc/profile.d/99-session-timeout.sh
    prepare_edit "$tf"
    cat > "$tf" <<'EOF'
# Managed by harden.sh
readonly TMOUT=600
export TMOUT
EOF
    run chmod 644 "$tf"
    ok "TMOUT idle shell timeout configured in $tf"
  fi

  if confirm "Replace /etc/motd with a minimal warning? Outcome: removes possible OS/kernel information leakage after login. Risk: replaces existing custom MOTD content"; then
    prepare_edit /etc/motd
    printf 'Authorized use only. Activity may be monitored.\n' > /etc/motd
    run chmod 644 /etc/motd
    ok "/etc/motd replaced with minimal warning text."
  fi

  if [[ -d /boot ]] && confirm "Restrict /boot permissions to 750? Outcome: reduces local browsing of boot artifacts. Risk: unusual non-root backup/monitoring tools may need access adjusted"; then
    record_perm /boot
    run chown root:root /boot
    run chmod 750 /boot
    ok "/boot permissions set to root:root 750."
  fi

  if [[ -e /etc/securetty ]] && ask_risky "Restrict direct root console login by emptying /etc/securetty. Outcome: blocks root password login on listed TTYs where PAM honors securetty. Risk: can remove an emergency console login path; verify sudo/rescue access first"; then
    prepare_edit /etc/securetty
    : > /etc/securetty
    run chmod 600 /etc/securetty
    ok "/etc/securetty emptied."
  fi

  if confirm "Restrict common compilers/build tools to root/group execution? Outcome: limits local exploit compilation. Risk: legitimate developers or build jobs may fail"; then
    local tool
    for tool in /usr/bin/gcc /usr/bin/cc /usr/bin/g++ /usr/bin/c++ /usr/bin/make /usr/bin/as; do
      [[ -e "$tool" ]] || continue
      record_perm "$tool"
      run chmod 750 "$tool"
      ok "Restricted $tool to owner/group execution."
    done
  fi
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
append_audit_watch_if_exists() {
  local rules_file="$1" path="$2" perms="$3" key="$4"
  if [[ -e "$path" ]]; then
    printf -- '-w %s -p %s -k %s\n' "$path" "$perms" "$key" >> "$rules_file"
  else
    info "Audit watch skipped; path not present: $path"
  fi
}

sec_auditd() {
  start_task "auditd" "Auditd / rsyslog / Process Accounting"
  require_supported_write "Auditd / rsyslog / Process Accounting" || { end_task; return; }
  require_systemd_task "Auditd / rsyslog / Process Accounting" || { end_task; return; }
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

  local rf=/etc/audit/rules.d/99-hardening.rules modbin
  prepare_edit "$rf"
  : > "$rf"
  append_audit_watch_if_exists "$rf" /etc/passwd wa identity
  append_audit_watch_if_exists "$rf" /etc/shadow wa identity
  append_audit_watch_if_exists "$rf" /etc/gshadow wa identity
  append_audit_watch_if_exists "$rf" /etc/group wa identity
  append_audit_watch_if_exists "$rf" /etc/sudoers wa sudoers
  append_audit_watch_if_exists "$rf" /etc/sudoers.d/ wa sudoers
  append_audit_watch_if_exists "$rf" "$SSHD_CONFIG" wa sshd
  append_audit_watch_if_exists "$rf" /var/log/sudo.log wa sudoaction
  append_audit_watch_if_exists "$rf" /etc/crontab wa cron
  append_audit_watch_if_exists "$rf" /etc/cron.d/ wa cron
  append_audit_watch_if_exists "$rf" /var/spool/cron/ wa cron
  append_audit_watch_if_exists "$rf" /var/spool/cron/crontabs/ wa cron
  append_audit_watch_if_exists "$rf" /etc/hosts wa network
  append_audit_watch_if_exists "$rf" /etc/pam.d/ wa pam
  for modbin in /sbin/insmod /usr/sbin/insmod /sbin/modprobe /usr/sbin/modprobe /sbin/rmmod /usr/sbin/rmmod; do
    append_audit_watch_if_exists "$rf" "$modbin" x modules
  done
  # Watch the platform's authentication log (Debian: auth.log, RHEL: secure).
  [[ -e /var/log/auth.log ]] && echo '-w /var/log/auth.log -p wa -k authlog' >> "$rf"
  [[ -e /var/log/secure   ]] && echo '-w /var/log/secure -p wa -k authlog'   >> "$rf"
  if ask_risky "Add auditd execve logging. Outcome: records executed commands for investigations. Risk: high log volume on busy web VMs"; then
    if [[ "$(getconf LONG_BIT 2>/dev/null || echo 64)" == "64" ]]; then
      echo '-a always,exit -F arch=b64 -S execve -k exec_log' >> "$rf"
    fi
    echo '-a always,exit -F arch=b32 -S execve -k exec_log' >> "$rf"
  fi

  if command -v augenrules >/dev/null 2>&1; then
    run augenrules --load || warn "augenrules --load failed; audit rules may require manual review."
  elif command -v auditctl >/dev/null 2>&1; then
    warn "augenrules not found; loading audit rules with auditctl fallback."
    run auditctl -R "$rf" || warn "auditctl fallback failed to load $rf."
    run systemctl restart auditd 2>/dev/null || true
  else
    warn "Neither augenrules nor auditctl is available; audit rules were written but not loaded."
  fi
  if command -v auditctl >/dev/null 2>&1; then
    run auditctl -e 1        # enable auditing (the checklist's 'auditctl -e 1')
    run auditctl -l
    if ask_risky "Set auditd immutable mode (-e 2). Outcome: audit rules cannot be changed until reboot. Risk: revert.sh cannot undo this during the same boot; reboot required"; then
      record_action "NOTE" "auditd_immutable_enabled_reboot_required"
      run auditctl -e 2
      ok "auditd immutable mode requested; reboot is required to undo."
    fi
  else
    warn "auditctl not found; cannot enable/list live audit rules."
  fi
  ok "auditd enabled with identity/sudoers/sshd/authlog watch rules"

  if confirm "Enable persistent journald storage? Outcome: keeps journal logs across reboot. Risk: uses disk space under /var/log/journal"; then
    local jf=/etc/systemd/journald.conf
    prepare_edit "$jf"
    set_conf_kv "$jf" Storage persistent "="
    run mkdir -p /var/log/journal
    run systemctl restart systemd-journald
    ok "journald persistent storage enabled."
  fi

  if [[ -e /var/log/sudo.log || -e /etc/sudoers.d/logging ]] && confirm "Install logrotate rule for /var/log/sudo.log? Outcome: prevents sudo log growth. Risk: rotates sudo command logs according to local logrotate schedule"; then
    local lr=/etc/logrotate.d/harden-sudo
    prepare_edit "$lr"
    cat > "$lr" <<'EOF'
/var/log/sudo.log {
    weekly
    rotate 12
    compress
    missingok
    notifempty
    create 0600 root root
}
EOF
    ok "logrotate rule written to $lr"
  fi

  if confirm "Ensure rsyslog is installed and enabled? Outcome: keeps traditional auth/system logs populated. Risk: installs/enables a logging daemon and may duplicate journald logs"; then
    if pkg_install_tracked rsyslog; then
      if systemctl list-unit-files 2>/dev/null | grep -q '^rsyslog\.service'; then
        record_service rsyslog
        run systemctl enable --now rsyslog
        ok "rsyslog enabled"
      else
        warn "rsyslog package installed, but rsyslog.service was not found."
      fi
    fi
  fi

  if confirm "Enable process accounting? Outcome: records executed commands for incident review. Risk: adds command metadata/log volume"; then
    local acct_pkg acct_svc
    if is_debian; then acct_pkg="acct"; acct_svc="acct"; else acct_pkg="psacct"; acct_svc="psacct"; fi
    if pkg_install_tracked "$acct_pkg"; then
      if systemctl list-unit-files 2>/dev/null | grep -q "^${acct_svc}\\.service"; then
        record_service "$acct_svc"
        run systemctl enable --now "$acct_svc"
        ok "Process accounting enabled via $acct_svc"
      else
        warn "$acct_svc.service was not found after installing $acct_pkg; process accounting not enabled."
      fi
    fi
  fi
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
  start_task "tools" "Security Audit Tools (ClamAV / rkhunter / Lynis / Unhide / Stacer)"
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
  if confirm "Install & run Unhide hidden-process checks? Outcome: finds hidden processes/ports. Risk: slow or noisy on busy systems"; then
    pkg_install_tracked unhide || warn "unhide unavailable; hidden-process checks skipped."
    if command -v unhide >/dev/null 2>&1; then
      run unhide -f brute proc procall procfs quick reverse sys || warn "unhide reported findings or errors; review output."
    else
      warn "unhide command not available; skipped."
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
# SECTION 23 — Remove unauthorized media files — DESTRUCTIVE / NOT REVERTIBLE
# ============================================================================
sec_mp3() {
  start_task "mp3" "Remove unauthorized media files (DESTRUCTIVE)"
  require_supported_write "Remove unauthorized media files" || { end_task; return; }
  warn "This deletes files PERMANENTLY and CANNOT be undone by revert.sh."
  warn "Per the checklist, only do this AFTER any forensics is complete."
  local files ext
  local exts=(mp3)
  if confirm "Also include common audio/video/image extensions? Outcome: catches more unauthorized media. Risk: web/app assets may match, so review before deleting"; then
    exts=(midi mid mod mp3 mp2 mpa abs mpega au snd wav aiff aif sid flac ogg \
      mpeg mpg mpe movie mov avi wmv asf asx wma wax wmx 3gp mp4 flv m4v \
      tiff tif gif jpeg jpg jpe png rgb xwd xpm ppm pbm pgm pcx ico svg svgz)
  fi
  local find_expr=()
  for ext in "${exts[@]}"; do
    [[ ${#find_expr[@]} -gt 0 ]] && find_expr+=(-o)
    find_expr+=(-iname "*.${ext}")
  done
  mapfile -t files < <(find / -type f \( "${find_expr[@]}" \) 2>/dev/null)
  prompt_selection "media files to DELETE" "${files[@]}"
  if [[ ${#SELECTED[@]} -gt 0 ]] && ask_risky "PERMANENTLY delete the ${#SELECTED[@]} selected media file(s)"; then
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
  elif { is_rhel || is_suse; } && systemctl is-active firewalld >/dev/null 2>&1; then
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
  "Service Config Hardening (FTP / Apache / ModSecurity / Nginx / PHP / DB)"
  "File Permissions & umask"
  "Display Manager (guest / autologin)"
  "Auditd / rsyslog / Process Accounting"
  "Fail2ban (SSH brute-force protection)"
  "Mandatory Access Control (AppArmor / SELinux)"
  "Security Audit Tools (ClamAV / rkhunter / Lynis / Unhide / Logwatch / Stacer)"
  "Remove unauthorized media files (DESTRUCTIVE)"
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
  echo "After you log back in, review it with:  ${C_BLD}sudo \"$SCRIPT_DIR/harden.sh\" --show-last${C_RST}"
  echo "Pending:"
  local i
  for i in "${!DEFERRED_CMD[@]}"; do echo "  - ${DEFERRED_DESC[$i]}"; done
  if ! confirm "Run these now? (No = leave them; they take effect on next reboot)"; then
    warn "Deferred actions NOT run."
    return 0
  fi
  for i in "${!DEFERRED_CMD[@]}"; do
    log "Deferred: ${DEFERRED_DESC[$i]}"
    run_deferred_command "${DEFERRED_CMD[$i]}"
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
  log "Transcript: $OUTPUT_LOG   (replay later: sudo \"$SCRIPT_DIR/harden.sh\" --show-last)"
  log "To undo changes: sudo ./revert.sh --log \"$ACTIONS_LOG\""

  # Disruptive actions (display-manager restart) happen here, dead last.
  run_deferred
}

main "$@"
