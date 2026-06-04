#!/usr/bin/env bash
#
# harden.sh — Menu-driven Linux security hardening tool
# ============================================================================
# Implements the checks in the "Linux System Checklist", with corrections.
# Supports Debian/Ubuntu/Mint (apt) and RHEL/Alma/Rocky/CentOS/Fedora (dnf/yum).
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
# Usage:   sudo ./harden.sh [--authorized PATH] [--state-dir DIR] [--yes-risky]
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
SHOW_LAST=0              # if 1, just replay the latest run's transcript and exit
PW_WORDLIST="${PW_WORDLIST:-}"   # optional custom wordlist for the password audit
PKG_FAMILY=""            # apt | dnf | yum
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
# Backup helpers (the foundation of revertibility)
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
  if [[ $ASSUME_RISKY -eq 1 ]]; then
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
  if   command -v apt-get >/dev/null 2>&1; then PKG_FAMILY="apt"; ADMIN_GROUP="sudo"
  elif command -v dnf     >/dev/null 2>&1; then PKG_FAMILY="dnf"; ADMIN_GROUP="wheel"
  elif command -v yum     >/dev/null 2>&1; then PKG_FAMILY="yum"; ADMIN_GROUP="wheel"
  fi

  if [[ -z "$PKG_FAMILY" || -z "$DISTRO_ID" ]]; then
    echo "${C_YEL}Could not reliably detect the distribution.${C_RST}"
    echo "Select the closest match:"
    echo "  1) Debian / Ubuntu / Mint   (apt)"
    echo "  2) Fedora / RHEL 8+ / Alma / Rocky / CentOS 8+ (dnf)"
    echo "  3) CentOS 7 / RHEL 7        (yum)"
    local c; read -r -p "Choice [1-3]: " c
    case "$c" in
      1) PKG_FAMILY="apt"; ADMIN_GROUP="sudo"; DISTRO_ID="${DISTRO_ID:-debian}";;
      2) PKG_FAMILY="dnf"; ADMIN_GROUP="wheel"; DISTRO_ID="${DISTRO_ID:-rhel}";;
      3) PKG_FAMILY="yum"; ADMIN_GROUP="wheel"; DISTRO_ID="${DISTRO_ID:-centos}";;
      *) echo "Invalid choice."; exit 1;;
    esac
  fi
  record_action "META" "distro" "${DISTRO_ID}" "${DISTRO_VER}" "${PKG_FAMILY}"
  log "Detected: ${C_BLD}${DISTRO_ID} ${DISTRO_VER}${C_RST} (package manager: ${PKG_FAMILY}, admin group: ${ADMIN_GROUP})"
}

is_debian() { [[ "$PKG_FAMILY" == "apt" ]]; }
is_rhel()   { [[ "$PKG_FAMILY" == "dnf" || "$PKG_FAMILY" == "yum" ]]; }

pkg_installed() {  # pkg_installed NAME
  case "$PKG_FAMILY" in
    apt) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed";;
    dnf|yum) rpm -q "$1" >/dev/null 2>&1;;
  esac
}

pkg_install() {
  local p="$1"
  case "$PKG_FAMILY" in
    apt) run env DEBIAN_FRONTEND=noninteractive apt-get install -y "$p";;
    dnf) run dnf install -y "$p";;
    yum) run yum install -y "$p";;
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
  esac
}

# Install a package we want kept; record so revert can remove it if desired.
pkg_install_tracked() {
  local p="$1"
  if pkg_installed "$p"; then info "$p already installed."; return 0; fi
  record_action "PKG_INSTALL" "$PKG_FAMILY" "$p"
  pkg_install "$p" && ok "Installed $p" || warn "Failed to install $p"
}

# ============================================================================
# SECTION 1 — User & Group Audit
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
      run userdel -r "$u" && ok "Deleted user $u (home archived)" || warn "Failed to delete $u"
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
    run gpasswd -d "$u" "$ADMIN_GROUP" && ok "Removed $u from $ADMIN_GROUP" || warn "Failed removing $u from $ADMIN_GROUP"
  done
  end_task
}

# ============================================================================
# SECTION 2 — Password Policies
# ============================================================================
sec_passwords() {
  start_task "passwords" "Password Policies (aging, complexity)"
  # pwquality module
  if is_debian; then pkg_install_tracked libpam-pwquality
  else               pkg_install_tracked libpwquality; fi

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

  # Apply aging to existing human accounts (risky: affects all users' expiry)
  if ask_risky "Apply 90/7/12 day aging to ALL existing human accounts (chage)"; then
    local u
    for u in $(awk -F: '$3>=1000 && $1!="nobody"{print $1}' /etc/passwd); do
      # record current aging so revert can restore it
      local cur
      cur=$(chage -l "$u" 2>/dev/null | awk -F: '/Maximum/{m=$2} /Minimum/{n=$2} /warning/{w=$2} END{gsub(/ /,"",m);gsub(/ /,"",n);gsub(/ /,"",w);print m":"n":"w}')
      record_action "CHAGE" "$u" "${cur:-:::}"
      run chage -M 90 -m 7 -W 12 "$u"
    done
    ok "Password aging applied to existing accounts"
  fi
  end_task
}

# ============================================================================
# SECTION 2b — Password Strength Audit (detect & reset weak passwords)
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
  lower=$(LC_ALL=C tr -dc 'a-z'        </dev/urandom | head -c1)
  upper=$(LC_ALL=C tr -dc 'A-Z'        </dev/urandom | head -c1)
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
    if pkg_installed wordlists; then :; else WL_INSTALLED=1; pkg_install wordlists; fi
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
    if is_debian; then pkg_installed john || { JOHN_INSTALLED=1; pkg_install john; }
    else pkg_installed john || pkg_installed john-the-ripper || { JOHN_INSTALLED=1; pkg_install john || pkg_install john-the-ripper; }; fi
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
  esac
}

# ============================================================================
# SECTION 3 — Account lockout, empty passwords, nullok
# ============================================================================
sec_auth_lockout() {
  start_task "auth_lockout" "Account Lockout / Empty Passwords / nullok"

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
  end_task
}

# ============================================================================
# SECTION 4 — SSH hardening
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
# SECTION 5 — Firewall (UFW on Debian, firewalld on RHEL)
# ============================================================================
SSH_PORT_CHANGED=""
sec_firewall() {
  start_task "firewall" "Firewall (managed)"
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
    run firewall-cmd --reload
    run firewall-cmd --list-all
    ok "firewalld configured"
  fi
  end_task
}

# ============================================================================
# SECTION 6 — Kernel / sysctl hardening
# ============================================================================
sec_kernel() {
  start_task "kernel" "Kernel / sysctl Hardening"
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
EOF
  ok "Baseline sysctl settings written"

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

  run sysctl --system
  ok "sysctl settings applied"
  end_task
}

# ============================================================================
# SECTION 7 — Unwanted services & packages
# ============================================================================
sec_services() {
  start_task "services" "Unwanted Services & Packages"

  # BAD + MEGA-BAD: attack tools & insecure daemons -> removal candidates.
  local bad_tokens=(john hydra medusa ophcrack nikto nmap netcat ncat socat \
    telnet telnetd rsh-server rsh rsh-client tightvncserver x11vnc tigervnc-server \
    vsftpd proftpd-basic proftpd tftpd-hpa tftp-server tftpd snmpd net-snmp xinetd \
    cryptcat kismet vuze frostwire freeciv minetest minetest-server truecrack \
    rsh-redone-server rlinetd finger fingerd)
  # POSSIBLY-BAD: legitimate services that may be required by the readme.
  local maybe_tokens=(samba postgresql apache2 httpd nginx mysql-server mariadb-server \
    php bind9 dovecot-core sendmail snmp pure-ftpd)

  local installed_bad=() installed_maybe=() t
  for t in "${bad_tokens[@]}";   do pkg_installed "$t" && installed_bad+=("$t");   done
  for t in "${maybe_tokens[@]}"; do pkg_installed "$t" && installed_maybe+=("$t"); done

  log "Scanning for insecure / hacking-tool packages"
  prompt_selection "BAD packages (attack tools / insecure daemons) to PURGE" "${installed_bad[@]}"
  for t in "${SELECTED[@]}"; do pkg_remove "$t" && ok "Purged $t"; done

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

  log "Listening sockets after changes:"
  run ss -tulpen
  end_task
}

# ============================================================================
# SECTION 8 — File permissions & umask
# ============================================================================
sec_perms() {
  start_task "perms" "File Permissions & umask"
  local f
  for f in /etc/passwd /etc/group; do
    [[ -e "$f" ]] || continue; record_perm "$f"; run chmod 644 "$f"; run chown root:root "$f"
  done
  for f in /etc/shadow /etc/gshadow; do
    [[ -e "$f" ]] || continue; record_perm "$f"; run chmod 640 "$f"; run chown root:root "$f"
  done
  if [[ -e "$SSHD_CONFIG" ]]; then record_perm "$SSHD_CONFIG"; run chmod 600 "$SSHD_CONFIG"; fi

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
# SECTION 9 — Display manager (guest / autologin)
# ============================================================================
sec_displaymgr() {
  start_task "displaymgr" "Display Manager (guest / autologin)"
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
# SECTION 10 — auditd
# ============================================================================
sec_auditd() {
  start_task "auditd" "Auditd"
  if is_debian; then pkg_install_tracked auditd; pkg_install_tracked audispd-plugins
  else               pkg_install_tracked audit; fi
  record_service auditd
  run systemctl enable --now auditd

  local rf=/etc/audit/rules.d/99-hardening.rules
  prepare_edit "$rf"
  cat > "$rf" <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
EOF
  run augenrules --load 2>/dev/null
  run auditctl -l
  ok "auditd enabled with identity/sudoers watch rules"
  end_task
}

# ============================================================================
# SECTION 11 — Automatic security updates
# ============================================================================
sec_autoupdate() {
  start_task "autoupdate" "Automatic Security Updates"
  if is_debian; then
    pkg_install_tracked unattended-upgrades
    local f=/etc/apt/apt.conf.d/20auto-upgrades
    prepare_edit "$f"
    cat > "$f" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
    run systemctl enable --now unattended-upgrades 2>/dev/null
    ok "unattended-upgrades configured"
  else
    if [[ "$PKG_FAMILY" == "dnf" ]]; then
      pkg_install_tracked dnf-automatic
      local f=/etc/dnf/automatic.conf
      prepare_edit "$f"
      set_conf_kv "$f" upgrade_type security " = "
      set_conf_kv "$f" download_updates yes " = "
      set_conf_kv "$f" apply_updates yes " = "
      record_action "TIMER" "dnf-automatic-install.timer"
      run systemctl enable --now dnf-automatic-install.timer
      ok "dnf-automatic configured (security only)"
    else
      pkg_install_tracked yum-cron
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
# SECTION 12 — Security audit tools (install + run, mostly read-only)
# ============================================================================
sec_tools() {
  start_task "tools" "Security Audit Tools (ClamAV / rkhunter / Lynis)"
  if confirm "Install & run ClamAV, rkhunter, chkrootkit (downloads signatures, can be slow)?"; then
    pkg_install_tracked clamav
    pkg_install_tracked rkhunter
    pkg_install_tracked chkrootkit
    log "Updating ClamAV signatures (freshclam)"; run freshclam
    log "Running chkrootkit"; run chkrootkit -q
    log "Updating & running rkhunter"; run rkhunter --update; run rkhunter --propupd; run rkhunter -c --sk
    info "rkhunter log: /var/log/rkhunter.log"
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
  end_task
}

# ============================================================================
# SECTION 13 — Forensic / persistence checks (READ-ONLY: nothing to revert)
# ============================================================================
sec_forensics() {
  start_task "forensics" "Forensic / Persistence Checks (read-only)"
  log "Listening sockets:";                 run ss -tulpen
  log "Suspicious reverse-shell processes:"; ps auww | grep -Ei 'nc |ncat|netcat|socat|bash -i|/dev/tcp|python.*socket|perl.*socket|curl.*sh|wget.*sh' | grep -v grep
  log "Enabled systemd services:";           run systemctl list-unit-files --type=service --state=enabled
  log "systemd unit ExecStart lines:";       find /etc/systemd/system /lib/systemd/system -type f -name "*.service" -exec grep -H "ExecStart" {} \; >> "$OUTPUT_LOG" 2>&1
  log "System crontab + cron.* dirs:";       { cat /etc/crontab; grep -R . /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null; } >> "$OUTPUT_LOG" 2>&1
  log "Per-user crontabs:";                  for u in $(cut -d: -f1 /etc/passwd); do out=$(crontab -l -u "$u" 2>/dev/null); [[ -n "$out" ]] && { echo "== $u =="; echo "$out"; }; done >> "$OUTPUT_LOG" 2>&1
  log "Executable files in tmp/home dirs:";  find /tmp /var/tmp /dev/shm /home /root -type f -perm /111 -ls >> "$OUTPUT_LOG" 2>&1
  log "SSH authorized_keys across users:";    find /root /home -name authorized_keys -exec ls -l {} \; -exec cat {} \; >> "$OUTPUT_LOG" 2>&1
  log "SUID binaries:";                       find / -perm -4000 -type f 2>/dev/null
  log "SGID binaries:";                       find / -perm -2000 -type f 2>/dev/null >> "$OUTPUT_LOG" 2>&1
  if is_rhel; then log "SELinux status:"; run sestatus; else log "AppArmor status:"; run aa-status; fi
  ok "Forensic report written to $OUTPUT_LOG (review it manually)."
  end_task
}

# ============================================================================
# SECTION 14 — Remove unauthorized media (.mp3) — DESTRUCTIVE / NOT REVERTIBLE
# ============================================================================
sec_mp3() {
  start_task "mp3" "Remove unauthorized .mp3 files (DESTRUCTIVE)"
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
# Menu / dispatch
# ============================================================================
SECTION_FUNCS=(sec_user_audit sec_passwords sec_pwaudit sec_auth_lockout sec_ssh sec_firewall sec_kernel sec_services sec_perms sec_displaymgr sec_auditd sec_autoupdate sec_tools sec_forensics sec_mp3)
SECTION_DESC=(
  "User & Group Audit (needs authorized.txt)"
  "Password Policies (aging + complexity)"
  "Password Strength Audit (detect & reset weak passwords)"
  "Account Lockout / Empty Passwords / nullok"
  "SSH Hardening"
  "Firewall (UFW / firewalld)"
  "Kernel / sysctl Hardening"
  "Unwanted Services & Packages"
  "File Permissions & umask"
  "Display Manager (guest / autologin)"
  "Auditd"
  "Automatic Security Updates"
  "Security Audit Tools (ClamAV / rkhunter / Lynis)"
  "Forensic / Persistence Checks (read-only)"
  "Remove unauthorized .mp3 files (DESTRUCTIVE)"
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
  for idx in "${todo[@]}"; do
    run_section "$idx"
  done

  echo
  log "${C_GRN}${C_BLD}All selected sections complete.${C_RST}"
  log "Transcript: $OUTPUT_LOG   (replay later: sudo $0 --show-last)"
  log "To undo changes: sudo ./revert.sh --log \"$ACTIONS_LOG\""

  # Disruptive actions (display-manager restart) happen here, dead last.
  run_deferred
}

main "$@"
