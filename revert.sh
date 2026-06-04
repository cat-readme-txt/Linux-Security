#!/usr/bin/env bash
#
# revert.sh — Undo changes made by harden.sh
# ============================================================================
# Reads the machine-readable actions log written by harden.sh, lists the tasks
# that were performed, lets you choose which to roll back, and restores the
# system to the state captured BEFORE harden.sh ran (file backups, original
# service states, package state, permissions, group membership, etc.).
#
# Usage:
#   sudo ./revert.sh                       # auto-uses the most recent run
#   sudo ./revert.sh --log  /path/actions.log
#   sudo ./revert.sh --run  /var/backups/security-hardening/run_XXXX
#   sudo ./revert.sh --list                # just list runs/tasks, change nothing
#
# Notes:
#   * Package PURGES are reversed by REINSTALLING (config from the package
#     defaults; user data in deleted home dirs is restored from the archive
#     harden.sh made).
#   * Some actions are intrinsically irreversible and will be reported but not
#     undone (e.g. permanently deleted .mp3 files).
# ============================================================================

set -o pipefail

STATE_BASE="/var/backups/security-hardening"
LOG=""
RUN_DIR=""
LIST_ONLY=0
REMOVE_INSTALLED=0   # whether to also uninstall packages harden.sh installed

if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'
  C_BLU=$'\033[34m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_RST=""
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --log) LOG="$2"; shift 2;;
    --run) RUN_DIR="$2"; LOG="$2/actions.log"; shift 2;;
    --state-dir) STATE_BASE="$2"; shift 2;;
    --list) LIST_ONLY=1; shift;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -30; exit 0;;
    *) echo "Unknown argument: $1" >&2; exit 1;;
  esac
done

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "${C_RED}This script must be run as root (use sudo).${C_RST}" >&2
  exit 1
fi

# ---- Locate the actions log -------------------------------------------------
if [[ -z "$LOG" ]]; then
  if [[ -e "$STATE_BASE/latest/actions.log" ]]; then
    LOG="$(readlink -f "$STATE_BASE/latest")/actions.log"
    RUN_DIR="$(dirname "$LOG")"
  else
    # fall back to newest run_* directory
    local_newest="$(ls -1dt "$STATE_BASE"/run_* 2>/dev/null | head -1)"
    if [[ -n "$local_newest" ]]; then
      RUN_DIR="$local_newest"; LOG="$local_newest/actions.log"
    fi
  fi
fi

if [[ -z "$LOG" || ! -r "$LOG" ]]; then
  echo "${C_RED}Could not find an actions log.${C_RST}"
  echo "Pass one explicitly:  sudo ./revert.sh --log /path/to/actions.log"
  echo "Available runs under $STATE_BASE:"
  ls -1dt "$STATE_BASE"/run_* 2>/dev/null || echo "  (none)"
  exit 1
fi
[[ -z "$RUN_DIR" ]] && RUN_DIR="$(dirname "$LOG")"

echo "${C_BLD}Reverting from log:${C_RST} $LOG"

# ---- Load log into memory ---------------------------------------------------
mapfile -t LINES < "$LOG"

# ---- Build the list of tasks ------------------------------------------------
TASK_ID=(); TASK_DESC=(); TASK_NACT=()
for l in "${LINES[@]}"; do
  if [[ "$l" == TASK_START\|* ]]; then
    IFS='|' read -r _ tid tdesc _ <<<"$l"
    TASK_ID+=("$tid"); TASK_DESC+=("$tdesc"); TASK_NACT+=(0)
  fi
done
# count actions per task
declare -A IDX_OF
for i in "${!TASK_ID[@]}"; do IDX_OF["${TASK_ID[$i]}"]=$i; done
for l in "${LINES[@]}"; do
  if [[ "$l" == ACTION\|* ]]; then
    IFS='|' read -r _ tid _rest <<<"$l"
    [[ -z "$tid" ]] && continue          # e.g. the META line has no task
    idx="${IDX_OF[$tid]:-}"
    [[ -n "$idx" ]] && TASK_NACT[$idx]=$(( TASK_NACT[idx] + 1 ))
  fi
done

if [[ ${#TASK_ID[@]} -eq 0 ]]; then
  echo "${C_YEL}No tasks recorded in this log — nothing to revert.${C_RST}"
  exit 0
fi

list_tasks() {
  echo
  echo "${C_BLD}Tasks recorded in this run:${C_RST}"
  for i in "${!TASK_ID[@]}"; do
    printf "  %2d) %-45s (%s revertible action(s))\n" "$((i+1))" "${TASK_DESC[$i]}" "${TASK_NACT[$i]}"
  done
}

list_tasks
if [[ $LIST_ONLY -eq 1 ]]; then exit 0; fi

echo "   a) Revert ALL tasks"
echo "   q) Quit (change nothing)"
echo
echo "Enter space-separated numbers (e.g. '2 4'), 'a' for all, or 'q' to quit."
read -r -p "> " choice

declare -a TODO=()
case "${choice,,}" in
  q|quit) echo "Nothing reverted."; exit 0;;
  a|all)  TODO=("${!TASK_ID[@]}");;
  *) for tok in $choice; do
       if [[ "$tok" =~ ^[0-9]+$ ]] && (( tok>=1 && tok<=${#TASK_ID[@]} )); then
         TODO+=("$((tok-1))")
       else echo "${C_YEL}Ignoring invalid selection: $tok${C_RST}"; fi
     done;;
esac
[[ ${#TODO[@]} -eq 0 ]] && { echo "No valid tasks selected."; exit 0; }

# Ask once whether to also uninstall packages that harden.sh installed.
echo
echo "Some tasks INSTALLED packages (e.g. auditd, ufw, ClamAV)."
if read -r -p "Also UNINSTALL packages that harden.sh installed for the reverted tasks? [y/N]: " a && [[ "${a,,}" =~ ^(y|yes)$ ]]; then
  REMOVE_INSTALLED=1
fi

# ---- Revert primitives ------------------------------------------------------
pkg_install() {
  local fam="$1" p="$2"
  case "$fam" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get install -y "$p";;
    dnf) dnf install -y "$p";;
    yum) yum install -y "$p";;
    *)   echo "  ${C_YEL}unknown pkg family '$fam' for $p${C_RST}";;
  esac
}
pkg_remove() {
  local fam="$1" p="$2"
  case "$fam" in
    apt) DEBIAN_FRONTEND=noninteractive apt-get purge -y "$p";;
    dnf) dnf remove -y "$p";;
    yum) yum remove -y "$p";;
  esac
}

restore_service_state() {
  local svc="$1" en="$2" act="$3"
  case "$en" in
    enabled)  systemctl enable  "$svc" >/dev/null 2>&1;;
    disabled) systemctl disable "$svc" >/dev/null 2>&1;;
  esac
  case "$act" in
    active)   systemctl start "$svc" >/dev/null 2>&1;;
    inactive|failed) systemctl stop "$svc" >/dev/null 2>&1;;
  esac
}

# Revert a single ACTION line. Receives the full pipe-delimited line.
revert_action() {
  local line="$1"
  IFS='|' read -r _tag _task type a1 a2 a3 a4 <<<"$line"
  case "$type" in
    FILE_BACKUP)
      if [[ -f "$a2" ]]; then
        cp -a "$a2" "$a1" && echo "  ${C_GRN}restored${C_RST} $a1"
      else echo "  ${C_YEL}backup missing for $a1 ($a2)${C_RST}"; fi
      ;;
    FILE_CREATE)
      if [[ -e "$a1" ]]; then rm -f "$a1" && echo "  ${C_GRN}removed${C_RST} created file $a1"; fi
      ;;
    PERM)
      if [[ -e "$a1" ]]; then
        chmod "$a2" "$a1" 2>/dev/null
        chown "$a3" "$a1" 2>/dev/null
        echo "  ${C_GRN}restored perms${C_RST} $a1 -> $a2 $a3"
      fi
      ;;
    SERVICE_STATE)
      restore_service_state "$a1" "$a2" "$a3"
      echo "  ${C_GRN}restored service${C_RST} $a1 (enabled=$a2 active=$a3)"
      ;;
    PKG_REMOVE)
      echo "  reinstalling $a2 ..."
      pkg_install "$a1" "$a2" && echo "  ${C_GRN}reinstalled${C_RST} $a2" || echo "  ${C_RED}failed to reinstall $a2${C_RST}"
      ;;
    PKG_INSTALL)
      if [[ $REMOVE_INSTALLED -eq 1 ]]; then
        echo "  removing $a2 ..."
        pkg_remove "$a1" "$a2" && echo "  ${C_GRN}removed${C_RST} $a2"
      else
        echo "  ${C_BLU}keeping installed package${C_RST} $a2 (re-run with the uninstall option to remove)"
      fi
      ;;
    USER_LOCK)
      passwd -u "$a1" >/dev/null 2>&1 && echo "  ${C_GRN}unlocked${C_RST} account $a1"
      ;;
    USER_DELETE)
      # passwd/shadow/group/gshadow are restored by their FILE_BACKUP entries;
      # here we restore the user's home directory from the archive.
      if [[ -n "$a3" && -f "$a3" ]]; then
        tar xzf "$a3" -C / && echo "  ${C_GRN}restored home${C_RST} for $a1 (from $a3)"
      else
        echo "  ${C_YEL}no home archive for $a1; account entry restored from passwd/shadow backups only${C_RST}"
      fi
      ;;
    GROUP_MEMBER)      # user WAS a member; harden removed them -> re-add
      gpasswd -a "$a1" "$a2" >/dev/null 2>&1 && echo "  ${C_GRN}re-added${C_RST} $a1 to group $a2"
      ;;
    GROUP_MEMBER_ADD)  # harden ADDED them -> remove
      gpasswd -d "$a1" "$a2" >/dev/null 2>&1 && echo "  ${C_GRN}removed${C_RST} $a1 from group $a2"
      ;;
    GROUP_CREATE)      # harden created the group -> delete it
      groupdel "$a1" >/dev/null 2>&1 && echo "  ${C_GRN}deleted${C_RST} group $a1"
      ;;
    CHAGE)
      IFS=':' read -r mx mn wn <<<"$a2"
      local args=()
      [[ "$mx" =~ ^-?[0-9]+$ ]] && args+=(-M "$mx")
      [[ "$mn" =~ ^-?[0-9]+$ ]] && args+=(-m "$mn")
      [[ "$wn" =~ ^-?[0-9]+$ ]] && args+=(-W "$wn")
      if [[ ${#args[@]} -gt 0 ]]; then
        chage "${args[@]}" "$a1" 2>/dev/null && echo "  ${C_GRN}restored aging${C_RST} for $a1"
      else
        echo "  ${C_YEL}no prior aging recorded for $a1${C_RST}"
      fi
      ;;
    AUTHSELECT_FEATURE)
      authselect disable-feature "$a1" >/dev/null 2>&1
      authselect apply-changes >/dev/null 2>&1
      echo "  ${C_GRN}disabled authselect feature${C_RST} $a1"
      ;;
    UFW_STATE)
      if [[ "$a1" == *inactive* ]]; then
        ufw --force disable >/dev/null 2>&1 && echo "  ${C_GRN}disabled UFW${C_RST} (was inactive originally)"
      else
        ufw reload >/dev/null 2>&1; echo "  ${C_GRN}reloaded UFW${C_RST} (was active originally)"
      fi
      ;;
    FIREWALLD_BACKUP)
      if [[ -d "$a2" ]]; then
        rm -rf "$a1"; cp -a "$a2" "$a1"
        firewall-cmd --reload >/dev/null 2>&1
        echo "  ${C_GRN}restored firewalld config${C_RST} $a1"
      fi
      ;;
    TIMER)
      systemctl disable --now "$a1" >/dev/null 2>&1 && echo "  ${C_GRN}disabled timer${C_RST} $a1"
      ;;
    FILE_DELETED_PERMANENT)
      echo "  ${C_RED}CANNOT REVERT${C_RST} permanently deleted file: $a1"
      ;;
    META|NOTE)
      : ;;  # informational only
    *)
      echo "  ${C_YEL}unknown action type '$type' — skipped${C_RST}"
      ;;
  esac
}

# Collect a task's ACTION lines (in original order) into REV_ACTIONS.
collect_task_actions() {
  local want="$1" in_task=0
  REV_ACTIONS=()
  for l in "${LINES[@]}"; do
    if [[ "$l" == TASK_START\|"$want"\|* ]]; then in_task=1; continue; fi
    if [[ "$l" == TASK_END\|"$want" ]]; then in_task=0; continue; fi
    [[ $in_task -eq 1 && "$l" == ACTION\|* ]] && REV_ACTIONS+=("$l")
  done
}

# ---- Execute ----------------------------------------------------------------
echo
echo "${C_BLD}About to revert ${#TODO[@]} task(s):${C_RST}"
for idx in "${TODO[@]}"; do echo "  - ${TASK_DESC[$idx]}"; done
read -r -p "Proceed? [y/N]: " go
[[ "${go,,}" =~ ^(y|yes)$ ]] || { echo "Aborted."; exit 0; }

REV_ACTIONS=()
SSH_REVERTED=0
for idx in "${TODO[@]}"; do
  tid="${TASK_ID[$idx]}"
  [[ "$tid" == "ssh" ]] && SSH_REVERTED=1
  echo
  echo "${C_BLD}${C_GRN}==> Reverting: ${TASK_DESC[$idx]}${C_RST}"
  collect_task_actions "$tid"
  if [[ ${#REV_ACTIONS[@]} -eq 0 ]]; then echo "  (no revertible actions)"; continue; fi
  # process in REVERSE order so later changes are undone before earlier ones
  for (( i=${#REV_ACTIONS[@]}-1; i>=0; i-- )); do
    revert_action "${REV_ACTIONS[$i]}"
  done
done

# If the SSH task was reverted, validate and restart sshd with the old config.
if [[ $SSH_REVERTED -eq 1 ]] && command -v sshd >/dev/null 2>&1 && sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  echo "${C_GRN}Restarted SSH with restored configuration.${C_RST}"
fi

echo
echo "${C_GRN}${C_BLD}Revert complete.${C_RST}"
echo "Review changes; a reboot is recommended if kernel/sysctl or PAM tasks were reverted."
