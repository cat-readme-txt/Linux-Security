# Linux Hardening Toolkit

Two scripts implementing the "Linux System Checklist" with corrections:

- **`harden.sh`** — menu-driven hardening. Logs and backs up everything it changes.
- **`revert.sh`** — reads the log produced by `harden.sh` and rolls back any task.

Supports **Debian / Ubuntu / Mint** (apt) and **RHEL / Alma / Rocky / CentOS / Fedora**
(dnf/yum), auto-detected from `/etc/os-release`. If detection fails, you're prompted
to pick the family.

---

## Quick start

```bash
# 1. (only needed for the user audit) describe who is allowed:
cp authorized.txt.example authorized.txt
$EDITOR authorized.txt            # put the REAL authorized users/sudoers in it

# 2. run the hardening tool
sudo ./harden.sh

# 3. if you need to undo something
sudo ./revert.sh                  # uses the most recent run automatically
```

## `harden.sh`

```
sudo ./harden.sh [--authorized PATH] [--state-dir DIR] [--yes-risky]
```

- Presents a numbered menu. Enter space-separated numbers (`1 4 6`), `a` for all, or `q`.
- After picking a section, **risky** items still prompt individually (default = No).
  `--yes-risky` auto-approves them (use with care).
- For service/package/user removal it asks: **process all? / choose which to ignore? /
  type `all` to skip the task entirely and change nothing.**

Each run writes to `/var/backups/security-hardening/run_<timestamp>/`:
- `actions.log` — machine-readable record consumed by `revert.sh`
- `output.log`  — full human transcript
- `backups/`    — copies of every file before it was modified
- a `latest` symlink points at the newest run.

### Sections
1. User & Group Audit (needs `authorized.txt`)
2. Password Policies (aging + complexity)
3. Account Lockout / Empty Passwords / nullok
4. SSH Hardening
5. Firewall (UFW / firewalld)
6. Kernel / sysctl Hardening
7. Unwanted Services & Packages
8. File Permissions & umask
9. Display Manager (guest / autologin)
10. Auditd
11. Automatic Security Updates
12. Security Audit Tools (ClamAV / rkhunter / Lynis)
13. Forensic / Persistence Checks (**read-only** — nothing to revert)
14. Remove unauthorized `.mp3` files (**destructive, NOT revertible**)

### Risky items (always prompted, default No)
- SSH port 22 → 2222
- `PasswordAuthentication no` (skipped automatically if no SSH keys exist)
- `AllowGroups sshusers`
- Enabling the firewall (SSH is allowed first to avoid lockout)
- `icmp_echo_ignore_all` (blocks ping; the checklist warns it can break scoring)
- Disabling IPv6
- `pam_faillock` lockout-after-failures
- Applying password aging to existing accounts
- Permanently deleting `.mp3` files

## `revert.sh`

```
sudo ./revert.sh                       # newest run
sudo ./revert.sh --log /path/actions.log
sudo ./revert.sh --run /var/backups/security-hardening/run_XXXX
sudo ./revert.sh --list                # show tasks, change nothing
```

Lists the tasks recorded in the run, lets you pick which to roll back (or `a` for all),
and restores: config files from backups, files created by the tool are deleted, original
file permissions/ownership, original service enabled/active states, package state
(purged packages are reinstalled), group membership, password aging, account locks, etc.
It asks once whether to also uninstall packages the tool installed (default: keep them).

**Cannot be reverted:** permanently deleted files (e.g. `.mp3`). These are reported, not restored.

---

## Notable corrections made vs. the original checklist
- Fixed commands that used en-dashes/smart-dashes instead of `--`.
- The toolkit uses **UFW *or* firewalld** (never raw iptables on top of UFW, which conflict).
- vsftpd-restart copy-paste error (it restarted gdm) and the bogus
  `banner-message-enable` directive are not reproduced.
- `Protocol 2` is **not** emitted — it's removed on OpenSSH ≥ 7.6 and would fail `sshd -t`.
- SSH config is validated with `sshd -t` before restart; on failure the backup is restored.
- `PasswordAuthentication no` is only offered when SSH keys actually exist.
- Firewall always allows SSH **before** enabling, to prevent lockout.
