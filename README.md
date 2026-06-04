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
sudo ./harden.sh [--authorized PATH] [--state-dir DIR] [--yes-risky] [--wordlist PATH]
sudo ./harden.sh --show-last          # replay the most recent run's transcript
```

- Presents a numbered menu. Enter space-separated numbers (`1 4 6`), `a` for all, or `q`.
- After picking a section, **risky** items still prompt individually (default = No).
  `--yes-risky` auto-approves them (use with care).
- For service/package/user removal it asks: **process all? / choose which to ignore? /
  type `all` to skip the task entirely and change nothing.**
- The **entire session is mirrored to `output.log`** (live terminal *and* file). If a
  task ends your session, log back in and run `sudo ./harden.sh --show-last`.
- **Session-disrupting actions are deferred to the very end.** The display-manager
  restart (which logs you out of the GUI) runs *after* every other selected section,
  so an interrupted GUI session no longer aborts the rest of the run.
  Set `PW_WORDLIST=/path` or `--wordlist` to point the password audit at a custom wordlist.

Each run writes to `/var/backups/security-hardening/run_<timestamp>/`:
- `actions.log` — machine-readable record consumed by `revert.sh`
- `output.log`  — full human transcript
- `backups/`    — copies of every file before it was modified
- a `latest` symlink points at the newest run.

### Sections
1. User & Group Audit (needs `authorized.txt`)
2. Password Policies (aging + complexity)
3. **Password Strength Audit (detect & reset weak passwords)**
4. Account Lockout / Empty Passwords / nullok
5. SSH Hardening
6. Firewall (UFW / firewalld)
7. Kernel / sysctl Hardening
8. Unwanted Services & Packages
9. File Permissions & umask
10. Display Manager (guest / autologin) — *restart deferred to end of run*
11. Auditd
12. Automatic Security Updates
13. Security Audit Tools (ClamAV / rkhunter / Lynis)
14. Forensic / Persistence Checks (**read-only** — nothing to revert)
15. Remove unauthorized `.mp3` files (**destructive, NOT revertible**)

### Password Strength Audit (section 3)
You can't tell if an *existing* password is weak from its hash — you have to test
candidates against it. This section:
1. Prefers **John the Ripper + the rockyou wordlist** (the standard, most popular tooling).
   It tries an installed `john`, else installs one, else downloads/locates rockyou
   (`wordlists` package → known download URL → built-in common-password list).
2. Falls back to a **built-in `crypt`-compare** (python3, supports yescrypt/sha512/md5)
   over a common-password + username-variation list when john/network is unavailable.
3. For each account whose password is cracked (= weak), generates a 20-char strong
   password, sets it, and writes `OLD(weak)` + `NEW` to a root-only `new-credentials.txt`
   in the run dir (also echoed to the console). The original hash is recorded so it's
   fully revertible. Covers **all** accounts with a usable password, including root, but
   **skips the account running the audit** (`$SUDO_USER`, i.e. the competitor's assigned
   user — not scored for password strength, and skipping it avoids changing the password
   on the session you're logged in with).

> ⚠️ **john is a dual-use cracker and is on this toolkit's own purge list.** Using it to
> audit *your own* system is legitimate, but if the script installs it just for the audit
> it **auto-removes it afterward** so the hardened system isn't left with a cracker (and
> you don't lose competition points). The same applies to a `wordlists` package it installs.

### Risky items (always prompted, default No)
- SSH port 22 → 2222
- `PasswordAuthentication no` (skipped automatically if no SSH keys exist)
- `AllowGroups sshusers`
- Enabling the firewall (SSH is allowed first to avoid lockout)
- `icmp_echo_ignore_all` (blocks ping; the checklist warns it can break scoring)
- Disabling IPv6
- `pam_faillock` lockout-after-failures
- Applying password aging to existing accounts
- Resetting weak passwords (section 3 — confirmed before running)
- Permanently deleting `.mp3` files

### Recovering an interrupted run
The complete transcript is always on disk at
`/var/backups/security-hardening/run_<ts>/output.log` (root-only). After logging back
in: `sudo ./harden.sh --show-last`. Terminal *scrollback* itself cannot survive a session
kill, but nothing in the log is lost. (Sections that hadn't started yet simply weren't run —
re-run the tool and pick them.)

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
(purged packages are reinstalled), group membership, password aging, account locks, and
**reset passwords (the original hash is restored)**, etc.
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
