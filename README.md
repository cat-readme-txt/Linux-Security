# Linux Hardening Toolkit

Two scripts implementing the "Linux System Checklist" with corrections. This
toolkit is built for cybersecurity blue-teaming competitions, especially web VM
hardening, but it also works for general Linux securing when the same services
and assumptions apply.

- **`harden.sh`** — menu-driven hardening. Logs and backs up everything it changes.
- **`revert.sh`** — reads the log produced by `harden.sh` and rolls back any task.

Fully supported write-hardening targets:
- **Debian / Ubuntu** with `apt`
- **Debian/Ubuntu-like apt distros** using `ID_LIKE=debian` or `ID_LIKE=ubuntu`
  such as Linux Mint, Pop!_OS, and Kali
- **RHEL / Fedora / AlmaLinux / Rocky Linux** with `dnf` or `yum`

Other distros are treated as unsupported for write-hardening. Read-only checks
can still run, but write-capable tasks print an unsupported-distro message and
skip instead of guessing.

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
sudo ./harden.sh [--authorized PATH] [--state-dir DIR] [--yes-risky] [--competition-safe] [--wordlist PATH]
sudo ./harden.sh --show-last          # replay the most recent run's transcript
```

- Presents a numbered menu. Enter space-separated numbers (`1 4 6`), `a` for all, or `q`.
- After picking a section, **risky** items still prompt individually (default = No).
  `--yes-risky` auto-approves them (use with care).
- `--competition-safe` disables risky auto-approval, runs the read-only competition
  checks first, and runs scored-service health again before deferred actions.
- The script only runs write-hardening tasks on fully supported distro families.
  Unsupported distros keep read-only checks available and skip unsupported tasks.
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
1. Scored Service Health Check (**read-only**)
2. AD / DNS / Time Dependency Check (**read-only**)
3. DNS Service Validation (**read-only**)
4. Webroot Malware & Permissions Sweep (**read-only**)
5. Forensic / Persistence Checks (**read-only** — nothing to revert)
6. Web/App Backup Snapshot
7. User & Group Audit (needs `authorized.txt`)
8. Package Upgrade / Automatic Security Updates
9. Password Policies (aging + complexity)
10. **Password Strength Audit (detect & reset weak passwords)**
11. Account Lockout / Empty Passwords / nullok
12. SSH Hardening
13. Firewall (UFW / firewalld)
14. Kernel / sysctl Hardening
15. Unwanted Services & Packages
16. Service Config Hardening (FTP / Apache / ModSecurity / Nginx / PHP / DB)
17. File Permissions & umask
18. Display Manager (guest / autologin) — *restart deferred to end of run*
19. Auditd / rsyslog / Process Accounting
20. Fail2ban (SSH brute-force protection)
21. Mandatory Access Control (AppArmor / SELinux)
22. Security Audit Tools (ClamAV / rkhunter / Lynis / Unhide / Logwatch / Stacer)
23. Remove unauthorized media files (**destructive, NOT revertible**)
24. Package Integrity Audit
25. AIDE File Integrity Baseline

Package upgrades are logged, but package version rollbacks are not automated by
`revert.sh`; use package-manager snapshots/rollback tooling if you need version
rollback guarantees.

### Password Strength Audit (section 10)
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
   **skips the account(s) tied to the active sudo/login session** (`$SUDO_USER`, `logname`,
   `who am i`, `LOGNAME`, or `USER`). If the script is launched from a root shell where no
   non-root invoking user can be identified, it protects root and warns you to verify the
   displayed account scope before any reset.

> ⚠️ **john is a dual-use cracker and is on this toolkit's own purge list.** Using it to
> audit *your own* system is legitimate, but if the script installs it just for the audit
> it **auto-removes it afterward** so the hardened system isn't left with a cracker (and
> you don't lose competition points). The same applies to a `wordlists` package it installs.

### Risky items (always prompted, default No)
- Full package upgrade (can restart or change scored services)
- Web/app and DB backup snapshots (can be slow and stores secrets in the run dir)
- SSH port 22 → 2222
- `PasswordAuthentication no` (skipped automatically if no SSH keys exist)
- `AllowGroups sshusers`
- Enabling the firewall (SSH is allowed first to avoid lockout)
- Enabling `fail2ban` (can ban scoring/Orange Team source IPs if misconfigured)
- `fail2ban` ignore-list entries (trusted IPs/CIDRs will never be banned)
- Locking root
- Injecting `pam_pwquality` into PAM stacks
- Enforcing SELinux/AppArmor profiles
- `icmp_echo_ignore_all` (blocks ping; the checklist warns it can break scoring)
- Disabling IPv6
- Checklist TCP tuning / low `fs.file-max`
- `/etc/host.conf` `nospoof on` compatibility item
- BIND recursion ACLs / zone-transfer defaults (can break resolver clients or secondary DNS)
- Apache/Nginx directory-listing and browser-header hardening (can break intentional indexes, embeds, or cross-origin flows)
- PHP dangerous-function/session-cookie hardening (can break apps that call shell functions or use HTTP-only sessions)
- AIDE baseline initialization (trusts the current filesystem state)
- `pam_faillock` lockout-after-failures (Debian/Kali uses a corrected no-`authsucc`
  stack rewrite; RHEL/Fedora uses `authselect with-faillock`)
- Restricting `su` to the distro admin group (`sudo` or `wheel`)
- Applying password aging to existing accounts except protected invoking/session accounts
- Locking empty-password accounts except protected invoking/session accounts
- Resetting weak passwords (section 10 — confirmed before running)
- Apache ModSecurity setup in DetectionOnly mode
- Top-level home directory privacy and common log permission tightening
- Process accounting / rsyslog enablement (extra logging and service changes)
- Permanently deleting media files

### Competition notes
For the eCitadel orientation scenario, SSH, HTTP, and DNS are scored services.
The web checks expect the original dynamic functionality to keep working; static
HTML replacement is not enough. Scoring sources can change IPs, and most checks
use AD authentication, so do not block broad networks or break DNS/time/domain
dependencies. After risky sections, verify SSH, HTTP app login/functionality, and
DNS before moving on.

Useful read-only check inputs:
- `WEB_CHECK_URLS='http://127.0.0.1/ http://127.0.0.1/login'`
- `DNS_TEST_NAME='rrintel.internal'`
- `AD_DOMAIN='rrintel.internal'`
- `FAIL2BAN_IGNOREIP='10.0.0.5 10.0.0.0/24'`

### Distro-specific behavior
Debian / Ubuntu and Debian-like apt distros:
- Uses `apt`, `unattended-upgrades`, `apt-listchanges`, UFW, AppArmor, Debian
  OpenSSH service naming, `rsyslog`, `acct`, and `/etc/pam.d/common-*` PAM files.
- Uses Debian/Ubuntu web paths such as `/etc/apache2`, `/etc/nginx`, and
  `/etc/php/*/*/php.ini` when present. Apache ModSecurity uses
  `libapache2-mod-security2` when available.

RHEL / Fedora / AlmaLinux / Rocky Linux:
- Uses `dnf` or `yum`, `dnf-automatic` or `yum-cron`, firewalld, SELinux,
  `wheel`, `audit`, `rsyslog`, `psacct`, and `sshd`.
- Enables `faillock` through `authselect with-faillock` after `authselect check`
  passes; authselect-managed PAM files are not hand-edited.
- Uses RHEL-family paths such as `/etc/httpd`, `/etc/php.ini`, `/etc/my.cnf.d`,
  and BIND config locations when present. Apache ModSecurity uses `mod_security`
  when available.

`pam_faillock` lockout is prompted because bad PAM ordering can lock out GUI, TTY,
and sudo authentication. Older versions of this script blindly inserted this
Debian/Kali-family layout:

```
/etc/pam.d/common-auth:
auth    required    pam_faillock.so preauth silent deny=5 unlock_time=900 fail_interval=900
auth    [default=die]   pam_faillock.so authfail deny=5 unlock_time=900 fail_interval=900
auth    sufficient      pam_faillock.so authsucc

/etc/pam.d/common-account:
account required pam_faillock.so
```

The fragile line was `auth sufficient pam_faillock.so authsucc`: if it did not
return clean success in that service context, Debian's fallback `pam_deny.so`
could still run after a correct password. The current script instead uses the
Linux-PAM account-phase pattern: it does **not** add `authsucc`, inserts only an
`authfail` line before `pam_deny.so`, and increments Debian/Kali
`[success=N default=ignore]` controls by 1 so a successful password skips both
`authfail` and `pam_deny.so`.

Current Debian/Kali-family target shape:

```
/etc/security/faillock.conf:
deny = 5
unlock_time = 900
fail_interval = 900

/etc/pam.d/common-auth:
auth    required    pam_faillock.so preauth silent
auth    [success=N+1 default=ignore] pam_unix.so ...
auth    [default=die]   pam_faillock.so authfail
auth    requisite       pam_deny.so

/etc/pam.d/common-account:
account required pam_faillock.so
```

For RHEL/Fedora-family systems, the script uses:

```
authselect enable-feature with-faillock
authselect apply-changes
```

Keep a root/rescue shell open and test TTY/GUI/sudo before logout.

Systemd note:
- Write tasks that manage services require `systemctl`; non-systemd support is
  intentionally out of scope for now.

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

**Cannot be reverted:** permanently deleted media files. These are reported, not restored.

---

## Notable corrections made vs. the original checklist
- Fixed commands that used en-dashes/smart-dashes instead of `--`.
- The toolkit uses **UFW *or* firewalld** (never raw iptables on top of UFW, which conflict).
- vsftpd-restart copy-paste error (it restarted gdm) and the bogus
  `banner-message-enable` directive are not reproduced; FTP hardening uses
  `ftpd_banner` and validates/restores around service restart.
- `Protocol 2` is **not** emitted — it's removed on OpenSSH ≥ 7.6 and would fail `sshd -t`.
- SSH config is validated with `sshd -t` before restart; on failure the backup is restored.
- `PasswordAuthentication no` is only offered when SSH keys actually exist.
- Firewall always allows SSH **before** enabling, to prevent lockout.
