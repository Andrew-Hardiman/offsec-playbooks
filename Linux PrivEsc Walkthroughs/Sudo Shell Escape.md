
⚠️ **Hard preconditions.**

- **Current user has sudo entitlement to at least one binary** for which a GTFOBins entry exists with a Shell function AND the Shell function has a populated Sudo tab.
- **Authentication available.** Either NOPASSWD on the chosen binary, or the current user's password (foothold creds usually suffice).
- **Non-destructive.** No filesystem modification; root shell spawned in-process. IOCs: `auth.log` entry for the `sudo` invocation.

No external lookup needed beyond GTFOBins for the specific payload — preconditions checked below.

---

## Enumerate sudo entitlements

### List ALL sudo-allowed commands:

`sudo -l`

If prompted for password, enter the current user's password if known. NOPASSWD entries surface without a password.

For each binary in output:

- `(root) NOPASSWD: /file/path/<binary>` → note the binary.
- `(root) /file/path/<binary>` (no NOPASSWD) → note the binary; password required at execution.
- `User <user> is not allowed to run sudo on <host>.` → walkthrough doesn't apply.
- `env_keep+=LD_PRELOAD` or `env_keep+=LD_LIBRARY_PATH` lines alongside any NOPASSWD entry → [[Sudo Environment Variables]] is a parallel route worth considering.
- `sudo: a password is required` (no further output) or "you must have a tty" → see [[Reverse Shell Stabilization]] for TTY upgrade.

### Exploit via GTFOBins:

Pass the noted binaries (primitive = **Sudo**) as the list to [[GTFOBins Cross-Reference]] — it loops them, stops at the first that elevates, and returns one verdict.

- Returns **root** → proceed to Decision.
- Returns **none elevated** → walkthrough doesn't apply → return to [[Linux Privilege Escalation Checksheet]].

---
## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

## Validation

THM:Linux PrivEsc:Task 6 Sudo - Shell Escape Sequences

