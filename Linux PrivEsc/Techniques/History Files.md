
**Pre-root** credential harvesting. Read-only enum from foothold user's perspective.

---

## Step 1 — Paste and run `history_enum.sh`

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/history_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output markers:

- `HISTORY_CRED[<file>]: <line_number>: <line>` → credential pattern hit. Multiple lines may appear across same and different files. Each is a candidate. Identify target principal from each `<line>` (usually obvious from command context: `mysql -uroot -p<pw>` → root; `ssh alice@host` → alice, etc.) → Proceed to Step 2 with the candidate list.
- `HISTORY_FOUND: <file>` → informational; script scanned this file, no credential pattern matched. No action (**delete or ignore**).
- `HISTORY_EMPTY` → no readable history files exist. Technique inapplicable. Return to [[Linux Privilege Escalation Checksheet]] `Credential Harvesting`.
- No `HISTORY_CRED` markers in output → script found no creds in any history file. Return to [[Linux Privilege Escalation Checksheet]] `Credential Harvesting`.

---

## Step 2 — Use extracted credential

For each candidate from Step 1, in order of likely root yield:

Most common: cred is for a local Linux account.

`su <user>`

(Enter `<password>` when prompted.)

`id`

- `uid=0(root)` → root achieved. Proceed to Decision.
- Non-root `<user>` → lateral foothold. Re-enter [[Linux Privilege Escalation Checksheet]] from `<user>`'s context.
- `Authentication failure` → either (a) target user guess wrong → try the same cred against the next likely user (other interactive accounts in `/etc/passwd`), or (b) cred is for a non-local target:
    - MySQL cred + `mysqld` running as root → [[MySQL UDF]]
    - SSH cred (host reachable from foothold) → `ssh <user>@<host>`
    - API token / cloud key / app-specific cred → log for later, move to next candidate.

All candidates exhausted with no root yield → return to [[Linux Privilege Escalation Checksheet]] `Credential Harvesting`.

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

---

## Validation

THM:Linux PrivEsc:Task 16 Passwords & Keys - History Files