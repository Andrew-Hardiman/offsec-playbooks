
> **STATUS: AUDITED** — first-principles derivation (primary sources: HackTricks, PayloadsAllTheThings, OSCP prep guides; empirical from GPI room `/etc/password.txt` case) 2026-09-14; sandbox-verified via `loose_creds_enum_tests.sh` (70/70 tests pass) and `loose_creds_triage_tests.sh` (84/84 tests pass); `user:password` handler path live-validated on THM:Guided Pentest: Infrastructure 2026-09-16; PEM / `user:hash` / URL-embedded / KV / env-shape handler paths and bare-password / unstructured fallback handlers not yet live-validated.

**Pre-root** credential harvesting via filename-hunted candidate files. 

---

## Step 1 — Paste and run `loose_creds_enum.sh`

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/loose_creds_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output markers:

- `LOOSE_CRED_FILE: <file>` → candidate. Multiple lines may appear. Each is a candidate. → Proceed to Step 2 with the candidate list.
- `LOOSE_CRED_EMPTY` → no readable files with suspicious names found across all tree-classes. Technique inapplicable. Return to [[Linux Privilege Escalation Checksheet]] `Credential Harvesting`.
- No markers in output → paste did not execute (terminal issue, syntax mangling, or connection drop). Retry.

---

## Step 2 — Triage each candidate, then apply matching handler

Define the `triage` function on target — paste ONCE, reused across all candidates. On **attacker**:

`sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/loose_creds_triage.sh | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste at target prompt. `triage` is now defined for the session.

For each `LOOSE_CRED_FILE: <file>` from Step 1, on target:

`triage <file>`

Route on emitted markers (priority order — most specific first):

| Marker              | Handler section              |
| ------------------- | ---------------------------- |
| LOOSE_CRED_PEM      | PEM private key handler      |
| LOOSE_CRED_HASH     | `user:hash` handler          |
| LOOSE_CRED_URL      | URL-embedded handler         |
| LOOSE_CRED_KV       | KV / env-shape handler       |
| LOOSE_CRED_USERPASS | `user:password` handler      |

No markers → triage detected no structural cred shape. Fall back: `cat <file>` on target and identify shape by eye (bare password, unstructured content, or shape triage missed). Apply matching handler from list above, or Bare password / Unstructured handler.

All candidates exhausted → cleanup and return to [[Linux Privilege Escalation Checksheet]] `Credential Harvesting`.

**Cleanup on target:** `unset -f triage`

#### PEM private key handler

Marker: `LOOSE_CRED_PEM[<file>]: <line>:-----BEGIN [X] PRIVATE KEY-----`

Triage detects the BEGIN line only. `cat <file>` on target to see the full block. Copy from `-----BEGIN` through `-----END` inclusive. On **attacker**:

`cat > /tmp/key.pem << 'EOF'`

(Paste the key, then on a new line type `EOF` and Enter.)

`chmod 600 /tmp/key.pem`

Identify the user the key belongs to:

- File path `/home/<user>/...` → `<user>` from path.
- File path `/root/...` → `root`.
- File path generic (`/etc/...`, `/opt/...`, `/tmp/...`) → try `<user>` from interactive accounts: `awk -F: '($3==0||$3>=1000)&&$7!~/(nologin|false)/{print $1}' /etc/passwd`. Prioritise `root`.

`ssh -i /tmp/key.pem <user>@<target>`

- Connection succeeds → in as `<user>`. `id` — `uid=0(root)` → root achieved, Decision. Otherwise re-enter [[Linux Privilege Escalation Checksheet]] from `<user>`'s context.
- `Permission denied (publickey)` → key not authorized for `<user>`; try next `<user>`. All exhausted → next candidate.

#### `user:hash` handler

Marker: `LOOSE_CRED_HASH[<file>]: <line>:<user>:<hash-prefixed-value>` — or bare hash-prefixed value with no user.

Route to [[Cracking Hashes]] — shared utility handles hash-type detection and cracking. On success, feed cracked plaintext into `user:password` handler below with the extracted `<user>` (or, for bare-hash-no-user cases, infer `<user>` from filename/path).

#### URL-embedded handler

Marker: `LOOSE_CRED_URL[<file>]: <line>:...<scheme>://<user>:<pass>@<host>...`

Extract `<user>` and `<pass>` from the userinfo component. On target:

`su <user>`

(Enter `<pass>` at prompt.)

`id`

- `uid=0(root)` → root achieved. Proceed to Decision.
- Non-root `<user>` → lateral foothold. Re-enter [[Linux Privilege Escalation Checksheet]] from `<user>`'s context.
- `Authentication failure` → cred was service-scoped (mysql/mongo/ftp/etc.), not OS. Try the service directly using the scheme (`mysql -u<user> -p<pass> -h<host>`, `ftp <host>`, etc.). Still no root path → next candidate.

#### KV / env-shape handler

Marker: `LOOSE_CRED_KV[<file>]: <line>:<content>` — inline `<keyword>=<value>` / `<keyword>: <value>`, or env-shape `<VAR><KEYWORD><SUFFIX>=<value>`.

Extract `<value>` — everything after the first `=` or `:` (strip surrounding quotes and trailing whitespace/comments).

Identify target principal:

- Filename contains `<user>_password`, `<user>_creds`, `<user>.pwd` etc. → `<user>` from filename prefix.
- Path `/home/<user>/...` → `<user>` from path.
- Path `/root/...` → `root`.
- Path generic (`/etc/...`, `/opt/...`, `/tmp/...`) → try `root` first, then each interactive user from `awk -F: '($3==0||$3>=1000)&&$7!~/(nologin|false)/{print $1}' /etc/passwd`.

For each candidate `<user>`: apply `user:password` handler below with `<pass> = <value>`.

#### `user:password` handler

Marker: `LOOSE_CRED_USERPASS[<file>]: <line>:<user>:<password>`

On target:

`su <user>`

(Enter `<password>` at prompt.)

`id`

- `uid=0(root)` → root achieved. Proceed to Decision.
- Non-root `<user>` → lateral foothold. Re-enter [[Linux Privilege Escalation Checksheet]] from `<user>`'s context.
- `Authentication failure` → either (a) cred stale, or (b) user requires SSH not local — try `ssh <user>@<target>` with `<password>`; still fails → next candidate.

#### Bare password handler

Fallback only — reached when triage emitted no marker for the file. Content is a single non-empty line with no colon, no `=`. Use `<value>` as `<pass>` in the KV / env-shape handler above (path-based user inference applies).

#### Unstructured handler

Fallback only — reached when triage emitted no marker for the file. File content doesn't match any of the above shapes. `cat <file>` and read; apply operator judgement. If any recognisable substructure emerges (multi-line user/password pairs, config-shape lines with `key = value`, etc.), apply the matching handler above.

All handlers exhausted for the current candidate with no root yield → next candidate.

---
## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

---

## Validation

- THM:Guided Pentest: Infrastructure
