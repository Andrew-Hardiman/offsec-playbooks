## Purpose and status

Design specification for enhancing [[Linux Privilege Escalation Checksheet]]'s **Root-owned Services** step (currently Step 10 at time of writing; step numbers change — search on note title or wikilinks). Preserves the empirical findings and design decisions from a build-design session where the build itself was deferred to first real-target encounter per V_S "build-when-encountered convention extends from walkthroughs to enum scripts".

**Status: build-when-encountered.** The enhancement adds a secondary detection probe (systemd unit view) alongside the existing primary probe (`ps -ef`-based) plus a diagnostic preflight probe (procfs `hidepid=` check). The current primary probe correctly handles all OSCP+/CTF/THM lab targets — near-100% of targets Andrew will face pre-first-engagement. The secondary detection fires meaningfully only on hardened engagement targets (procfs `hidepid=` set, systemd `ProtectProc=` on a service unit) or on targets using systemd socket activation with an idle daemon at scan time. Neither pattern is present on lab-tier targets; both are realistic on hardened production engagement targets.

**When to consult this note and build:** first real encounter with a target where the current primary probe returns empty despite known-installed services (e.g. mysql package installed, `ps` shows nothing), OR when linpeas or another tool surfaces a root-runnable service that the primary probe missed. That is the canonical validation context per V_S convention — implement against a real target with fresh systemd version awareness, not speculatively.

**Related in-vault artefacts (already applied at time of writing, do not re-apply):**
- [[MySQL UDF]] Step 1 `mysqld OS user` block: third bullet added handling "no mysqld process line" case (covers hidepid, ProtectProc=, socket-activated-idle, remote-only-access, other ps-failure modes). Sibling walkthroughs likely need parallel edits — see "Related walkthrough audit" section below.
- LPEC Step 6 (Init system hijacking) systemd sub-block: second ⚠️ note added flagging build-time considerations for `~/scripts/systemd_enum.sh` (unrelated to this Secondary Detection build, but flagged for reference — the two builds may inform each other on systemd enumeration patterns).

**Not yet applied — this build's deliverables:**
- LPEC Step 10 restructure (Preflight + Primary marker + Secondary sub-block + unified routing).
- `~/scripts/root_services_enum.sh` — enumeration script.
- `~/scripts/root_services_enum.tests.sh` — regression tests.
- `Scripts_Index.md` entry for the above.

---

## Motivation — why the current primary probe has blind spots

Current LPEC Step 10 primary probe:

```
ps -ef | awk '$1=="root" && $8 !~ /^\[/'
```

Enumerates root-owned processes and filters kernel threads (bracketed names). Under default Linux configurations, this catches every root daemon on the target. **On OSCP+/CTF/THM lab targets, it is complete and correct.**

Three specific target classes cause it to under-report:

### Class 1 — procfs mounted with `hidepid=<n>` where `<n>` ∈ {1, 2, 4}

Under any active `hidepid` mode, unprivileged foothold's `ps -ef` sees only foothold's own processes. All other-user processes (including root daemons) are hidden. The awk filter matches nothing.

- Common on CIS-benchmark-hardened production Linux systems.
- Essentially never present on OSCP+/CTF/THM boxes.
- Named modes (`hidepid=noaccess`, `hidepid=invisible`, `hidepid=ptraceable`) supported on kernel 5.8+ are semantic equivalents to numeric `hidepid=1`, `=2`, `=4` respectively; kernel translates on remount.

### Class 2 — systemd `ProtectProc=` set on a specific `.service` unit

Per-service hidepid via systemd unit directive (`ProtectProc=noaccess`/`invisible`/`ptraceable`). Applies hidepid semantics scoped to that service without touching global `/proc/mounts`. From foothold's perspective the specific hardened service is invisible via `ps` even though global procfs is unrestricted.

- Realistic on hardened production systems where specific sensitive services (databases, secret managers) are hardened individually rather than system-wide.
- Preflight (which reads only global `/proc/mounts`) is blind to this. Only systemd unit view catches it. **This is the primary design justification for having a Secondary probe as a separate sub-block.**

### Class 3 — systemd socket-activated services with idle daemon at scan time

Systemd binds the socket at boot (as root, because systemd is init) and holds the listening FD. The associated `.service` unit is triggered on first client connect — systemd spawns the daemon, hands it the FD, and the daemon begins serving. Until first connect, no daemon process exists for `ps` to see.

- Not hardening; a design choice. Common for services with variable load profiles (postgres on some RHEL configurations, cups, dbus, several others).
- Independent of hidepid state. Occurs on baseline non-hardened targets.
- **Key insight:** the walkthrough that follows (e.g. [[MySQL UDF]]) starts with a `connect to daemon` step. That connect triggers systemd's activation transparently — daemon spawns, connect succeeds, walkthrough proceeds normally. No extra "wake" step needed in the walkthrough. Class 3 is invisible to `ps` but fully exploitable via the standard walkthrough IF Secondary detection surfaces it.

### Not covered — other process-hiding mechanisms (documented gap)

- LD_PRELOAD userspace rootkits hooking `readdir` on `/proc`.
- Kernel rootkits hooking `sys_getdents`.
- PID namespaces (container confinement).
- `prctl(PR_SET_NAME)` renaming a process to bracketed-name form to evade the awk kernel-thread filter.

Blind spots for BOTH primary and secondary probes. No defensive move in the enumeration — we cannot detect what we cannot detect. Documented gap; do not attempt to catch these in the script.

---

## Empirical findings (sandbox-verified during design session)

**Kernel tested:** 6.18.5. Sandbox was a container with systemd installed but not running as PID 1 (container init was `/process_api --firecracker-init`). Consequence: `systemctl` commands could not connect to bus — `systemctl list-units`, `systemctl show`, etc. were unverifiable end-to-end. Kernel-level behaviour (procfs hidepid, `ps` output) was fully verifiable via remount and `runuser -u nobody`.

### Preflight probe verification (10 test cases, all pass)

Probe:

```
grep -oE 'hidepid=(1|2|4|noaccess|invisible|ptraceable)' /proc/mounts | awk '{print "PROCFS_HIDEPID: " $0}'; echo "PROCFS_SCANNED"
```

Verified: catches all six hiding modes (numeric 1/2/4 and named noaccess/invisible/ptraceable); correctly ignores `hidepid=0` and `hidepid=off`; handles absent `/proc/mounts` gracefully (emits only `PROCFS_SCANNED`).

Kernel behaviour observed on remount:
- Passing `hidepid=1` to `mount -o remount` produces `hidepid=noaccess` in `/proc/mounts`.
- Passing `hidepid=2` produces `hidepid=invisible`.
- Kernel translates numeric to named form at the point of mount, so recent kernels may present named forms even when numeric was passed. Regex must catch both to be portable across kernel versions.

### `ps -ef` behaviour under each hidepid mode (verified via `runuser -u nobody`)

Correction of a documentation-based assumption made earlier in the design session (this note preserves the correction to prevent regression on future build):

| Mode | Foothold's `ps -ef` line count | Primary probe (awk-filtered) output |
|---|---|---|
| off (hidepid=0 or unset) | 62 (all processes visible) | 5 root non-kernel-threaded lines including PID 1 |
| hidepid=1 (noaccess) | 2 (header + own ps only) | empty |
| hidepid=2 (invisible) | 2 (header + own ps only) | empty |

Kernel 6.18.5 behaviour under hidepid=1 differed from expectation: `ls /proc | grep '^[0-9]'` from unprivileged user still shows all PIDs (directory entries visible), but `ls -la /proc/<other-uid-pid>/` returns `Operation not permitted` and `cat /proc/<pid>/status` returns `Operation not permitted`. `ps -ef` drops other-user processes entirely from its output rather than showing them with blank UID column — because it cannot read `/proc/<pid>/stat` to populate ANY column, it skips the process. Consequence for our detection: under any active hidepid mode, the awk `$1=="root"` filter matches nothing, not because it fails to match UIDs but because there are no other-user rows to match.

**Impact on design:** the routing bullets for the primary probe should not attempt to distinguish "empty because hidepid" from "empty because paste failed" via marker semantics on the primary probe itself. Distinguishing that requires the Preflight probe running BEFORE the primary. That's why Preflight exists as a separate diagnostic step.

### `ps` output distinction — "no output" vs "header only"

The primary probe as written (`ps -ef | awk ...`) with the awk filter applied at pipeline end produces:
- Zero lines under any active hidepid mode from foothold.
- Multiple lines under hidepid off (at least PID 1 = init/systemd).

The awk filter drops the header (since `$1` for the header is `UID`, not `root`), so under hidepid the output is genuinely empty — not "header only". This differs from walkthroughs that use `ps -ef | awk 'NR==1 || /[daemon]/'` (where NR==1 preserves the header) — those produce "header only" output when the daemon isn't visible. Do not conflate the two patterns when reasoning about output.

### systemctl availability in the design sandbox — limitations acknowledged

The build container had systemd installed but not running as PID 1. All systemctl calls returned "System has not been booted with systemd as init system. Can't operate. Failed to connect to bus: Host is down." Consequence: the following COULD NOT be sandbox-verified during design and MUST be verified during real-box build:

- `systemctl list-units --type=service --state=active --no-legend --plain` output shape.
- `systemctl list-units --type=socket --state=listening --no-legend --plain` output shape.
- `systemctl show <unit> -p User --value` behaviour (does empty output indicate default = root, or is there always a value?).
- `systemctl show <socket> -p Triggers --value` output format on multi-trigger sockets (space-separated? comma-separated?).
- `systemctl --version` output format across systemd versions (for the `--value` portability gate).
- `systemctl` behaviour when run by unprivileged foothold user (any polkit restrictions).

The script structure is a specification; the specific command output parsing must be validated at build time against a real running-systemd target.

---

## Design decisions (rationale-preserving)

### Preflight probe purpose — diagnostic, not routing

Preflight fires a single probe checking global `/proc/mounts` for active hidepid modes. Its output is diagnostic context: it tells the operator whether to expect empty primary output (hidepid detected → yes, blindness is happening) or not (hidepid off → primary should see everything on a functional Linux system). It does NOT gate anything — Secondary runs regardless of Preflight state (Secondary catches ProtectProc= and socket-activated-idle daemons which are independent of global hidepid).

Design decision made after considering alternatives:
- Preflight gates Secondary (Secondary runs only if hidepid detected): rejected. Socket-activated-idle daemons are independent of hidepid — gating Secondary on hidepid would miss them entirely.
- Preflight replaces Primary (skip primary if hidepid detected): rejected. Primary is cheap and confirms the diagnostic — under hidepid it should return empty, and confirmation is worth the trivial cost.
- Preflight is purely informational, Secondary always runs: **chosen.** Simplest, catches all three blind-spot classes, does not miss coverage.

Preflight bullets in LPEC should be written as diagnostic context (prose form), not routing bullets. Routing bullets imply "match output → take action", which Preflight does not do. Every Preflight branch is "continue" — that is not routing.

### Two-class blind-target model — identical operator remediation

Under Secondary detection, blind daemons surface in one of two classes:
- **Class A** — hidepid-blinded or ProtectProc='d daemon that IS currently running. Daemon exists on target; connect works immediately.
- **Class B** — socket-activated daemon whose `.service` is idle. Daemon does not exist yet; connect triggers systemd's socket activation transparently — systemd spawns the daemon in response to the incoming connection, connect completes (slightly delayed during spawn), daemon proceeds normally.

**Critical insight: both classes have IDENTICAL operator remediation for connect-and-exploit walkthroughs.** For [[MySQL UDF]], [[Postgres UDF]], [[Redis Configuration File Write]], [[Tomcat Manager WAR Deploy]] — the walkthrough's normal connect step (e.g. `mysql -u root`, `psql -h localhost -U postgres`, `redis-cli`, HTTP request to Tomcat manager) works in both classes. The walkthrough's internal ps-based UID preflight (where present, e.g. MySQL UDF Step 1) fails in both classes — remediation in both classes is "skip the ps preflight, connect anyway, defer UID confirmation to authenticated session via `do_system('id')` or equivalent".

Because remediation is identical, the class distinction is NOT routing-critical. Secondary emits ONE marker per daemon regardless of class. The operator does not need to know which class surfaced the daemon.

**Exception (documented, not currently triggered):** if a future walkthrough surfaces a PID-dependent exploit (gdb attach to daemon, signal send, `/proc/<pid>/environ` read of daemon's env), Class A and Class B diverge — Class A has a PID (blocked by hidepid but exists), Class B has no PID (spawns on connect, PID appears only after). None of the current watchlist walkthroughs need PID. Revisit if/when such a walkthrough is added.

### UID filter requirement (Concrete misroute example if dropped)

Primary probe filters to root-owned processes via awk `$1=="root"`. Secondary MUST equivalently filter to daemons whose runtime UID is root. If Secondary skips this filter, misroutes occur.

**Concrete failure mode:** target is a default Debian or Ubuntu with `mysqld` running as `mysql` OS user (this is the shipped default — the mysql package configures `User=mysql` in the .service unit). Primary probe: `ps -ef | awk '$1=="root"'` correctly excludes mysqld (its UID is `mysql`, not `root`) — no route emitted, correct. Naive Secondary that just checks `systemctl is-active mysql.service` sees `active` → emits `SERVICE_ROOT[mysqld]: mysql.service` → routes to [[MySQL UDF]] → operator runs the walkthrough → exploit yields shell as `mysql` OS user, not root. Wasted work AND a misroute that Primary would have caught.

**Secondary's filter mechanism:** for each unit under consideration, query `systemctl show <unit> -p User --value`. Result interpretation:
- Empty output → systemd default → daemon spawns as root → route.
- `root` → explicit root → route.
- Any other value → non-root service account → drop.

For socket-activated services: the `User=` on the `.service` unit determines the spawned daemon's UID (NOT the `.socket` unit's ownership or the socket file's ownership on disk — systemd holds the listening FD as root regardless, then drops privileges per the `.service` unit's `User=` at spawn time). So the User= check must be on the resolved `.service`, not on the `.socket`.

### Yield-discipline catch-all preservation

Primary probe's routing bullet "any other root-owned service → [[Service Known Exploits]]" is a catch-all that lets `ps` surface novel root daemons not in the named-daemon watchlist (mysqld/postgres/redis/tomcat). Under Secondary, if we only enumerate the named watchlist, we lose this catch-all — hidepid targets get strictly less coverage than non-hidepid targets, which violates V_S yield-estimation discipline ("default: include the detection; defer requires positive evidence the vector is low-yield").

**Secondary MUST enumerate ALL root-runnable running-or-listening units,** name-match each against the watchlist, emit named markers for matches, emit `SERVICE_ROOT[unknown]: <unit>` for unmatched root-runnable units. The catch-all routes to [[Service Known Exploits]] for CVE lookup on the unrecognised daemon.

### Systemctl-unavailable degraded fallback

Not all Linux targets have systemd. Alpine (openrc), older Debian pre-Jessie (SysV init), custom-init embedded systems, some hardened build-your-own configurations. Secondary must degrade gracefully when systemctl is absent.

Detection: `command -v systemctl >/dev/null 2>&1`. If absent: emit informational marker `SYSTEMD_UNAVAILABLE` (per V_S informational-marker convention for source-absent enumeration results) and retreat to a filesystem-based enumeration:

```
find /var/run /run -maxdepth 2 -name "*.pid" -newer /proc/1/status 2>/dev/null
```

For each pid file discovered: read the pid, attempt `readlink /proc/<pid>/exe` (may fail under hidepid), cross-reference the pid file's filename stem (without `.pid`) against the watchlist. Emit `SERVICE_ROOT[<class>]: <pidfile>` for matches, `SERVICE_ROOT[unknown]: <pidfile>` for non-matches.

Coverage is strictly less than the systemctl path (pid files may be stale, may not exist for all daemons, cannot distinguish daemon UID). The `SYSTEMD_UNAVAILABLE` marker signals the operator to expect gaps and consider manual enumeration as supplement.

Systemd version awareness — the `--value` portability gate

`systemctl show <unit> -p <property> --value` returns the bare property value (no `Property=Value` prefix). Introduced in systemd 230 — present on:
- Ubuntu 16.10 and later.
- Debian 9 (Stretch) and later.
- RHEL 8 and later.
- Fedora 24 and later.

Older systemd (present on RHEL 7 / CentOS 7, Ubuntu 16.04, Debian 8) does NOT support `--value` — `-p <property>` returns `Property=Value` format. Script must probe systemd version once at start:

```
systemctl --version | head -1 | awk '{print $2}'
```

Returns integer major version. Branch parsing behaviour accordingly. For systemd < 230, parse `=`-delimited: `systemctl show <unit> -p User | cut -d= -f2-`.

### Triggers property parse-fragility

For socket-to-service resolution, `systemctl show <socket> -p Triggers` returns the associated service unit(s). Multi-trigger sockets (one `.socket` unit triggering multiple `.service` units — rare but exists) return space-separated values. Script must iterate on whitespace-split, not assume single-value. Fallback for empty `Triggers`: `${socket_name%.socket}.service` basename replacement (systemd default: a `.socket` unit with no explicit trigger points to its same-basename `.service`).

Example expected outputs (to be verified at build time against real systemd):
```
# Single-trigger socket
$ systemctl show sshd.socket -p Triggers --value
sshd.service

# Multi-trigger (hypothetical, rare)
$ systemctl show some.socket -p Triggers --value
service-a.service service-b.service

# No triggers explicitly set (falls back to basename replacement)
$ systemctl show foo.socket -p Triggers --value

```

### Daemon watchlist matching approach

Watchlist entries and expected unit-name variants observed across distros:

| Class | Unit-name patterns |
|---|---|
| `mysqld` | `mysql.service`, `mysqld.service`, `mariadb.service`, `mariadbd.service` |
| `postgres` | `postgresql.service`, `postgresql-<version>.service` (e.g. `postgresql-13.service`, `postgresql@<version>-<cluster>.service`) |
| `redis` | `redis.service`, `redis-server.service`, `redis@<instance>.service`, `redis-server@<instance>.service` |
| `tomcat` | `tomcat.service`, `tomcat<version>.service` (e.g. `tomcat9.service`, `tomcat10.service`) |

Match approach: strip `.service` suffix, strip `@<instance>` suffix if present, compare stem against class keyword prefix. Case-insensitive to accommodate distro variation. Instance-specific units (multi-instance daemons) route to the same class marker — the walkthrough is instance-agnostic.

---

## Proposed LPEC restructure (paste-ready when built)

Replaces the current published shape. Adds Preflight, adds `PS_ROOT_SCANNED` marker to primary, adds Secondary sub-block, extends routing bullets to unified across Primary + Secondary, preserves the existing architectural note verbatim.

```
## <current step number> — Root-owned services

### Preflight — procfs hidepid check:

`grep -oE 'hidepid=(1|2|4|noaccess|invisible|ptraceable)' /proc/mounts | awk '{print "PROCFS_HIDEPID: " $0}'; echo "PROCFS_SCANNED"`

Diagnostic context — output informs interpretation, does not route. `PROCFS_HIDEPID: <mode>` before `PROCFS_SCANNED` = hidepid active; Primary detection below will return empty output regardless of what root daemons are running (Secondary detection handles the blind). Only `PROCFS_SCANNED` alone = hidepid off; Primary detection has full process visibility (Secondary still runs — covers socket-activated-idle daemons and per-service `ProtectProc=` regardless of hidepid state).

### Primary detection — visible root-owned processes:

`ps -ef | awk '$1=="root" && $8 !~ /^\[/'; echo "PS_ROOT_SCANNED"`

Emits raw ps lines for root-owned non-kernel-threaded processes + scan-completion marker. Routes via unified routing below.

### Secondary detection — systemd unit view:

Deploy `~/scripts/root_services_enum.sh` per the standard attacker→target paste-body pattern (see [[Scripts Index]] for invocation form).

Marker contract:

| Marker | Routing |
|---|---|
| `SERVICE_ROOT[mysqld]: <unit>` | [[MySQL UDF]] |
| `SERVICE_ROOT[postgres]: <unit>` | [[Postgres UDF]] |
| `SERVICE_ROOT[redis]: <unit>` | [[Redis Configuration File Write]] |
| `SERVICE_ROOT[tomcat]: <unit>` | [[Tomcat Manager WAR Deploy]] |
| `SERVICE_ROOT[unknown]: <unit>` | [[Service Known Exploits]] |
| `SYSTEMD_UNAVAILABLE` | informational; degraded filesystem enum follows |
| `SERVICE_SCANNED` | positive scan-completion (always emitted) |

### Routing (unified across Primary + Secondary):

Primary emits raw ps content matched by keyword; Secondary emits tagged markers. Both feed the same routing key (daemon class).

- `mysqld` in Primary, OR `SERVICE_ROOT[mysqld]: <unit>` in Secondary → [[MySQL UDF]]  (DOES THIS COVER MARIADB ALSO???)
- `postgres` in Primary, OR `SERVICE_ROOT[postgres]: <unit>` in Secondary → [[Postgres UDF]]
- `redis-server` in Primary, OR `SERVICE_ROOT[redis]: <unit>` in Secondary → [[Redis Configuration File Write]]
- `org.apache.catalina.startup.Bootstrap` in cmdline args in Primary, OR `SERVICE_ROOT[tomcat]: <unit>` in Secondary → [[Tomcat Manager WAR Deploy]]
- Any other root-owned service in Primary, OR `SERVICE_ROOT[unknown]: <unit>` in Secondary → [[Service Known Exploits]]
- Only `PS_ROOT_SCANNED` from Primary AND only `SERVICE_SCANNED` from Secondary (no daemon markers from either) → no root-runnable service PrivEsc route; proceed to next step.
- No output at all from either probe → paste did not execute. Retry.

> **Architectural note.** Enumeration filters to UID=root by design. The rare case of a non-root daemon with a CVE that directly grants root is excluded by this filter. If that case is ever encountered, the response is pre-decided: drop the awk root filter, rename the step, update inline bullets with explicit "running as root" qualifiers, broaden Service Known Exploits to UID-agnostic. **No re-deliberation.** Full reasoning in Vault_Strategy.md `Decisions held` — search "service known exploits root-gating decision".
```

Notes on the restructure:
- The `(DOES THIS COVER MARIADB ALSO???)` TODO in the mysqld routing bullet is preserved verbatim — it is an unresolved question from a prior session and should not be silently dropped when this restructure lands.
- Preflight is written in prose diagnostic form, not routing bullets — the routing-bullet visual pattern implies "match output → action" which Preflight does not do.
- Existing architectural note preserved verbatim at the bottom.

---

## Proposed script — `~/scripts/root_services_enum.sh`

### Purpose

Enumerate root-runnable systemd services and socket-activated services from an unprivileged foothold. Emit tagged markers routing to the LPEC Root-owned Services routing bullets. Filters to units whose spawn UID is root (matching primary probe's awk filter). Degrades to filesystem-based enumeration if systemctl is unavailable.

### Runtime environment

Runs on target as unprivileged foothold (no root required for enumeration — systemctl queries do not require polkit escalation for read-only operations like `list-units` and `show`). Bash 4+ assumed (associative arrays used for watchlist matching — verify at build time whether bash 3 fallback is worth the complexity).

### Algorithm

```
1. Preamble
   - shebang: #!/bin/bash
   - set -o pipefail (do NOT set -e — enumeration must continue past individual unit query failures)
   - error output redirected to /dev/null throughout (foothold context; no need to leak stderr on target)

2. systemctl availability check
   - if ! command -v systemctl >/dev/null 2>&1: goto step 8 (degraded fallback)

3. Systemd version detection
   - systemd_major=$(systemctl --version 2>/dev/null | head -1 | awk '{print $2}')
   - if [ "$systemd_major" -ge 230 ]: SHOW_ARGS="--value"
   - else: SHOW_ARGS=""  # older systemd, parse Property=Value

4. Enumerate active services
   - systemctl list-units --type=service --state=active --no-legend --plain 2>/dev/null | awk '{print $1}' → active_services list

5. Enumerate listening sockets and resolve to services
   - systemctl list-units --type=socket --state=listening --no-legend --plain 2>/dev/null | awk '{print $1}' → listening_sockets list
   - For each socket:
     - triggers=$(systemctl show <socket> -p Triggers $SHOW_ARGS 2>/dev/null)
     - if $SHOW_ARGS empty (systemd < 230): triggers=${triggers#Triggers=}
     - if triggers empty: triggers="${socket%.socket}.service"
     - iterate on whitespace-split of triggers, add each to socket_derived_services list

6. Deduplicate and filter by UID
   - all_services = active_services ∪ socket_derived_services (dedup)
   - For each service:
     - user=$(systemctl show <service> -p User $SHOW_ARGS 2>/dev/null)
     - if $SHOW_ARGS empty: user=${user#User=}
     - if [ -z "$user" ] || [ "$user" = "root" ]: keep; else drop
   - → root_services list

7. Name-match and emit markers
   - For each unit in root_services:
     - strip .service suffix and @<instance> suffix → stem
     - lower-case stem for matching
     - if stem matches mysql|mysqld|mariadb|mariadbd: emit "SERVICE_ROOT[mysqld]: <unit>"
     - elif stem matches postgresql|postgres (prefix): emit "SERVICE_ROOT[postgres]: <unit>"
     - elif stem matches redis|redis-server (prefix): emit "SERVICE_ROOT[redis]: <unit>"
     - elif stem matches tomcat (prefix, allow numeric version suffix): emit "SERVICE_ROOT[tomcat]: <unit>"
     - else: emit "SERVICE_ROOT[unknown]: <unit>"
   - skip step 8 (systemctl path complete), goto step 9

8. Degraded fallback (systemctl unavailable)
   - echo "SYSTEMD_UNAVAILABLE"
   - find /var/run /run -maxdepth 2 -name "*.pid" -newer /proc/1/status 2>/dev/null
   - For each pid file:
     - stem = basename without .pid
     - lower-case stem for matching
     - apply same watchlist regex as step 7 → emit appropriate SERVICE_ROOT marker
     - unmatched → SERVICE_ROOT[unknown]: <pidfile>

9. Emit scan completion
   - echo "SERVICE_SCANNED"
```

### Marker format contract (must match LPEC routing bullets exactly)

- `SERVICE_ROOT[<class>]: <unit_or_path>` — class ∈ {mysqld, postgres, redis, tomcat, unknown}.
- `SYSTEMD_UNAVAILABLE` — informational, emitted only when systemctl is absent.
- `SERVICE_SCANNED` — always emitted as final line, even when no other markers fire.

### Deployment invocation pattern (matches `af_unix_sock_enum.sh` precedent)

On attacker:

```
(echo "bash <<'EOF'"; sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' ~/scripts/root_services_enum.sh; echo "EOF") | xclip -selection clipboard
```

(Wayland: substitute `wl-copy` for `xclip -selection clipboard`.)

Paste into target shell. The script executes in the foothold shell context, emits markers, operator reads output and routes.

---

## Proposed test suite — `~/scripts/root_services_enum.tests.sh`

### Sandbox-testable scope

Sandbox at design time could NOT run real systemctl. Test suite must use fixture-based mocking. Approach: `sed`-rewrite the script under test to replace `systemctl` invocations with a mock wrapper function that returns synthetic output (matches the pattern used in other enum-script test suites — check `af_unix_sock_enum.tests.sh` for reference structure).

### Test cases required

1. **systemctl unavailable** — mock `command -v systemctl` returning false; verify SYSTEMD_UNAVAILABLE marker emitted, verify filesystem fallback runs, verify SERVICE_SCANNED emitted.
2. **systemctl available, no services** — mock empty `list-units` outputs; verify only SERVICE_SCANNED emitted.
3. **systemctl available, one root service (mysql)** — verify `SERVICE_ROOT[mysqld]: mysql.service` emitted.
4. **systemctl available, mysql with User=mysql (non-root)** — verify NO marker emitted for mysql (UID filter working).
5. **systemctl available, mysql with User= empty (default = root)** — verify marker emitted (empty User= treated as root).
6. **systemctl available, mysql with User=root explicit** — verify marker emitted.
7. **listening socket, no active service** — mock only `list-units --type=socket --state=listening` returning content; verify socket-to-service resolution → marker emitted for socket-activated-idle daemon.
8. **multi-trigger socket** — mock socket with space-separated Triggers property; verify all triggers processed, deduplication working.
9. **socket with empty Triggers** — verify basename replacement fallback works (`.socket` → `.service`).
10. **systemd < 230 (no --value)** — mock old systemd, verify Property=Value parsing works correctly.
11. **watchlist matching** — for each watchlist class, verify correct marker emitted for representative unit names (mysql/mysqld/mariadb/mariadbd; postgresql/postgresql-13; redis/redis-server/redis@instance; tomcat/tomcat9/tomcat10).
12. **catch-all** — mock a root-runnable unit not in watchlist (e.g. `foobar.service`); verify `SERVICE_ROOT[unknown]: foobar.service` emitted.
13. **case sensitivity** — mock unit named `MySQL.service` (unusual capitalisation); verify still matches watchlist (case-insensitive match required).

### Real-box validation (post-sandbox, closure condition)

Sandbox tests validate structure and parsing logic. Real-box validation closes the loop and moves the script from TENTATIVE to VALIDATED per V_S build-when-encountered convention. Real-box test scenarios:

- CIS-benchmark-hardened Ubuntu with `hidepid=2` remounted globally: primary probe returns empty, Preflight fires PROCFS_HIDEPID marker, Secondary correctly enumerates root services. Compare Secondary output against `sudo ps -ef` (verifying script surfaces what Secondary should catch).
- Debian/Ubuntu with default mysql package installed (mysqld runs as `mysql` user): Secondary correctly does NOT emit mysqld marker (UID filter working).
- RHEL-family with socket-activated postgres: primary probe returns empty for postgres (idle daemon), Secondary correctly emits postgres marker via socket resolution.
- Alpine Linux (no systemd): Secondary emits SYSTEMD_UNAVAILABLE, filesystem fallback runs.

### Scripts_Index.md entry (add at build time)

Add row for `root_services_enum.sh`, invoker: LPEC Root-owned Services step. Follow format of existing Scripts_Index entries (verify current format at build time — conventions may have evolved).

---

## Related walkthrough audit (build-time task)

The following walkthroughs likely have parallel structure to the [[MySQL UDF]] Step 1 ps-based UID preflight that was generalised in the design session. Audit each when the Secondary detection is built:

- **[[Postgres UDF]] Step 1** — highly likely to have a `ps -ef | ... /postgres/` UID preflight with the same "remote-only access" fallback phrasing that misses hidepid/socket-idle. Apply parallel edit: add third bullet handling "no output" case with same fallback (defer UID check to authenticated session).
- **[[Redis Configuration File Write]] Step 1** — check whether Redis walkthrough uses a ps-based preflight for redis daemon UID. If yes, same parallel edit.
- **[[Tomcat Manager WAR Deploy]] Step 1** — Tomcat walkthrough likely does not use a ps-based UID preflight (Tomcat UID often less predictable and is instead verified post-exploit). Audit anyway.
- **Any future [[Service Known Exploits]] entries** with per-daemon walkthroughs following the connect-authenticate-exploit pattern — parallel structure likely.

---

## Non-hidepid process-hiding acknowledged gap

Restated for prominence in the "session provenance" region because it is easy to forget: LD_PRELOAD rootkits, kernel rootkits, PID namespaces (container confinement), and `prctl(PR_SET_NAME)` bracketed-name evasion are blind spots for BOTH primary and secondary probes. Do not attempt to build defensive detection for these in `root_services_enum.sh` — they cannot be detected by userspace tools relying on kernel-provided /proc data. Documented gap; if a real target ever exhibits these patterns, that is a separate work piece (rootkit detection is out of scope for LPEC's default enumeration).

---

## Session provenance

**Design session date:** 2026-08-02.

**Sandbox verification scope during design:**
- Kernel 6.18.5 in a container without systemd running as PID 1.
- Preflight probe verified against 10 test cases (all hidepid modes numeric + named, hidepid=0 and hidepid=off explicit-off cases, absent /proc/mounts edge case). All pass.
- Primary probe `ps -ef | awk '$1=="root" && $8 !~ /^\[/'` verified: emits at least PID 1 under hidepid off; emits empty under hidepid=1, hidepid=2 from unprivileged nobody user.
- Kernel hidepid=1 behaviour empirically observed to differ from earlier documentation-based assumption (correction preserved in Empirical findings section above).
- systemctl commands could NOT be verified (systemd not running as PID 1 in sandbox). Script implementation specification carries known-unverified elements that must be validated at real-box build time — see "systemctl availability in the design sandbox" subsection above.

**Related in-session changes that WERE applied (do not re-apply):**
- [[MySQL UDF]] Step 1 `mysqld OS user` block: third bullet added covering ps-blind cases.
- LPEC Step 6 systemd sub-block: second ⚠️ note added flagging build-time considerations for the (separate, unbuilt) `~/scripts/systemd_enum.sh`.

**Deferred to build-when-encountered:**
- LPEC Root-owned Services step restructure (paste-ready form in this note).
- `~/scripts/root_services_enum.sh` (specification in this note).
- `~/scripts/root_services_enum.tests.sh` (test cases in this note).
- `Scripts_Index.md` entry for the above (add at build time).
- Related walkthrough audit (see section above).

**V_S convention grounding:**
- Build-when-encountered convention extends from walkthroughs to enum scripts (established prior to this session).
- Positive scan-completion marker convention (Preflight and Secondary both emit `_SCANNED` markers).
- Informational-marker convention for source-absent enumeration (`SYSTEMD_UNAVAILABLE`).
- Yield-estimation discipline (default: include the detection; defer requires positive evidence the vector is low-yield).
- Design Notes top-level directory convention (established this session).
