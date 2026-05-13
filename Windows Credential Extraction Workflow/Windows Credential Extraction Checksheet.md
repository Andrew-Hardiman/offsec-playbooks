
## Section 0 — Context check

Primary: `set USERPROFILE` (type this do not copy and paste)
Fallback (this command may disconnect shell): `cmd.exe /c whoami`

- `USERPROFILE=C:\Windows\system32\config\systemprofile` (or `whoami` returns `nt authority\system`) → SYSTEM
- Any other path / non-SYSTEM whoami → not SYSTEM (admin or regular user — distinguish per walkthrough preflight if needed)

## Section 1 — Triage

| Need                                       | Min context           | Walkthrough                                 |
| ------------------------------------------ | --------------------- | ------------------------------------------- |
| Local user(s) NTLM hashes (offline crack)  | SYSTEM                | [[SAM Hive Dump]]                           |
| Currently logged-in users' cleartext creds | SYSTEM                | [[LSASS Dump (Mimikatz sekurlsa)]]          |
| Cached domain creds (mscash)               | SYSTEM                | [[LSA Secrets Dump]]                        |
| Kerberos tickets                           | SYSTEM                | [[Kerberos Ticket Extraction]]              |
| Browser saved passwords                    | Target user or SYSTEM | [[Browser Credential Extraction (LaZagne)]] |
| Credential Manager / Vault                 | Target user or SYSTEM | [[Windows Credential Manager Extraction]]   |
| AD NTDS.dit                                | SYSTEM on DC          | [[NTDS.dit Extraction]]                     |

> **Local account** = stored in this machine's SAM. **Domain account** = stored in Active Directory.

