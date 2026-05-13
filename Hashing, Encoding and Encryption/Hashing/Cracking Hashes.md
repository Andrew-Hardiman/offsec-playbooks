**Do NOT attempt to crack hashes on a Virtual Machine (VM), as it will not have access to the computer's GPU. Even if you use the CPU, which most password cracking software does by default, there will still be some performance degradation when using the software inside the VM.**

## Section 0 — Triage routing

- Hash type **known** (walkthrough specified it, or you already identified it) → skip to Section 1.
- Hash type **unknown** → [[Identify Data Blob]] for triage, then return to Section 1.

## Section 1 — Hash type quick reference

|Hash type|Typical source|Hashcat mode|John format|
|---|---|---|---|
|NTLM|SAM hive, NTDS.dit, LSASS|`-m 1000`|`--format=NT`|
|NetNTLMv1|SMB challenge-response (legacy)|`-m 5500`|`--format=netntlm`|
|NetNTLMv2|SMB challenge-response (Responder)|`-m 5600`|`--format=netntlmv2`|
|MSCASH (DCC1)|LSA Secrets (pre-Vista)|`-m 1100`|`--format=mscash`|
|DCC2|LSA Secrets (Vista+)|`-m 2100`|`--format=mscash2`|
|Kerberos AS-REP|ASREPRoasting|`-m 18200`|`--format=krb5asrep`|
|Kerberos TGS-REP|Kerberoasting|`-m 13100`|`--format=krb5tgs`|
|bcrypt|Web app DBs, modern Unix|`-m 3200`|`--format=bcrypt`|
|SHA-512 crypt (`$6$`)|Linux `/etc/shadow`|`-m 1800`|`--format=sha512crypt`|
|MD5|Web app DBs (legacy)|`-m 0`|`--format=raw-md5`|

For hash types not listed, look up the hashcat mode with:

`hashcat --example-hashes | grep -B 2 -A 10 "<type>"`

Where `<type>` is the hash type name (e.g., `bcrypt`); flags print two lines before and ten lines after each match. Example hash syntax for each mode appears in the output.

Look up the John format name with:

`john --list=formats | grep -i <type>`

Hash internals, sentinel values, and source-specific notes: Section 5.

## Section 2 — Hashcat

Basic syntax:

`hashcat -m <mode> <hashfile> <wordlist>`

`<hashfile>` accepts either a file path (one hash per line) or a literal hash string. Hashcat tries to open the argument as a file first; if no such file exists, it treats the argument as a literal hash.

### Wordlists on Kali

|Path|Notes|
|---|---|
|`/usr/share/wordlists/rockyou.txt`|Standard. Decompress with `gunzip /usr/share/wordlists/rockyou.txt.gz` if only the `.gz` is present.|
|`/usr/share/seclists/Passwords/Leaked-Databases/rockyou-*.txt`|Pre-filtered rockyou variants (e.g., length-bounded)|
|`/usr/share/seclists/Passwords/xato-net-10-million-passwords.txt`|10M password list, larger than rockyou|
|`/usr/share/seclists/Passwords/Common-Credentials/top1000.txt`|Quick first-pass for common passwords|

### Reading the output

Cracked entries appear as `<original_hash>:<plaintext>`. Example:

`$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG:85208520`

Key status line:

`Recovered........: <N>/<total>`

Tells you how many hashes were cracked. `0/1` = single hash, not yet recovered.

Status indicators:

- `Status...........: Cracked` — at least one hash cracked
- `Status...........: Exhausted` — wordlist exhausted, no more candidates to try
- `Status...........: Running` — still working

## Section 3 — John the Ripper

(to be built when encountered)

## Section 4 — Online cracking

[[Useful Websites (Password Cracking)]]

## Section 5 — Hash type deep dives

### NTLM (and LM)

**Source** — SAM hive (local accounts), NTDS.dit (domain accounts on DC), LSASS (live session credentials).

**LM hash (LAN Manager)** — Legacy Microsoft hash from the 80s. Cryptographically broken: case-insensitive, splits password into two 7-byte halves cracked independently, no salt, encrypts a fixed string with password-derived DES keys. Disabled by default since Vista.

**NT hash** — Modern Windows password hash. `MD4(UTF-16-LE password)`. 128-bit, case-sensitive, no truncation, no salt. Pre-image-resistant. The NT hash IS the NTLM credential — Pass-the-Hash uses it directly without cracking.

**secretsdump output format** — `<user>:<rid>:<lm>:<nt>:::`

- **RID** — 500 = built-in Administrator; 501 = Guest; 1000+ = user-created locals
- **LM** — usually `aad3b435b51404eeaad3b435b51404ee` (LM disabled). Non-default value = LM was enabled; crack this first (much faster than NT and recovers an uppercase version of the password, which you then case-permute against NT for the real password)
- **NT** — operational hash for cracking
- `:::` — legacy padding fields (LM-response, NT-response)

**Sentinel hashes to recognise on sight:**

- `aad3b435b51404eeaad3b435b51404ee` — empty LM (normal on modern Windows)
- `31d6cfe0d16ae931b73c59d7e0c089c0` — NT hash of empty string (account has no password set)

**Cracking the NT hash from secretsdump output:**

Single hash (literal):

`hashcat -m 1000 <nt_hash> /usr/share/wordlists/rockyou.txt`

Multiple hashes — extract the NT column from secretsdump output to a file:

`awk -F: '{print $4}' ntlm_hashes.txt > nt_hashes.txt`

`hashcat -m 1000 nt_hashes.txt /usr/share/wordlists/rockyou.txt`

### MSCASH / DCC

(to be built when encountered)

### Kerberos AS-REP / TGS-REP

(to be built when encountered)


