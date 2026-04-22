Web frameworks often use `admin:password` as the default login credentials, have you tried this?

## Default wordlist

Kali: `/usr/share/wordlists/rockyou.txt` — if gzipped: `sudo gunzip /usr/share/wordlists/rockyou.txt.gz`

## Syntax forms — equivalent

`hydra -l <user> -P <wordlist> <ip> <service>`

Both accepted. Pick one and stick to it.

## FTP

`hydra -l <user> -P /usr/share/wordlists/rockyou.txt <ip> <service>`

## SSH

`hydra -l <user> -P /usr/share/wordlists/rockyou.txt -t 4 <ip> <service>`

SSH default thread count is 4 for a reason — OpenSSH rate-limits and drops parallel auth attempts above that. Do not raise `-t` on SSH.

## Useful flags

| Flag        | Purpose                                                                                                                                                    |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-s <port>` | `-s <port>` — specify the port Hydra connects to. Required when a service runs on a non-standard port (e.g. SSH on 2222 instead of 22). Common on CTF/HTB. |
| `-V`        | Show every user:pass combination as it is tried                                                                                                            |
| `-vV`       | Verbose + show attempts — use when you need to see progress                                                                                                |
| `-t <n>`    | Parallel threads. Default 16 most services, 4 for SSH. Raise with caution — lockouts.                                                                      |
| `-d`        | Debug — surfaces connection issues (closed port, wrong service string). Use if Hydra hangs.                                                                |
| `-L <file>` | Username list instead of single `-l <user>`                                                                                                                |
| `-f`        | Stop on first valid pair found                                                                                                                             |
| `-o <file>` | Write valid pairs to file                                                                                                                                  |

## Stop condition

`CTRL-C` when a valid pair is found (or use `-f` to auto-stop).

## If Hydra appears to hang

Add `-d`. Usually one of:

- Closed port on target
- Wrong service string (e.g. `ssh` vs `ssh2`)
- Target throttling / lockout kicked in




