
## **1. `dns` mode (Subdomain Enum)**

Use this mode to find subdomains via **DNS resolution** (useful when the target has a real DNS-resolvable domain like `example.thm`).

**FOR `dns` MODE USE THE WORD LISTS IN `/usr/share/seclists/Discovery/DNS`**

`gobuster dns -d example.thm -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

**MAKE SURE YOU ARE ENTERING THE DOMAIN FOR THIS COMMAND, NOT THE IP ADDRESS**

## **2. `vhost` mode (Virtual Hosts Enum)**

Use this technique to discover name-based virtual hosts configured on a single IP.

### 🛠️ Wordlists Location:

`/usr/share/seclists/Discovery/DNS/`

---

### 🔎 1. Subdomain-style VHOST scan (e.g. `admin.example.thm`)

Use this when you know the base domain (e.g. `example.thm`, `target.local`, etc.).

`gobuster vhost -u http://10.101.113.159 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain --domain example.thm`

> ✍️ Add discovered subdomains to `/etc/hosts` for resolution:

`10.101.113.159 admin.example.thm`

**IF YOU ARE GETTING LOTS OF RESULTS WITH THE SAME CONTENT-LENGTH, THIS IS LIKELY A STANDARD RESPONSE FOR "NO PAGE THERE", REMEMBER TO FILTER OUT THESE RESPONSES USING `--exclude-length {2359}`**

---

### 🔍 2. Full-domain scan (e.g. `long.com`, `staging.dev`, `internal.local`)

Use this to catch standalone or non-subdomain vhosts that may be misconfigured or forgotten.

`gobuster vhost -u http://10.101.113.159 -w /usr/share/seclists/Discovery/DNS/namelist.txt`

> No need for `--append-domain` here — domains are used directly from the wordlist.

**IF YOU ARE GETTING LOTS OF RESULTS WITH THE SAME CONTENT-LENGTH, THIS IS LIKELY A STANDARD RESPONSE FOR "NO PAGE THERE", REMEMBER TO FILTER OUT THESE RESPONSES USING `--exclude-length {2359}`**

---

### ⚙️ 3. Hybrid scan (optional, catches edge cases)

Use a custom wordlist combining subdomains and full domains.

Example content:

`admin admin.example.thm long.com backup.local`

Then scan:

`gobuster vhost -u http://10.101.113.159 -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt`

---

### 🧼 CLEAN OUTPUT: Clean up 404 noise (content-length filtering)

If your output is flooded with false positives (typically 404s), filter them by excluding their `Content-Length`. First, inspect the noisy output to identify the length (e.g. 252), then:

`gobuster vhost -u http://10.101.113.159 -w /your/wordlist.txt {--append-domain --domain example.thm} --exclude-length 252`

`--exclude-length 250-350`

---

### 💡 Pro Tips:

- Always check `/etc/hosts` — without DNS, the virtual host must resolve locally.
    
- Use smaller wordlists like `bitquark-subdomains-top100.txt` if short on time.
    
- Try discovered vhosts manually in a browser or with `curl`:
    

`curl -H "Host: admin.example.thm" http://10.101.113.159`