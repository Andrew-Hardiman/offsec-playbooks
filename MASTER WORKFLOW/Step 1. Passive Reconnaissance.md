
## 1. Is this an external engagement or does the scope permit OSINT?

- **No** (lab / internal / CTF with known scope) → Skip to Step 2
- **Yes** → Continue below

---

## 2. Whois

```bash
whois <domain>
```

Record:

- `Registrant Name:`
- `Registrant Organization:`
- `Registrant Email:`
- `Name Server:`
- `Creation Date:`
- `Expiry Date:` 

---

## 3. DNS Enumeration

```bash
dig <domain> A
dig <domain> AAAA
dig <domain> CNAME
dig <domain> MX
dig <domain> SOA
dig <domain> TXT
dig <domain> NS
dig <domain> ANY
```

Record:

- `A` → IPv4 address(es) of domain
- `AAAA` → IPv6 address(es) of domain
- `CNAME`→ Canonical Name
- `MX` → mail servers
- `SOA`→ Primary name server, admin email, zone serial number
- `TXT` → SPF, DMARC, verification strings, anything leaking internal info
- `NS` → authoritative name servers

---

## 4. DNSDumpster

- Site: [https://dnsdumpster.com](https://dnsdumpster.com)
- Input domain → enumerate subdomains, hosts, DNS records
- Record everything returned. **Of particular importance for iterative reconnaissance, are subdomains**

---

## 5. Shodan

- Site: [https://shodan.io](https://shodan.io)
- Search: `hostname:<domain>` or `ip:<target_ip>`

Record: 

- Open ports: 
- Service banners: 
- Flagged CVEs:

---

## Done → Proceed to [[MASTER WORKFLOW/Step 2. Scope & Reachability]]



