
### **1. SSL/TLS Certificates**

When an SSL/TLS (Secure Sockets Layer/Transport Layer Security) certificate is created for a domain by a CA (Certificate Authority), CA's take part in what's called "Certificate Transparency (CT) logs". These are publicly accessible logs of every SSL/TLS certificate created for a domain name. The purpose of Certificate Transparency logs is to stop malicious and accidentally made certificates from being used. We can use this service to our advantage to discover subdomains belonging to a domain, sites like [https://crt.sh](https://crt.sh) offer a searchable database of certificates that shows current and historical results.

Use `Certificate Search` [[Useful Websites (Web App Pen Testing)]]

#### ✅ How crt.sh Works (Important)

- crt.sh is a front-end for **Certificate Transparency logs**, which are public, append-only logs of issued TLS certificates.
    
- When you run a query like `iprotectu`, it matches:
    
    - `CN=*.iprotectu.co.uk`
        
    - `SAN=portal.iprotectu.com`
        
- It **does not** match organization names, descriptions, or metadata like "Issued to: iProtectU Ltd".

**Therefore, it is important to run the following six searches in order to make sure you are thorough (obviously, replace the top-level domain name as appropriate):**

1. `%.iprotectu.co.uk`
2. `%.iprotectu.com`
3. `iprotectu.co.uk`
4. `iprotectu.com`
5. `"iprotectu.co.uk"`
6. "iprotectu.com"

### **2. Search Engines**

Search engines contain trillions of links to more than a billion websites, which can be an excellent resource for finding new subdomains. Using advanced search methods on websites like Google, such as the `site: filter`, can narrow the search results. For example, `site:*.domain.com -site:www.domain.com` would only contain results leading to the domain name domain.com but exclude any links to www.domain.com; therefore, it shows us only subdomain names belonging to domain.com.

## 3. DNSDumpster

- Site: [https://dnsdumpster.com](https://dnsdumpster.com)
- Input domain → enumerate subdomains, hosts, DNS records
- Record everything returned. **Of particular importance for iterative reconnaissance, are subdomains**