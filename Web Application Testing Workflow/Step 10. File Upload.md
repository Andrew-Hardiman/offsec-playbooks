
## Goal
Upload a malicious file → execute it or read sensitive files. Please see [[Web Shells]]

### 1  Identify Upload Points

- Profile pictures, support tickets, document submission.

### 2  Bypass Techniques

- Double extension: `shell.php.jpg`
- Content‑Type spoof: `image/png`
- Null byte (older PHP): `shell.php%00.jpg`
- Case tricks: `.pHp`, `.PhP`

### 3  Verify Upload Location and Location

- Guess common folders: `/uploads/`, `/files/`, `/images/`.
- Use gobuster with extensions: `php,asp,aspx,jsp`.

### 4  Execute Shell

- Access uploaded `shell.php` → reverse shell or web cmd.
Please see [[Web Shells]]

### 5  If Execution Blocked

- SVG XSS payload
- .htaccess trick (`AddType application/x-httpd-php .jpg`)

