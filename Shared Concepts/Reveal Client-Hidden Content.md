> **STATUS: AUDITED** — first-principles + primary-source derivation (MDN Web Docs for DOM/CSS mechanics; PortSwigger Web Security Academy "Client-side controls" module for the bypass-as-doctrine principle; OWASP WSTG-CLNT-* series for client-side testing methodology — specific section IDs unverified from training, cite when confirmed); shell mechanics sandbox-verified where in-container-testable; live-validation pending. Last audit: 2026-09-19.

Purpose: reveal content the browser hides that the server actually sent. Fires when a caller playbook requires the operator to read a page's content and browser rendering hides some or all of it (paywall overlays, "premium" blockers, cookie-consent modals, JS-removed elements, "please log in" overlays that gate display without gating the response).

Domain principle: any content-restriction enforced on the client is bypassable from the client. The server sent the content; the browser is instructed to hide it. Only server-side restriction (server sends less or nothing based on session/auth) constitutes real access control. This is the foundational trust-boundary principle of client-side controls (PortSwigger Web Security Academy).

Callers: [[IDOR]] Verify + extract

---

## Step 1 — Diagnostic: is the content in raw HTML?

Fetch the URL raw. Include session cookie if the caller is authed:

`curl -s [-b '<session_cookie>'] "http://<host>:<port><path>" | less`

Route on what you see:

- **Content is present in the raw HTML** (that is not visible in browser) → client-side hiding, categories 1-4 below. Proceed to Step 2.
- **Content is NOT in the raw HTML** (only a skeleton page, or a "loading..." placeholder) → category 5 (JS-lazy-load) OR server-side hiding. Proceed to Step 3.

⚠️ Read the raw output carefully. Client-side hiding often puts the "please pay" overlay div ABOVE the actual content div — both are present in the HTML. Look past the overlay text for the underlying content.

---

## Step 2 — Client-side hiding present: bypass techniques

Ordered fastest → most expensive. First that works, stop.

### 2.1 View Page Source (Ctrl+U)

Right-click page in Firefox/Chrome → View Page Source. OR: Ctrl+U.

- Shows raw server response, exactly as HTTP delivered it
- Session cookie preserved (page fetch is authed as current session)
- No CSS applied, no JS executed — everything the server sent is visible
- Cost: text view, no styling; long HTML harder to navigate than rendered page

Works against: any case where content is in raw HTML (categories 1-4). Same visibility as `curl` from Step 1 but keeps the browser session active for follow-up navigation.

### 2.2 Devtools Elements panel — delete/modify blocker

Right-click on the blocking element (overlay, paywall, modal) → Inspect. In Elements panel:

- Identify the wrapping element (typically `<div class="...blocker...">` or `<div class="modal-overlay">`)
- Right-click the element → Delete Node. OR: in Styles panel, set `display: none !important` on it.
- Article/content behind becomes visible immediately.

Alternative — Devtools Console command for known-selector blockers:

`document.querySelectorAll('.premium-blocker, .paywall, .modal-overlay, [class*="blocker"]').forEach(e => e.remove())`

⚠️ Firefox and Chrome block first-time paste into Devtools Console (anti-phishing measure). Console prints a warning and refuses the paste. To unblock: TYPE (do not paste) the words `allow pasting` and press Enter. Paste permitted for the rest of that Devtools session. Persists until Devtools is closed.

Adjust selector to match the specific class observed. `[class*="X"]` is a CSS attribute-substring selector (MDN); catches class names containing X.

Works against: categories 1 (CSS overlay), 2 (CSS `display:none`, `visibility:hidden`, etc.).

Fails against: category 3 (JS re-injects blocker after removal — refresh reverts the deletion). Diagnose: after removing, wait a few seconds — if blocker returns, JS is re-injecting on interval/mutation observer. Move to 2.3 or 2.4.

### 2.3 Devtools → disable JavaScript, refresh

Firefox: F12 → Settings (gear icon) → check "Disable JavaScript" → refresh page (F5). Chrome: F12 → Command Menu (Ctrl+Shift+P) → "Disable JavaScript" → refresh.

- Prevents all JS execution on subsequent page load
- Session cookie preserved
- Page renders with only server-sent HTML + CSS

Works against: category 3 (JS-removed elements — no JS means the removal script doesn't run), category 4 (JS-populated blocker — no JS means the injection script doesn't run).

Fails against: categories 1-2 (pure CSS hiding — CSS is not JS; disabling JS doesn't affect it). If content still hidden after JS-disable, the hiding is CSS-based → use 2.1 or 2.2.

Side effect: many sites break entirely without JS (navigation, styling, interactive elements). Acceptable for content-read-only purposes; do NOT stay in JS-disabled mode for interactive flows.

### 2.4 Curl with session cookie + grep

`curl -s -b '<session_cookie>' "http://<host>:<port><path>" | less`

OR to extract specific content patterns from a large response:

`curl -s -b '<session_cookie>' "http://<host>:<port><path>" | perl -0777 -pe 's#<(style|script)\b[^>]*>.*?</\1>##gs; s#<[^>]*># #g' | tr -s '[:space:]' ' '`

- Strips `<style>` and `<script>` blocks (removes CSS/JS text that would otherwise be in the output)
- Strips all HTML tags
- Normalises whitespace
- Yields plain-text version of page content

Same visibility as 2.1 View Source. Preferable when the operator wants to grep/awk/sed on the content (e.g. extract every `<p>` text, find email addresses in output, feed to a pipeline).

Works against: any category 1-4 case. Session-preserving via `-b` cookie flag.

---

## Step 3 — Content NOT in raw HTML

Two sub-cases: JS-lazy-load (bypassable) vs server-side hiding (not bypassable by this technique).

### 3.1 Diagnostic: JS-lazy-load or server-side?

Open Devtools → Network tab → clear history → refresh page. Observe subsequent XHR / Fetch / WebSocket requests as the page loads:

- **XHR/Fetch requests populate content after page load** → JS-lazy-load. Content lives at the requested endpoint. Proceed to 3.2.
- **No subsequent XHR/Fetch requests OR they only fetch styling/tracking** → server sent all it will send. Content restriction is server-side. Route out per Step 4.

### 3.2 JS-lazy-load bypass

For each XHR/Fetch request that populates content:

1. Note the endpoint URL, method, and any custom headers (Authorization, X-*, etc.)
2. Copy as curl: right-click request → Copy → Copy as cURL
3. Run the curl directly — retrieves the raw content payload without browser rendering

`curl -s [-b '<session_cookie>'] [-H '<custom_header>'] "http://<host>:<port><api_endpoint>"`

Response is typically JSON. Parse with `jq`:

`curl -s -b '<session_cookie>' "http://<host>:<port>/api/articles/3" | jq .`

Content visible directly.

---

## Step 4 — Server-side hiding: route out

If Step 1 and 3.1 both indicate the content is not being sent by the server (with the current session's auth state), the restriction is server-side. This technique does not bypass server-side controls.

Route:

- Restriction gated on higher-privilege session → escalate via [[Authenticated Walk]] sub-block 10 (privilege escalation branch) if authed, or via [[Credential Attacks]] / [[Login Bypass Techniques]] if unauth.
- Restriction gated on specific object identifier → [[IDOR]] (server may serve to different user IDs).
- Restriction gated on payment/subscription state → out of scope for foothold-focused testing; log finding, next URL.

---

## Return

Reveal succeeded → hand revealed content back to caller for their own inspection purpose.

Reveal failed (server-side hiding) → return `HIDDEN_SERVER_SIDE` to caller so they know the technique doesn't apply here; caller routes to escalation.

---

## Validation
