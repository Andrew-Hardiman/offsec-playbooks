A **race condition vulnerability** occurs when an application allows multiple requests or operations to act on the same shared resource at the same time, and the final outcome depends on the order in which those operations execute. If the application does not enforce proper locking or atomic operations, an attacker can exploit this timing window to bypass checks, perform actions multiple times, or corrupt application state.

### **1. Identify High-Risk Race Condition Surfaces**

Focus only on **state-changing functionality**.

#### **High-probability targets**

- Balance / credit updates
    
- Coupon or promo redemption
    
- Password reset flows
    
- Email or username changes
    
- File uploads
    
- Account registration
    
- Inventory / booking systems
    
- Rate-limited actions
    
- One-time tokens (OTPs, magic links)
    
- “Only once” logic (claim, vote, like, redeem)
    

#### **Low-probability / ignore**

- Read-only GET requests
    
- Static content
    
- Pure data retrieval
    

If the action **modifies state**, keep going.

---
### **2. Establish a Safe Baseline**

Before racing anything:

- Confirm the action works **once**
    
- Confirm the state updates as expected
    
- Reset the environment if possible
    

Example:

- Balance goes from 100 → 90
    
- Coupon marked as “used”
    

You need a clean baseline to prove duplication later.

---

### **3. Force True Concurrency (Required for Proof)**

You must send **near-simultaneous requests**.
#### Recommended tools:

- Burp Suite → Repeater → “Send group in parallel”

#### Steps:

1. Intercept the appropriate HTTP request
2. Send to `repeater`
3. Once you have the request in `repeater` **turn off Proxy Intercept**. This will prevent confusion with concurrent requests and redirects being inadvertently caught by the proxy.
4. Click on the `+` icon next to the received request tab and select **Create/New tab group**
5.  Assign a group name, and include the tab of the request you just sent to `repeater` before clicking **Create**
6. Right-click on the request tab and choose **Duplicate tab** (If this option is not available in your version, you can press **CTRL**+**R** multiple times instead)
7. As a starting point, duplicate it 20 times
8. Next to the Send button, the arrow pointed downwards will bring a menu to decide how you want to send the duplicated requests
9. Select **Send group in parallel**

Before clicking the orange `Send group (parallel)` button, go to the `logger` tab and clear the log, so that you can view the N number of requests easily in the log.

### **4. Observe for Race Indicators**

You are looking for **logic violations**, not errors.
#### Indicators:

- Balance deducted multiple times
    
- Balance goes negative
    
- Coupon redeemed twice
    
- Token accepted more than once
    
- Two accounts created with same unique field
    
- Same file written twice
    
- Limit bypassed
    
Even **one duplicated success** is a valid vulnerability.

### **5. Prove Impact (Minimum Viable PoC)**

A valid race condition PoC must show:

1. Intended limit or check
    
2. Concurrent requests
    
3. Broken invariant
    
#### Example proof statement:

> Sending two concurrent requests to `/redeem` allows the same coupon to be redeemed twice, bypassing the intended single-use restriction.

No exploit chain is required.

### **6. Strengthen the Proof (Optional but Ideal)**

If possible:

- Increase request count (5, 10, 20)
    
- Show deterministic success rate
    
- Capture timestamps
    
- Demonstrate reproducibility
    
This turns “possible issue” into **undeniable vulnerability**.

---

**Reporting Sentence (Drop-in Ready)**

> The application performs a non-atomic check-then-act operation on shared state, allowing concurrent requests to bypass intended logic and resulting in a race condition vulnerability.

