**Burp Repeater** is used for manual testing of individual HTTP requests. It lets you modify and resend requests one at a time so you can observe how the application responds to specific changes.

## ==Exploit One: Union SQL Injection Vulnerability==

In order to use this exploit, you need to have identified a GET Request where either the Request Attributes or the Request Query Parameters are used directly in a server-side SQL statement.

Adding a single apostrophe (') to a parameter in a URL or form field is a common technique to test for SQL Injection vulnerabilities. This works because many SQL databases use single quotes to delimit string literals. 

___For example:___
Consider a Web application that constructs an SQL query using user input:

`https://example.com/products?id=2`

The SQL query might look something like this:

`SELECT * FROM products WHERE id = '2'`

An attacker might manipulate the URL to:

`https://example.com/products?id = 2'`

When the server processes this Request, it might build a SQL query like this:

`SELECT * FROM products WHERE id = '2''`

That unescaped single quote will break the syntax. Simply by adding a single quote we can check to see if the user inputs are being directly included in our SQL queries, as this should cause the server to throw an error. Importantly to our cause, many Web applications, by default, display detailed error messages from the database when an error occurs. We can use this error message information to exploit the system.

### ==Exploitation==

Let us say that we have this Request attribute:

`GET /about/ID HTTP/1.1`

Well, if we try adding an apostrophe to the end of the URL and submit the Request, hopefully we will get a 500 (Internal Server Error) Response:

`GET /about/ID' HTTP/1.1`

___Does the Response contain the SQL error message?___

Search in the Response for the strings "SELECT" or "FROM" or "WHERE". Here is an example of an error message that might actually be sent to you (the client-side):

```HTML
<h2>
  <code>
    Invalid statement: <code>
      SELECT firstName, lastName, pfpLink, role, bio FROM       people WHERE id = ID'
    </code>
  </code>
</h2>
```

This message tells us a couple of things that we can use to exploit this vulnerability:

+ The database table we are selecting from is called "people"
+ The query selects five columns from the table "firstName", "lastName", "pfpLink", "role" and "bio".

We can therefore infer that the "people" table looks something like this:

| id  | firstName | lastName | pfpLink  | role  | bio         |
| --- | --------- | -------- | -------- | ----- | ----------- |
| 1   | John      | Doe      | {a link} | Admin | {user info} |
| 2   | Jane      | Smith    | {a link} | User  | {user info} |
| 3   | Alice     | Johnson  | {a link} | Admin | {user info} |
We now want to know just how many columns are actually in this database table, and the names of those columns. We know that the user input is not being validated/sanitised correctly and being passed directly to the SQL statement. _We know this because when we did **GET /about/ID'** the server threw an error._

We can, therefore, use the Union operator to add a second SQL query to the original. The second query will request information from the "information_schema" table, specifically for information about the column names of the "people" table. The output will be the combined output from both of the queries:

`GET /about/0 UNION ALL SELECT column_name, null, null, null, null FROM information_schema.columns WHERE table_name="people"`









