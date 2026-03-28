### ==IMPORTANT MENTAL MODEL==

Gobuster is a path guesser, not a filesystem mapper.  
  
It brute-forces URL paths from a wordlist.  
  
If a path does not appear in results, that does **not** prove the resource does not exist. It only means your current request for that exact path did not return a valid match, or that exact path is not exposed as a route.  
  
Parent paths may return 404 even when deeper file paths exist.  
  
**Example**  
  
`/static` -> `404`  
`/static/` -> `404`  
`/static/js` -> `404`  
`/static/js/decrypt.js` -> `200`  
  
Meaning:  
  
- the app did **not** expose `/static` or `/static/js` as valid browseable routes  
- but it **did** serve the exact file path `/static/js/decrypt.js`  
### Preparation

**Create a directory on your local machine for the specific target, and save the output of each scan in the directory.**
### **1.  `dir` mode (Directory and File Enum)**

**FOR `dir` MODE USE THE WORD LISTS IN `/usr/share/wordlists/dirbuster`**

1. Used to enumerate website directories and their files.

`gobuster dir -u "http://www.example.com" -w /path/to/wordlist -r -o {file_name}.txt`

- `-r` This flags configures Gobuster to follow the redirect that it received as a response to the sent request. A HTTP redirect status code (e.g., 301 or 302) is used to redirect the client to a different URL.
- **The URL must contain the protocol used, in this case, HTTP. This is important and required. If you pass the wrong protocol, the scan will fail.**

2. Gobuster does not enumerate recursively. So, if the results from the initial scan show a directory path you are interested in, you will have to enumerate that specific directory separately. **Do NOT ignore this point, to do thorough enumeration, you need to see what directories you can find within directories (recursively), not just the root of the Web file system. The same holds trues for file searches; do not forget to look for files recursively inside directories and sub-directories.**

3. In addition to directory listing, you can also list files, by specifying the file extensions you wish to search for, e.g. `.php` or `.js`.

`gobuster dir -u "http://www.example.thm" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,js -r`

(A more thorough extension list you can use: `php,html,txt,js,json,bak,log,conf,inc,lua,py`)


**If you're trying to find _both directories and files_, but only use `-x`, GoBuster might miss pure directories if your wordlist doesn’t contain directory-style entries (`admin/`, `css/`, etc.).**

So you should **run one scan without `-x` (example `1`) and one with (example `3`)**

**NB: Again, Gobuster does not enumerate recursively, so if the results from the initial scan show a directory path you are interested in, you will have to enumerate that specific directory with both the directory and file scan independently.**

### 2. High-probability manual route guessing  
  
After automated discovery, do a short round of manual requests for likely application routes.  **This step is important, as valid application route can be missed by automation (see `important mental model` at the top of this note.)**
  
Use app context and naming patterns.  
  
Examples:  
- `/api`  
- `/api/users`
- `/api/users/admin`
- `/api/messages`  
- `/api/messages/admin`
- `/api/chats`  
- `/api/chats/admin`
- `/api/admin`  
- `/api/users/admin`  
- `/api/messages/admin`  

Example command:

`curl http://10.129.163.30:5005/api/messages/admin`

When to do this:  
- API-style app  
- JSON responses  
- chat / user / admin functionality visible  
- naming patterns already observed in the app  
  
Rule:  
Do not treat this as random guessing.  
Use it to test high-probability routes that fit the application's visible design.