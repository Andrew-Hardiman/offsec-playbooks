**Do NOT attempt to crack hashes on a Virtual Machine (VM), as it will not have access to the computer's GPU. Even if you use the CPU, which most password cracking software does by default, there will still be some performance degradation when using the software inside the VM.**

### **1. Cracking with HashCat**

Basic Syntax

`hashcat {options} {hashfile} {wordlist}`

1. What is your hash type?

To discover this please see the note [[Identifying Hashes]] in this folder.

2. What is the `mode` for the hash type?

Once you know your hash type, e.g. `bcrypt`, you need to find the corresponding `hashcat` mode to use. You can do this using the following command:

`hashcat --example-hashes | grep -B 2 -A 10 {"string"}`

Where `string` is the hash type, e.g. `bcrypt` and the options mean to print two lines `before` and 10 lines `after` the matching string.

3. Once you know the related `hash mode`, e.g. `3200`, you can proceed to attempt to crack the hash:

`hashcat -m <hash_type> hashfile wordlist`

**On Kali Linux, word lists can be found in `/usr/share/wordlists/`**

OR USE THESE FROM SECLISTS, WHICH ARE EVEN BIGGER:

- `Passwords/Leaked-Databases/rockyou-*.txt`
    
- `Passwords/xato-net-10-million-passwords.txt`
    
- `Passwords/Common-Credentials/top1000.txt`

The output will be something like this:

`$2a$06$7yoU3Ng8dHTXphAg913cyO6Bjs3K5lBnwq5FJyA6d01pMSrddr1ZG:85208520`

`Session..........: hashcat`
`Status...........: Cracked`
`Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))`

**The important line you are looking for is the fist line from above, with the format `{original hash:cracked password}`**

**Also, look for this line `Recovered........: 0/1` or just the word `Recovered`in the terminal output, it will tell you what fraction of the hashes were successfully cracked (none out of one, in the example given).**

### **2. Online Cracking**

[[Useful Websites (Password Cracking)]]

### **3. Cracking with John the Ripper (JTR)**


