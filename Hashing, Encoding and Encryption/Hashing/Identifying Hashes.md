
## Before trying to identify a hash

**Do not assume the value is a hash. Prove it first.**

If a string does **not** match a common hash shape, stop and consider whether it is instead:

- **encoded** data (for example Base64) [[Identifying Encoded Data]]
    
- **encrypted** data [[Identifying Encrypted Data]]

**Quick checks before using hash-identification tools**

1. **Look at the character set**
    
    - Hex-looking only (`0-9`, `a-f`) may be a hash
        
    - Contains `+`, `/`, `=` → often **Base64**, not a normal hex hash
    
2. **Use context**
    
    - Where did the value come from?
        
    - Password database? Likely hash
        
    - URL/token/API response/app field? Could easily be something else
        
3. **Decode before cracking if appropriate**
    
    - If it looks like Base64, decode it first and inspect the result [[Identifying Encoded Data]]

## **1. Example Hashes**

`hashcat --example-hashes | less`

or

`hashcat --example-hashes | grep -B 2 -A 10 {"string"}`

The later will find the specific string, and print the line with the string, plus two lines before it and 10 lines after it.

**The output of `hashcat --example-hashes` shows the hash name with the hashing algorithm in parentheses after the name, on the first line.**

## **2. Hash Prefix Table**

**MS Windows passwords are hashed using NTLM, a variant of MD4. They’re visually identical to MD4 and MD5 hashes, so it’s very important to use context to determine the hash type.**

| Type          | Prefix                         | Algorithm                                                                                                                                                                                        |
| ------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `yescrypt`    | `$y$`                          | yescrypt is a scalable hashing scheme and is the default and recommended choice in new systems                                                                                                   |
| gost-yescrypt | `$gy$`                         | gost-yescrypt uses the GOST R 34.11-2012 hash function and the yescrypt hashing method                                                                                                           |
| scrypt        | `$7$`                          | scrypt is a password-based key derivation function                                                                                                                                               |
| bcrypt        | `$2b$`, `$2y$`, `$2a$`, `$2x$` | bcrypt is a hash based on the Blowfish block cipher originally developed for OpenBSD but supported on a recent version of FreeBSD, NetBSD, Solaris 10 and newer, and several Linux distributions |
| sha521crypt   | `$6$`                          | sha512crypt is a hash based on SHA-2 with 512-bit output originally developed for GNU libc and commonly used on (older) Linux systems                                                            |
| SunMD5        | `$md5$`                        | SunMD5 is a hash based on the MD5 algorithm originally developed for Solaris                                                                                                                     |
| md5crypt      | `$1$`                          | md5crypt is a hash based on the MD5 algorithm originally developed for FreeBSD                                                                                                                   |

## **3. Online Tools for Identifying Hashes**

[[Useful Websites (Password Cracking)]]

## **4. hashid.py**

Identify the different types of hashes used to encrypt data

`hashid hash_file.txt`

Or, to get the hash format, along with the related `hashcat` mode:

`hashid -m hash_file.txt`



