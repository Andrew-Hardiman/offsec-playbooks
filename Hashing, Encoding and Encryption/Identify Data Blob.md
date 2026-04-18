
## Goal

Route the artefact to:
-  [[Decoding Encoded Data]]
-  [[Decrypting Data]]
-  [[Cracking Hashes]]
## 1. Does the artifact look like an encoded text layer?

**Examples:**

```test
- Base64-like: letters, numbers, `+`, `/`, sometimes ending in `=`
- Base64URL-like: letters, numbers, `-`, `_`, sometimes no padding
- Hex-like: only `0-9`, `a-f`, `A-F`
- URL-encoded: lots of `%` sequences like `%2f`, `%3a`, `%20`
```

- **No** -> continue
- **Yes** -> go to [[Decoding Encoded Data]] - remember type, e.g. Hex, Base64 etc.

## 2. Is the artifact easily identified as a hash, via ...?

Go to hashes.com, specifically the `hash_identifier` route: [[Useful Websites (Password Cracking)]]

- **No** -> continue
- **Yes** -> go to [[Cracking Hashes]]

## 3. Is the artifact easily identified as a hash from the below table...?

| Type          | Prefix                         | Algorithm                                                                                                                                                                                        |
| ------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `yescrypt`    | `$y$`                          | yescrypt is a scalable hashing scheme and is the default and recommended choice in new systems                                                                                                   |
| gost-yescrypt | `$gy$`                         | gost-yescrypt uses the GOST R 34.11-2012 hash function and the yescrypt hashing method                                                                                                           |
| scrypt        | `$7$`                          | scrypt is a password-based key derivation function                                                                                                                                               |
| bcrypt        | `$2b$`, `$2y$`, `$2a$`, `$2x$` | bcrypt is a hash based on the Blowfish block cipher originally developed for OpenBSD but supported on a recent version of FreeBSD, NetBSD, Solaris 10 and newer, and several Linux distributions |
| sha521crypt   | `$6$`                          | sha512crypt is a hash based on SHA-2 with 512-bit output originally developed for GNU libc and commonly used on (older) Linux systems                                                            |
| SunMD5        | `$md5$`                        | SunMD5 is a hash based on the MD5 algorithm originally developed for Solaris                                                                                                                     |
| md5crypt      | `$1$`                          | md5crypt is a hash based on the MD5 algorithm originally developed for FreeBSD                                                                                                                   |
- **No** -> continue
- **Yes** -> go to [[Cracking Hashes]]

## 4. hashid.py

Identify the different types of hashes

`hashid hash_file.txt`

Or, to get the hash format, along with the related `hashcat` mode:

`hashid -m hash_file.txt`

⚠️ `hashid` does pattern matching, not true identification.

- **No** -> continue
- **Yes** -> go to [[Cracking Hashes]]

## 5. Do you have any evidence of an encryption/decryption path?

Evidence means things like:

- **a possible key**
- source code showing algorithm/mode
- app logic mentioning **encryption**
- JS/config with crypto operation
- IV/nonce/key material nearby
- challenge wording strongly indicating encryption

- **Yes** -> go to [[Decrypting Data]]
- **No** -> continue

## 6. Final routing options...

- Have a likely key, algorithm clue, or crypto implementation clue? -> [[Decrypting Data]]
- Looks like a hash or hash context? -> [[Cracking Hashes]]
- Still looks transformed by encoding -> [[Decoding Encoded Data]]
- Do you have binary data but no key and no hash context, check if data could be serialized blob -> [[Insecure Deserialisation#2. Decode and identify the signature]]
- No evidence yet -> go back to app context:
  - source code
  - JavaScript
  - config
  - related requests/responses
  - nearby parameters
  - challenge wording / labels
