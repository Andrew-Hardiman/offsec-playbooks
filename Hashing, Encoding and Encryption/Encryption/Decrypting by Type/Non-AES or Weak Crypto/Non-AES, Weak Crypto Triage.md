
### 1. Do you know the algorithm from code, challenge text, tool output, or context?

- **Yes** -> use the matching note for that algorithm
- **No** -> continue

### 2. Is there a key, password, or short secret nearby?

Examples:
- hardcoded string
- variable called key/password/secret
- challenge hint
- repeated word/string in code
- user-supplied secret

- **Yes** -> continue
- **No** -> go back to app context and look for the key source

### 3. Do you have a plausible XOR setup?

A plausible XOR setup means:
- you have a candidate key/secret to test
- the decoded/raw data is **not** strongly suggesting AES/block cipher
- the app/code/context does **not** already point to another specific algorithm

Strong AES/block-cipher clues:
- decoded byte length is a multiple of 16
- IV / nonce / mode handling is present
- code/context names AES, CBC, ECB, CTR, GCM, etc.

- **Yes** -> continue to step 4
- **No** -> go to step 7
### 4. Try XOR first

- If the **entire key is 1 byte (1 char long)** -> try [[Single-Byte XOR]]
- If the **entire key is longer than 1 byte (1 char)** -> try [[Repeating-Key XOR]]
- If only part of the key is known, choose based on the **suspected full key length**
- If challenge/context says weak crypto / easy crypto / homemade crypto -> try XOR before anything more complex

### 5. After XOR attempt, is the output meaningful plaintext?

- **Yes** -> done
- **No** -> continue

### 6. Check for simple text transforms

Try:
- Caesar / ROT shift
- substitution-style transform
- reverse / split / reorder logic from code
- per-character arithmetic from code

- **If code/challenge shows the transform** -> reproduce it exactly
- **If not** -> continue

### 7. Still no plaintext?

- Go back to app context
- Look for:
  - exact encrypt/decrypt function
  - library import
  - custom loop over characters/bytes
  - key derivation logic
  - nonce / IV / salt handling
  - compression before encryption