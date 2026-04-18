
### 1. Try XOR first

- If the **entire key is 1 byte (1 char long)** -> try [[Single-Byte XOR]]
- If the **entire key is longer than 1 byte (1 char)** -> try [[Repeating-Key XOR]]
- If only part of the key is known, choose based on the **suspected full key length**
### 2. After XOR attempt, is the output meaningful plaintext?

- **Yes** -> done
- **No** -> continue

### 3. Check for simple text transforms

Try:
- Caesar / ROT shift
- substitution-style transform
- reverse / split / reorder logic from code
- per-character arithmetic from code

- **If code/challenge shows the transform** -> reproduce it exactly
- **If not** -> continue

### 4. Still no plaintext?

- Go back to app context
- Look for:
  - exact encrypt/decrypt function
  - library import
  - custom loop over characters/bytes
  - key derivation logic
  - nonce / IV / salt handling
  - compression before encryption