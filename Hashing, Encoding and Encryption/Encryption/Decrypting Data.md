
## 1. Do you have a possible key?

**No** -> then you cannot decrypt, go back to the app context, source code, JS, config, related requests/responses.

**Yes** -> continue

## 2. Does the ciphertext look encoded?

- Base64-like (`A-Z a-z 0-9 + / =`) -> decode it
- Hex-like (`0-9 a-f A-F`) -> decode it
- Neither -> treat as raw/binary ciphertext candidate (jump to step 4)

**Base64:**

`echo 'STRING_HERE' | base64 -d | xxd`

**Hex:**

`echo 'STRING_HERE' | xxd -r -p | xxd`

## 3. After decoding, is the result readable text?

- **Yes** -> inspect it; it may not be encrypted
- **No** -> continue

## 4. Is the decoded/raw length a multiple of 16 bytes?

- **Yes** -> [[Decrypting by Type/AES]]
- **No** -> [[Non-AES, Weak Crypto Triage]]
