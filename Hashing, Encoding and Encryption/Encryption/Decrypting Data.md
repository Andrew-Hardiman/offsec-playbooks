
## 1. After decoding, is the result readable text?

- **Yes** -> inspect it; it may not be encrypted
- **No** -> continue

## 2. Is the decoded/raw length a multiple of 16 bytes?

- **Yes** -> [[Decrypting by Type/AES]]
- **No** -> [[Non-AES, Weak Crypto Triage]]
