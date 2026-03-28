
## Checks

### 1. Check the character set

- **Base64-like**: letters, numbers, `+`, `/`, sometimes ending in `=`
    
- **Base64URL-like**: letters, numbers, `-`, `_`, sometimes no padding
    
- **Hex-like**: only `0-9`, `a-f`, `A-F`
    
- **URL-encoded**: lots of `%` sequences like `%2f`, `%3a`, `%20`    
### 2. Check context

- Web parameter / cookie / token / API field → often **encoded**
    
- Password database / `/etc/shadow` / SAM-style dump → more likely [[Identifying Hashes]]
    
- Binary-looking data turned into text → often **Base64** or **hex**

## Things to try

### Base64 decode

`echo 'STRING_HERE' | base64 -d`

If output is messy/binary:

`echo 'STRING_HERE' | base64 -d | xxd`
(if the decoded length is NOT readable text but its length **is** a **multiple** of 16 bytes, there is a strong possibility that this could be AES encrypted ciphertext [[Decrypting Data]])
(Also, check it's signature, as this may be a serialized blob [[Insecure Deserialisation#2. Decode and identify the signature]])
### Hex decode

`echo 'STRING_HERE' | xxd -r -p`

### URL decode

`python3 -c "import urllib.parse; print(urllib.parse.unquote('STRING_HERE'))"`

## Decision rule

After decoding, route based on the result:

- If output is clearly readable text inspect it directly (readable means it is not binary, readable does not mean that is it prose, e.g. this is still clearly readable text `BiA8RSIrPhE4JjFULzA1VC9lP145ZS1eJiorQyQyeVA/ZWoRGwh3EQgqN1cuNzxfKCB5QyQqNBEJaw==` , where as this is clearly binary `<E"+>8&1T/05T/e?^9e-^&*+C$2yP?*7W.7<_( yC$*4   k`
  - **check whether it is the real content, or another wrapped layer**

- If output is **not readable text**:
  - treat this as **structured/binary/transformed data**
  - go to [[Identifying Encrypted Data]]

- If decoding fails entirely:
  - reconsider the encoding guess
  - check for:
    - wrong encoding family
    - hash instead of encoding
    - compressed data
    - encrypted data
    - serialized/token/blob data