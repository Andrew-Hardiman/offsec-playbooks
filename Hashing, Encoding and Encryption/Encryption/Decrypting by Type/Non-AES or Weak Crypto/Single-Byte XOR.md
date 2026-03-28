
## Use this note when

Use this note when you suspect the **entire XOR key is 1 byte (1 char) long**.

Do **not** use this note if the key is likely multiple characters long. That is [[Repeating-Key XOR]].

## Core rule

Single-byte XOR means:

- one byte key
- repeated across the entire plaintext

Example mental model:

`plaintext XOR K = ciphertext`, where the same single byte `K` is used for every position.

## 1. Do you have a candidate 1-byte key?

- **Yes** -> go to step 2
- **No** -> go to step 4

## 2. Convert the candidate key to hex

If the key is a single character:

`echo -n 'K' | xxd -p`

## 3. XOR the data with that single byte

If the ciphertext is already raw bytes:

```bash
python3 - <<'PY'
from pathlib import Path

ct = Path("ct.bin").read_bytes()
key = ord('K')   # replace K
pt = bytes([b ^ key for b in ct])
print(pt)
PY
```

**Where `ct.bin` is your ciphertext binary file.**

If the ciphertext is Base64-wrapped, decode it first:

`base64 -d ciphertext.b64 > ct.bin`

Then run the XOR script above.

## 4. Is the output meaningful plaintext?

- **Yes** -> done
    
- **No** -> continue

## 5. Still no plaintext?

- go back to [[Non-AES, Weak Crypto Triage]]
    
- consider:
    
    - [[Repeating-Key XOR]]
        
    - simple text transforms
        
    - wrong key assumption
        
    - wrong wrapper/decoding step
        
    - app/code context

