
## Use this note when

Use this note when you suspect the **entire XOR key is longer than 1 byte (1 char)** and repeats across the data.

Examples:
- short word/string key
- partially known multi-character key

Do **not** use this note if the entire key is only 1 byte long. That is [[Single-Byte XOR]].

## Core rule

Repeating-key XOR means:

- the key is multiple bytes long
- the same key repeats across the whole plaintext

Mental model:

`plaintext[i] XOR key[i % len(key)] = ciphertext[i]`

## 1. Do you have the full key?

- **Yes** -> go to step 2
- **No** -> go to step 5

## 2. Decode/unpack the ciphertext if needed

- Base64-like -> decode first
- Hex-like -> decode first
- Otherwise -> use raw bytes as-is

## 3. XOR the data with the repeating key

```bash
python3 - <<'PY'
from pathlib import Path

ct = Path("ct.bin").read_bytes()
key = b"KEY_HERE"

pt = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))
print(pt)
PY
```

If needed, write output to a file instead:

```bash
python3 - <<'PY'
from pathlib import Path

ct = Path("ct.bin").read_bytes()
key = b"KEY_HERE"

pt = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))
Path("pt.bin").write_bytes(pt)
print("Wrote pt.bin")
PY
```

## 4. Is the output meaningful plaintext?

**Yes** -> done

**No** -> continue to step 7

## 5. Is the key only partially known?

**Yes** -> continue to step 6

**No** -> go to step 7

## 6. Test the suspected full key pattern

Use this when the key is partly known but the full key length is still believed to be more than 1 byte.

Example:

- suspected key pattern: `key_`
    
- suspected full key length: 4
    

Test candidate completions against the ciphertext.

### 6.1 Fix the suspected full key length  
  
Before testing anything, write down:  
  
- the **suspected full key**  
- the **suspected full key length**  
- the **unknown positions**  
  
Example:  
  
- suspected full key pattern: `key_`  
- suspected full key length: `4`  
- unknown position(s): character 4  
  
Do **not** change key type here.  
  
- If the suspected full key length is **more than 1 byte (1 char)**, stay in [[Repeating-Key XOR]]  
- Do **not** switch to [[Single-Byte XOR]] just because part of the key is unknown  
  
### 6.2 Build candidate keys  
  
Replace each unknown position with likely candidates from context.  
  
Start with the smallest, highest-probability set first.  
  
Good candidate sources:  
- nearby code / variables  
- challenge wording  
- usernames  
- hostnames  
- app names  
- common suffixes/prefixes  
- digits  
- `_`, `-`, `!`, `@`  
- common casing patterns  
  
Example:  
- `key_` -> test `key1`, `key2`, `key!`, `key_`, `keyA`, `keya`  
  
### 6.3 Test each candidate key against the ciphertext  
  
If needed, decode first so you have raw bytes in `ct.bin`.  
  
```bash  
python3 - <<'PY'  
from pathlib import Path
  
ct = Path("ct.bin").read_bytes()  
  
candidates = [  
b"key1",  
b"key2",  
b"key!",  
b"key_",  
b"keyA",  
b"keya",  
]  
  
for key in candidates:  
pt = bytes(ct[i] ^ key[i % len(key)] for i in range(len(ct)))  
printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in pt) / len(pt)  
preview = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in pt[:80])  
print(f"{key!r} printable={printable:.2f} preview={preview}")  
PY 
```
> [!note]
> That `PY` marker is only used to close a shell heredoc. If writing a `.py` file, do not include the heredoc opening or closing markers.
> Do not forget, if writing a `.py` file, indent the body of the `for in` block using 4 spaces.

**Where `ct.bin` is your ciphertext binary file.**
### 6.4 Does one candidate produce meaningful plaintext?

Look for:

- flag format
    
- readable words
    
- normal spacing
    
- sensible punctuation
    
- output that makes sense across the whole message
    
- **Yes** -> use that key and finish
    
- **No** -> continue
    

### 6.5 Expand carefully

If the first candidate set fails:

- keep the same suspected full key length
    
- expand candidates in a controlled way
    
- change one assumption at a time
    

Examples:

- try more likely final characters
    
- try case changes
    
- try nearby words from the app/context
    
- try a different suspected full key pattern
    

Do **not** jump to random large brute force immediately.

### 6.6 Still no plaintext?

- the guessed key pattern may be wrong
    
- the guessed key length may be wrong
    
- the data may not be repeating-key XOR
    
- go to step 7


## 7. Still no plaintext?

Go back to app context...