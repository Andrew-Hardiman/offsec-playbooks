
## Use this note when

Use this note when you suspect the **entire XOR key is longer than 1 byte (1 char)** and repeats across the data.

Examples:
- short word/string key
- partially known multi-character key
- Keys created in code using random chars that are of a length of more than 1 byte (1 char). **In the below example `k=5` means 5 bytes (5 chars)**:

```python
res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
key = str(res)
```

Do **not** use this note if the entire key is only 1 byte long. That is [[Single-Byte XOR]].

## Mental model

⚠️ XOR has three variables:
- plaintext
- ciphertext
- key

**If you know any two, you can derive the third**:

`ciphertext[i] = plaintext[i] XOR key[i % len(key)]`

`plaintext[i] = ciphertext[i] XOR key[i % len(key)]`

`key[i % len(key)] = ciphertext[i] XOR plaintext[i]`

## 1. What do you know?

- Full key known -> go to step 2
- Partial key known -> go to step 3
- Full or partial plaintext known or strongly guessable (flag format counts, e.g. `THM{}`) → go to step 4

## 2. XOR the data with the repeating key

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


## 3. Test the suspected full key pattern

Use this when the key is partly known but the full key length is still believed to be more than 1 byte.

Example:

- suspected key pattern: `key_`
    
- suspected full key length: 4
    

Test candidate completions against the ciphertext.

### 3.1 Fix the suspected full key length  
  
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
  
### 3.2 Build candidate keys  
  
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
  
### 3.3 Test each candidate key against the ciphertext  
  
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
### 3.4 Does one candidate produce meaningful plaintext?

Look for:

- flag format
    
- readable words
    
- normal spacing
    
- sensible punctuation
    
- output that makes sense across the whole message
    
- **Yes** -> use that key and finish
    
- **No** -> continue
    

### 3.5 Expand carefully

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

### 3.6 Still no plaintext?

- the guessed key pattern may be wrong
    
- the guessed key length may be wrong
    
- the data may not be repeating-key XOR


## ## 4. Derive key from known/partial plaintext

Use this when:

- ciphertext is known
- full or partial plaintext is known (or strongly guessable — **flag format counts**)
- key is not known
### 4.1 Strip transport wrappers

Decode any transport encoding (hex, base64, etc.) to get raw ciphertext bytes in `ct.bin`. **You may have already landed here with the raw bytes, if so just make sure to add to a file for use `ct.bin`**

```bash
# hex
echo 'HEX_HERE' | xxd -r -p > ct.bin

# base64
echo 'B64_HERE' | base64 -d > ct.bin
```

Measure:

```bash
wc -c ct.bin
```

### 4.2 Check your plaintext assumption against ciphertext length


```bash
echo -n 'ASSUMED_PLAINTEXT' | wc -c
```

Compare `len(ct)` to `len(pt)`:

| Comparison                                                      | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                       | Action            |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| `len(ct) == len(pt)`                                            | Full plaintext, BYTE mode likely                                                                                                                                                                                                                                                                                                                                                                                              | Go to 4.3a        |
| `len(ct) > 2 × len(pt)` AND some bytes `≥ 0x80` in `xxd ct.bin` | likely CHAR mode (UTF-8 wrapped)                                                                                                                                                                                                                                                                                                                                                                                              | Go to 4.3b first. |
| `len(ct) > len(pt)`, no high bytes visible                      | **Plaintext assumption does not fit — the real plaintext is probably longer than what you have. <br><br>Know bytes, i.e. a partial match, is still usable. Especially known positional bytes such as known formats (e.g. `THM{` prefix, `}` suffix).<br><br>**NB:** Source placeholders (`flag = 'THM{thisisafakeflag}'`) are often not the live value, but could well give you the partial know bytes as already mentioned.  | Go to 4.3c        |
| `len(ct) < len(pt)`                                             | Wrong plaintext or wrong ciphertext                                                                                                                                                                                                                                                                                                                                                                                           | Stop. Re-examine. |

### 4.3a BYTE mode — full plaintext, raw byte XOR

```python
from pathlib import Path

ct = Path("ct.bin").read_bytes()

# REPLACE APPROPRIATELY
pt = b"PLAINTEXT_HERE"

# REPLACE APPROPRIATELY
key_len = 5

key = [None] * key_len
conflict = False

for i in range(min(len(ct), len(pt))):
    kb = ct[i] ^ pt[i]
    idx = i % key_len
    if key[idx] is None:
        key[idx] = kb
    elif key[idx] != kb:
        print(f"CONFLICT at index {idx}")
        conflict = True
        break

if not conflict:
    print("Recovered key bytes:", key)
    print("Recovered key string:", ''.join(chr(b) if b is not None and 32 <= b <= 126 else '?' for b in key))
```

### 4.3b CHAR mode — full plaintext, character-layer XOR

```python
from pathlib import Path

ct = Path("ct.bin").read_bytes().decode()

# REPLACE APPROPRIATELY
pt = "PLAINTEXT_HERE"

# REPLACE APPROPRIATELY
key_len = 5

key = [None] * key_len
conflict = False

for i in range(min(len(ct), len(pt))):
    kb = ord(ct[i]) ^ ord(pt[i])
    idx = i % key_len
    if key[idx] is None:
        key[idx] = kb
    elif key[idx] != kb:
        print(f"CONFLICT at index {idx}")
        conflict = True
        break

if not conflict:
    print("Recovered key bytes:", key)
    print("Recovered key string:", ''.join(chr(b) if b is not None and 32 <= b <= 126 else '?' for b in key))
```

### 4.3c PARTIAL mode — known plaintext at known positions

Use this when you only know parts of the plaintext — typically flag format (`THM{` prefix, `}` suffix) or other known strings at known positions.

List `(position, plaintext_byte)` for every byte of plaintext you know:

```python
from pathlib import Path

ct = Path("ct.bin").read_bytes()

# REPLACE APPROPRIATELY
key_len = 5

# (index, plaintext_char) REPLACE THE VALUES APPROPRIATELY
known = [
    (0, ord('T')),
    (1, ord('H')),
    (2, ord('M')),
    (3, ord('{')),
    (len(ct) - 1, ord('}')),
]

key = [None] * key_len
conflict = False

for pos, pt_byte in known:
    kb = ct[pos] ^ pt_byte
    idx = pos % key_len
    if key[idx] is None:
        key[idx] = kb
    elif key[idx] != kb:
        print(f"CONFLICT at key index {idx}: {key[idx]} vs {kb}")
        conflict = True

print("Recovered key bytes:", key)
print("Recovered key string:", ''.join(chr(b) if b is not None and 32 <= b <= 126 else '?' for b in key))

# Fill any remaining None positions by brute force against printable plaintext
if not conflict and None in key:
    missing = [i for i, k in enumerate(key) if k is None]
    print(f"Missing key positions: {missing} — brute-force remaining bytes against printable plaintext")
```

### 4.4 Route based on script output

- **Prints `Recovered key bytes: [...]` with no `None` and no `CONFLICT` line** → key recovered. Go to step 2 and decrypt the full ciphertext with this key to obtain the plaintext.
- **Prints `Recovered key bytes: [...]` with one or more `None` entries, no `CONFLICT` line** → partial key. Go to step 3 to brute-force the missing positions.
- **Prints any `CONFLICT` line** → the current mode is wrong OR the plaintext bytes you supplied are wrong. Try next mode in this order:
    1. If you ran 4.3a, try 4.3b (CHAR mode)
    2. If you ran 4.3b, try 4.3a (BYTE mode)
    3. If both modes conflict, try 4.3c with only flag-format known bytes (`THM{` at start, `}` at end)
- **All three sub-modes conflict** → the server isn't running the code you're reading. Verify by running the suspected code locally (**Not possible on a fully black box challenge**):

``` bash
python3 suspected_server.py   # compare output length to live server
```

If outputs differ, find the real code or treat as black-box with only flag-format knowledge.