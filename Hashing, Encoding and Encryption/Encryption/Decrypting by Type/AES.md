
### 1. Is the key length 16, 24, or 32 bytes?

`echo -n 'KEY_HERE' | wc -c`

- 16 -> possible AES-128
- 24 -> possible AES-192
- 32 -> possible AES-256
- Anything else -> AES less likely unless the key is derived first

### 2. Do you know an IV / nonce is required?

- **Yes** -> find it first, then try decryption
- **No** -> continue to step 3.

**You know an IV/nonce is required only if the mode is known and requires it, or the application/context shows one. You usually cannot tell from the ciphertext alone.**

### 3. Try AES decryption with the matching key size

- **16-byte key** -> try **AES-128**
    
- **24-byte key** -> try **AES-192**
    
- **32-byte key** -> try **AES-256**

### AES-ECB Mode (IV / nonce not required) -- TO DO you need to add all of the other modes --

If no IV / nonce is required, first try should be **AES-ECB** mode, because it is the common AES case that does **not** need and IV / nonce:

**For a 24-byte key:**

`echo 'decoded_raw_binary string' > ct.bin`

then

`openssl enc -d -aes-192-ecb -in ct.bin -out pt.bin -K "$(echo -n 'KEY_HERE' | xxd -p -c 256)"`

then

`xxd pt.bin`

**NB:** `-aes-128-ecb`, `-aes-192-ecb`, and `-aes-256-ecb` differ by **key size**

### Next move

**If OpenSSL returns `bad decrypt`, the guess was wrong: key, mode, algorithm, or padding assumptions are incorrect. Likewise, the conclusion that this is AES could also have been incorrect.**

**Go back to app context and look for evidence of mode/IV/nonce or encryption type before blind guessing further.**