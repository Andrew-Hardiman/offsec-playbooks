
### Base64 decode

`echo 'STRING_HERE' | base64 -d`

If output is messy/binary:

`echo 'STRING_HERE' | base64 -d | xxd`
(if the decoded length is NOT readable text but its length **is** a **multiple** of 16 bytes, there is a strong possibility that this could be AES encrypted ciphertext [[Decrypting Data]])
(Also, check it's signature, as this may be a serialized blob [[Insecure Deserialisation#2. Decode and identify the signature]])
### Hex decode

`echo 'STRING_HERE' | xxd -r -p | xxd`

### URL decode

`python3 -c "import urllib.parse; print(urllib.parse.unquote('STRING_HERE'))"`

## Decision rule  
  
- If the decode attempt fails:  
	- reconsider the encoding guess [[Identify Data Blob]]

- If the decode attempt succeeds and the result is readable text, decide whether it is:  
	- the real content  
	- another encoded / wrapped text layer [[Identify Data Blob]]
  
- If the decode attempt succeeds and the result is not readable text:  
	- treat it as decoded binary / transformed data  
	- go to [[Decrypting Data]]