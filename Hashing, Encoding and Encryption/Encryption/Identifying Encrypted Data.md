## Purpose

Use this note when a value is:

- not obviously plain text
- not a common hash shape
- not explained by simple [[Identifying Encoded Data]]
- still not readable after decoding attempts
## Core rule

You usually cannot prove “encrypted” from the string alone.

First classify the transformed data into the most likely bucket.

## Routing checks

### 1. Did decoding succeed, but output is still unreadable?

- **Yes** -> continue
- **No** -> go back to [[Identifying Encoded Data]]

### 2. Does it look like a known hash format or hash context?

- password store
- `/etc/shadow`
- hash prefix
- fixed/common digest shape

- **Yes** -> go to [[Identifying Hashes]]
- **No** -> continue

### 3. Do you have any evidence of a decryption path?

Evidence means things like:

- **a possible key**
- source code showing algorithm/mode
- app logic mentioning **encryption**
- JS/config with crypto operation
- IV/nonce/key material nearby
- challenge wording strongly indicating encryption

- **Yes** -> go to [[Decrypting Data]]
- **No** -> continue

## Route

- Have a likely key, algorithm clue, or crypto implementation clue? -> [[Decrypting Data]]
- Looks like a hash or hash context? -> [[Identifying Hashes]]
- Still looks transformed by encoding -> [[Identifying Encoded Data]]
- Do you have binary data but no key and no hash context, check if data could be serialized blob -> [[Insecure Deserialisation#2. Decode and identify the signature]]
- No evidence yet -> go back to app context:
  - source code
  - JavaScript
  - config
  - related requests/responses
  - nearby parameters
  - challenge wording / labels