
| Hex signature at start | Likely file type | Notes / quick recognition |
|---|---|---|
| `FF D8 FF` | JPEG | Common image upload type |
| `89 50 4E 47 0D 0A 1A 0A` | PNG | Strong PNG signature |
| `47 49 46 38 37 61` | GIF87a | GIF image |
| `47 49 46 38 39 61` | GIF89a | GIF image |
| `25 50 44 46` | PDF | `%PDF` |
| `50 4B 03 04` | ZIP | Also used by many ZIP-based formats |
| `50 4B 05 06` | ZIP (empty archive) | End-of-central-directory style ZIP signature |
| `50 4B 07 08` | ZIP (spanned) | Less common ZIP variant |
| `1F 8B` | GZIP | `.gz` compressed file |
| `42 5A 68` | BZIP2 | `.bz2` compressed file |
| `37 7A BC AF 27 1C` | 7-Zip | `.7z` archive |
| `52 61 72 21 1A 07 00` | RAR v1.5+ | Older RAR |
| `52 61 72 21 1A 07 01 00` | RAR v5+ | Newer RAR |
| `7F 45 4C 46` | ELF | Linux executable / shared object / object file |
| `4D 5A` | PE / EXE / DLL | Windows Portable Executable begins with `MZ` |
| `CA FE BA BE` | Java class | Java bytecode class file |
| `BE BA FE CA` | Mach-O (some variants) | Apple binary family variant |
| `CF FA ED FE` | Mach-O 64-bit | macOS / iOS binary |
| `CE FA ED FE` | Mach-O 32-bit | macOS / iOS binary |
| `FE ED FA CE` | Mach-O (reverse-endian 32-bit) | Older / endian variant |
| `FE ED FA CF` | Mach-O (reverse-endian 64-bit) | Older / endian variant |
| `4F 67 67 53` | OGG | Audio/container |
| `49 44 33` | MP3 with ID3 tag | MP3 often starts with ID3 metadata |
| `52 49 46 46` | RIFF container | Could be WAV, AVI, WEBP; inspect later bytes |
| `52 49 46 46 .... 57 41 56 45` | WAV | RIFF + `WAVE` |
| `52 49 46 46 .... 41 56 49 20` | AVI | RIFF + `AVI ` |
| `52 49 46 46 .... 57 45 42 50` | WEBP | RIFF + `WEBP` |
| `00 00 00 ?? 66 74 79 70` | MP4 / MOV family | Look for `ftyp` near start |
| `3C 3F 78 6D 6C` | XML | `<?xml` |
| `3C 68 74 6D 6C` | HTML | `<html` |
| `3C 21 44 4F 43 54 59 50 45 20 68 74 6D 6C` | HTML | `<!DOCTYPE html` |
| `7B` | JSON object | Only indicates likely text JSON, not guaranteed |
| `5B` | JSON array | Only indicates likely text JSON, not guaranteed |
| `AC ED 00 05` | Java serialized object | High-value for insecure deserialization triage |
| `80 03` | Python pickle protocol 3 | Pickle opcode stream, not a fixed universal file signature |
| `80 04` | Python pickle protocol 4 | Very common in labs / CTFs |
| `80 05` | Python pickle protocol 5 | Newer pickle protocol |
| `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | SQLite 3 | SQLite database |
| `D0 CF 11 E0 A1 B1 1A E1` | OLE Compound File | Old Office docs: `.doc`, `.xls`, `.ppt`, MSI |
| `50 4B 03 04` | DOCX / XLSX / PPTX / JAR / APK / ODT | ZIP-based containers; extension/content matters |
| `23 21` | Script with shebang | e.g. `#!/bin/bash`, `#!/usr/bin/python3` |
| `3C 3F 70 68 70` | PHP file | `<?php` |
| `23 64 65 66 69 6E 65` | PHP / C-style text source maybe | Do not trust blindly; text needs manual inspection |
| `4D 53 43 46` | CAB | Microsoft Cabinet archive |
| `49 53 63 28` | InstallShield CAB | Installer-related |
| `4C 00 00 00 01 14 02 00` | Windows `.lnk` | Shortcut file |
| `21 3C 61 72 63 68 3E 0A` | Unix ar archive | Used by static libraries `.a`, Debian packages internally |
| `64 65 78 0A 30 33 35 00` | Android DEX | Dalvik executable |
| `4D 54 68 64` | MIDI | Audio / sequencing file |
| `46 4C 56 01` | FLV | Flash video |
| `46 57 53` | SWF (uncompressed) | Flash |
| `43 57 53` | SWF (compressed) | Flash |
| `5F 27 A8 89` | Java Keystore (JKS) | Useful in credential / config triage |

## Fast rules

- **File extension can lie.** Check the bytes.
- **Magic number can suggest type, not prove safety.**
- **ZIP-based formats need deeper inspection.** `docx`, `xlsx`, `jar`, `apk`, `odt` may all begin with `50 4B 03 04`.
- **Text formats may not have a strong magic number.**
- **Pickle is opcode-based.** `80 04` or `80 05` is a useful clue, not a universal guarantee.
- **If header and extension disagree, investigate manually.**

## High-value OSCP / CTF checks

| If you see                              | Think                                                              |
| --------------------------------------- | ------------------------------------------------------------------ |
| `7F 45 4C 46`                           | Linux binary, try `file`, `strings`, `checksec`, execute carefully |
| `4D 5A`                                 | Windows executable / DLL                                           |
| `50 4B 03 04`                           | ZIP or ZIP-based document/app container                            |
| `AC ED 00 05`                           | Java deserialization surface                                       |
| `80 04` / `80 05`                       | Python pickle / possible insecure deserialization surface          |
| `3C 3F 70 68 70`                        | Actual PHP content, useful in upload/filter bypass checks          |
| `FF D8 FF` / `89 50 4E 47` / `47 49 46` | Real image headers for upload validation testing                   |

## Useful commands

```bash
xxd -l 32 file.bin
```

