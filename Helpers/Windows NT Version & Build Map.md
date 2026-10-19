
> **STATUS: AUDITED** — primary-source pass 2026-10-16 against Microsoft Learn (`operating-system-version`, `release-information`, `windows11-release-information`, `windows-server-release-info`, `webhostgetversion-function`). NT 5.x/6.x build numbers and `25398` not confirmed by those sources. Not CANONICAL.

##### Build → NT version → products

| Build            | NT   | Products                                              |
| ---------------- | ---- | ----------------------------------------------------- |
| 2195             | 5.0  | Windows 2000                                          |
| 2600             | 5.1  | Windows XP (32-bit)                                   |
| 3790             | 5.2  | Server 2003, Server 2003 R2, XP Professional x64      |
| 6000, 6001, 6002 | 6.0  | Vista, Server 2008                                    |
| 7600, 7601       | 6.1  | Windows 7, Server 2008 R2                             |
| 9200             | 6.2  | Windows 8, Server 2012                                |
| 9600             | 6.3  | Windows 8.1, Server 2012 R2                           |
| 10240            | 10.0 | Win10 1507, Win10 LTSB 2015                           |
| 10586            | 10.0 | Win10 1511                                            |
| 14393            | 10.0 | Win10 1607, Win10 LTSB 2016, Server 2016              |
| 15063            | 10.0 | Win10 1703                                            |
| 16299            | 10.0 | Win10 1709, Server 1709                               |
| 17134            | 10.0 | Win10 1803, Server 1803                               |
| 17763            | 10.0 | Win10 1809, Win10 LTSC 2019, Server 2019, Server 1809 |
| 18362            | 10.0 | Win10 1903, Server 1903                               |
| 18363            | 10.0 | Win10 1909, Server 1909                               |
| 19041            | 10.0 | Win10 2004, Server 2004                               |
| 19042            | 10.0 | Win10 20H2, Server 20H2                               |
| 19043            | 10.0 | Win10 21H1                                            |
| 19044            | 10.0 | Win10 21H2, Win10 LTSC 2021                           |
| 19045            | 10.0 | Win10 22H2                                            |
| 20348            | 10.0 | Server 2022                                           |
| 22000            | 10.0 | Win11 21H2                                            |
| 22621            | 10.0 | Win11 22H2                                            |
| 22631            | 10.0 | Win11 23H2                                            |
| 25398            | 10.0 | Server 23H2 — ⚠️ build unconfirmed                    |
| 26100            | 10.0 | Win11 24H2, Win11 LTSC 2024, Server 2025              |
| 26200            | 10.0 | Win11 25H2                                            |
| 26300            | 10.0 | Win11 26H2                                            |
| 28000            | 10.0 | Win11 26H1                                            |

Build absent from this table → look it up. Not "no match". Current to 2026-10-16.

##### IIS version → NT version → products

Use when no build is available. Resolve IIS → NT, then read the build from the first table above.

| IIS  | NT   | Products                                                           |
| ---- | ---- | ------------------------------------------------------------------ |
| 5.0  | 5.0  | Windows 2000                                                       |
| 5.1  | 5.1  | Windows XP Professional (32-bit)                                   |
| 6.0  | 5.2  | Server 2003, Server 2003 R2, XP Professional x64                   |
| 7.0  | 6.0  | Vista, Server 2008                                                 |
| 7.5  | 6.1  | Windows 7, Server 2008 R2                                          |
| 8.0  | 6.2  | Windows 8, Server 2012                                             |
| 8.5  | 6.3  | Windows 8.1, Server 2012 R2 — ⚠️ client half from secondary source |
| 10.0 | 10.0 | Every NT 10.0 row above — no narrowing                             |

