<div align="center">

# 🔍 QQ Music Credential Reverse Engineering

<!-- Language Switcher -->
<p>
  <a href="README.md"><img src="https://img.shields.io/badge/English-English-blue?style=flat-square" alt="English"></a>
  <a href="README_zh.md"><img src="https://img.shields.io/badge/中文-中文-red?style=flat-square" alt="中文"></a>
</p>

**Deep dive into QQ Music's local credential storage — AES-128-CBC encryption analysis, binary key extraction, MMKV/ConfigInfo/Cookie decryption research**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows-blue)]()
[![Language](https://img.shields.io/badge/language-JavaScript-green)]()
[![Stars](https://img.shields.io/github/stars/BlueChonk/qqmusic-credential-reverse-engineering?style=social)]()

[🇨🇳 中文文档](README_zh.md) | [🇺🇸 English](README.md)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Research Target](#research-target)
- [Data Storage Map](#data-storage-map)
- [Step-by-Step Process](#step-by-step-process)
- [Results Summary](#results-summary)
- [Encryption Analysis](#encryption-analysis)
- [Failed Attempts](#failed-attempts)
- [Comparison with Trae Project](#comparison-with-trae-project)
- [Future Work](#future-work)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## 🔬 Overview

This project documents the complete reverse engineering process of **QQ Music (QQ音乐)** desktop client's local credential storage on Windows. The goal is to extract authentication tokens, device fingerprints, and other sensitive data from the local storage — mirroring the approach used in the [trae-check](../trae-check) project.

**Key Findings:**
- QQ Music stores data in `%APPDATA%\Tencent\QQMusic\` with **18+ files**
- Three critical files are encrypted with **AES-128-CBC** (identified via OpenSSL strings in `QMNetwork.dll`)
- The `CEncryptFile` class in `QQMusicCommon.dll` manages encryption/decryption
- Multiple plaintext files expose account IDs, device fingerprints, DNS cache, and API endpoints
- **AES key was NOT extractable** via static binary analysis alone

---

## 🎯 Research Target

The goal is to extract the following credential fields from QQ Music's local storage:

| Field | Description | Status |
|---|---|---|
| `token` | JWT auth token for API calls | ❌ Encrypted |
| `refreshToken` | Token refresh credential | ❌ Encrypted |
| `expiresAt` | Token expiration timestamp | ❌ Encrypted |
| `deviceId` | Device fingerprint ID | ⚠️ Partial |
| `machineId` | Machine hardware ID | ❌ Encrypted |
| `privateKeyPEM` | RSA private key | ❌ Encrypted |
| `publicKeyPEM` | RSA public key | ❌ Encrypted |
| `userId` | User account identifier | ✅ Found |
| `host` | API server addresses | ⚠️ Partial |
| `authInfo` | Complete auth info object | ❌ Encrypted |
| `signingKeyEntries` | Signing key entries | ❌ Encrypted |

---

## 🗺️ Data Storage Map

```
%APPDATA%\Tencent\QQMusic\
├── WNS\
│   └── 201915\
│       ├── config.xml          ✅ PLAIN TEXT — WNS network config (uin, deviceId, hosts)
│       └── data\
│           ├── user.data       🔒 Binary (locked by process)
│           └── report.data     🔒 Binary
├── ComData\
│   └── qmcomdata.ini           ✅ PLAIN TEXT — COM data (uin, path)
├── QQMusicServiceConfig.ini    ✅ PLAIN TEXT — Service config (Uin=2131899634)
├── DomainCache.ini             ✅ PLAIN TEXT — DNS cache (API server IPs)
├── startup.ini                 ✅ PLAIN TEXT — Startup config (hardware info)
├── WebkitCachePath.ini         ✅ PLAIN TEXT — Webkit cache path
├── MonitorQQMusic.ini          ✅ PLAIN TEXT — Monitor config
├── QQMusicConfV3.dat           🔒 ENCRYPTED — Main config (245KB, likely auth tokens)
├── ConfigInfoXML1.dat          🔒 ENCRYPTED — Config XML (270KB, likely full auth info)
├── SetCookie.dat               🔒 ENCRYPTED — Cookies (1.7KB, login cookies)
├── mmkv\
│   ├── mmkv.default            🔒 OBFUSCATED — MMKV key-value store (16KB)
│   └── mmkv.default.crc        🔒 Binary — MMKV CRC data
├── qmlist64.db                 🔒 SQLite (locked) — Music playlist database
├── weiyun.file.2131899634.v27.db  🔒 SQLite — Weiyun cloud storage DB
├── block.dat                   🔒 Binary — Blocklist data
├── CrashDump\                  📁 Crash dump logs
├── Pic\                        📁 Skin resources
├── SSN\                        📁 Sound effect resources
└── Logs\                       📁 Application logs
```

Additionally, QQ Music uses **Tencent Qimei** device fingerprinting service:
```
%APPDATA%\Tencent\qimei\
├── A201CFB4C8D73FBE6916E0F5A2D14D39  🔒 128-byte device fingerprint hash
├── Config.ini                           🔒 16-byte encrypted config
├── Global.db                            🔒 64-byte global data
└── RanMgr.db                            ✅ PLAIN TEXT — Profile configs (5 MD5 hashes)
```

---

## 🔧 Step-by-Step Process

### Step 1: Locate Data Storage

Search for QQ Music's data directory across multiple locations:

```powershell
# Search AppData\Roaming
Get-ChildItem "$env:APPDATA" -Directory | Where-Object { $_.Name -like '*QQMusic*' }

# Search AppData\Local
Get-ChildItem "$env:LOCALAPPDATA" -Directory | Where-Object { $_.Name -like '*QQMusic*' }

# Search Program Files installation directory
Get-ChildItem "C:\Program Files\Tencent\QQMusic" -Recurse -File
```

**Result:** Found `%APPDATA%\Tencent\QQMusic\` as the primary data directory with 18+ files.

---

### Step 2: Analyze File Formats

Read the first 64 bytes of each file to determine format:

| File | First Bytes (Hex) | Format |
|---|---|---|
| `config.xml` | `3C 63 6F 6E 66 69 67 3E` | Plain text XML (`<config>`) |
| `QQMusicConfV3.dat` | `49 A4 31 2D 3C B1 5A B0` | Encrypted binary |
| `ConfigInfoXML1.dat` | `61 FD 30 60 24 16 02 26` | Encrypted binary |
| `SetCookie.dat` | `F2 FA 48 4C 94 D7 EF 7C` | Encrypted binary |
| `mmkv.default` | `86 3E 00 00 AF 23 79 03` | MMKV (obfuscated) |
| `qmlist64.db` | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | SQLite |
| `weiyun.file.*.db` | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | SQLite |

---

### Step 3: Extract Plaintext Data

#### 3.1 WNS Config (`config.xml`)

```xml
<config>
    <uin>5729475454240175104</uin>          <!-- QQ Number -->
    <appInfo>
        <appId>201915</appId>
        <appName>QQMusicPC</appName>
        <appVersion>2043.2858.1014</appVersion>
        <qua>V1_WPC_KG_20.43.2858_1014_GW_D</qua>
        <deviceInfo>qq=2131899634</deviceInfo>  <!-- Device ID -->
    </appInfo>
    <configCookie>417564696F506C617965725032503D333637343826417564696F506C617965725032505F4154563D343237343126...</configCookie>
</config>
```

**Decoded configCookie:**
```
AudioPlayerP2P=36748&AudioPlayerP2P_ATV=42741&AudioPlayerP2P_PC=22525&RS=28461&WSL=3825915940&WS=14869
```

#### 3.2 Service Config (`QQMusicServiceConfig.ini`)

```ini
[Account]
Uin=2131899634
```

#### 3.3 DNS Cache (`DomainCache.ini`)

```ini
[DomainCache]
stat.y.qq.com=14.116.237.185
c.y.qq.com=119.147.3.178
y.qq.com=222.216.230.128
isure.stream.qqmusic.qq.com=59.42.242.215
ws.stream.qqmusic.qq.com=172.29.0.20
```

#### 3.4 Qimei Device Fingerprint (`RanMgr.db`)

```ini
[Profile]
config1=0b2046113648735db393bd41e57e2f27
config2=8ebe7490a0833980dfb4a2078754c3f0
config3=99f81b52128f485ba4945335e3fbf7bf
config4=3a24b6d78920b969577820e04eb1160c
config5=1
```

#### 3.5 Webkit Cache (Local Storage & Cookies)

Using Node.js built-in `node:sqlite` module to read Chromium SQLite databases:

```javascript
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync('path/to/localstorage.db');
const rows = db.prepare('SELECT * FROM "ItemTable"').all();
```

**Local Storage (`i2.y.qq.com`):**
```json
{"key": "pc_alert_countdown_end", "value": "1786642509238"}
{"key": "imusictjStockData", "value": "{...tracking data...}"}
```

**Cookies:**
```
.qq.com    | fqm_pvqid | 244f761f-2783-4c5c-8ba0-414061248390
.qq.com    | pgv_pvid  | 7951749250
.y.qq.com  | ts_uid    | 5631091113
```

---

### Step 4: Encryption Algorithm Identification

#### 4.1 Binary String Analysis

Search `QMNetwork.dll` for crypto-related strings:

```
crypto\rand\md_rand.c
crypto\engine\eng_init.c
crypto\threads_win.c
crypto\init.c
crypto\evp\digest.c
id-aes128-wrap
aes128-wrap
AES-128-CBC        ← Key finding!
AES128
aes128
id-aes192-wrap
aes129-wrap
AES-192-CBC
AES-256-CBC
```

**Conclusion:** QQ Music uses **OpenSSL** with **AES-128-CBC** as the primary encryption algorithm.

#### 4.2 CEncryptFile Class Analysis

`QQMusicCommon.dll` contains the `CEncryptFile` class with the following methods (from C++ name mangling):

| Mangled Name | Method |
|---|---|
| `??0CEncryptFile@@IAE@XZ` | Default constructor |
| `??0CEncryptFile@@IAE@ABV0@@Z` | Copy constructor |
| `??1CEncryptFile@@IAE@XZ` | Destructor |
| `??4CEncryptFile@@IAEAAV0@ABV0@@Z` | Assignment operator |
| `?AddRef@CEncryptFile@@QAEJXZ` | AddRef (reference counting) |
| `?EncryptData@...` | Encryption method |
| `?DecryptData@...` | Decryption method |

The `AddRef` method indicates a COM-like reference-counted class design.

#### 4.3 Frequency Analysis

```
SetCookie.dat:        entropy = 7.863 bits/byte (max = 8.0)
ConfigInfoXML1.dat:   entropy = ~7.86 bits/byte
QQMusicConfV3.dat:    entropy = ~7.86 bits/byte
```

Entropy close to 8.0 confirms **strong encryption** (AES-like), not simple XOR or substitution.

---

### Step 5: Key Extraction Attempts

#### 5.1 High-Entropy Binary Scanning

Scanned `QQMusicCommon.dll` for 16-byte sequences with entropy ≥ 3.85:

```javascript
// Search near EncryptData function
const searchStart = encryptDataPos - 4096;
const searchEnd = encryptDataPos + 4096;
for (let i = searchStart; i < searchEnd - 16; i++) {
    const slice = commonDll.subarray(i, i + 16);
    if (entropy(slice) >= 3.85) {
        keyCandidates.push({ offset: i, data: slice });
    }
}
```

**Result:** 914 candidates found near `EncryptData`, 41,386 candidates across entire binary. **None successfully decrypted the files.**

#### 5.2 Known-Plaintext Attack

Assuming `ConfigInfoXML1.dat` starts with XML:

```javascript
const knownPlaintexts = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<?xml version="1.0"?>',
    '<ConfigInfo>',
    '<Root>',
    '<config>',
];
```

**Result:** No simple XOR key found. The encryption is confirmed to be AES, not XOR.

#### 5.3 Qimei-Derived Key Attempts

Tried using device fingerprint data as AES keys:
- Qimei hash file (128 bytes) as key stream
- Qimei Config.ini (16 bytes) as repeating key
- Profile config hashes (MD5, 16 bytes each) as AES keys

**Result:** All failed.

#### 5.4 Common Key Attempts

```javascript
const commonKeys = [
    Buffer.from('0123456789abcdef', 'utf8'),
    Buffer.from('QQMusic202400000', 'utf8'),
    Buffer.from(' TencentQQMusic', 'utf8'),
    // ... 10+ common keys
];
```

**Result:** All failed.

---

## 📊 Results Summary

### Successfully Extracted

```json
{
  "qqNumber": "5729475454240175104",
  "qqMusicId": "2131899634",
  "deviceId": "qq=2131899634",
  "appId": "201915",
  "appVersion": "2043.2858.1014",
  "qua": "V1_WPC_KG_20.43.2858_1014_GW_D",
  "apiHosts": [
    "c.y.qq.com",
    "y.qq.com",
    "i2.y.qq.com",
    "isure.stream.qqmusic.qq.com",
    "ws.stream.qqmusic.qq.com"
  ],
  "cookies": {
    "fqm_pvqid": "244f761f-2783-4c5c-8ba0-414061248390",
    "pgv_pvid": "7951749250",
    "ts_uid": "5631091113"
  },
  "qimeiHash": "27ebb697...128-byte device fingerprint",
  "profileConfigHashes": [
    "0b2046113648735db393bd41e57e2f27",
    "8ebe7490a0833980dfb4a2078754c3f0",
    "99f81b52128f485ba4945335e3fbf7bf",
    "3a24b6d78920b969577820e04eb1160c"
  ]
}
```

### Encrypted (Not Recovered)

| File | Size | Contents (Suspected) |
|---|---|---|
| `QQMusicConfV3.dat` | 245 KB | Auth tokens, session keys, API credentials |
| `ConfigInfoXML1.dat` | 270 KB | Full auth info, user profile, signing keys |
| `SetCookie.dat` | 1.7 KB | Login cookies, session tokens |
| `mmkv.default` | 16 KB | Runtime key-value store (token cache?) |

---

## 🔐 Encryption Analysis

### Algorithm: AES-128-CBC (Confirmed)

**Evidence:**
1. `QMNetwork.dll` imports OpenSSL with `AES-128-CBC` string literals
2. `QQMusicCommon.dll` contains `CEncryptFile` class with `EncryptData`/`DecryptData` methods
3. Encrypted files have entropy ~7.86 bits/byte (consistent with AES output)
4. No simple XOR or substitution patterns detected

### Key Management

The `CEncryptFile` class likely manages:
- **Key storage:** Possibly hardcoded in `QQMusicCommon.dll` .rdata section
- **IV (Initialization Vector):** May be fixed (all zeros) or derived from file metadata
- **Key derivation:** May involve device fingerprint (qimei) or machine-specific values

### File Format (Suspected)

```
[16 bytes IV][AES-128-CBC encrypted data][optional padding]
```

Or possibly a custom header format similar to Trae's envelope structure.

---

## ❌ Failed Attempts

| Attempt | Method | Result |
|---|---|---|
| Single-byte XOR | Brute-force 256 keys | No readable output |
| Multi-byte XOR | Keys from binary patterns | No readable output |
| AES-128-CBC | 41,386 binary key candidates | All failed |
| AES-128-ECB | Same candidates | All failed |
| AES-256-CBC | 32-byte binary candidates | All failed |
| Known-plaintext | XML headers as known plaintext | No XOR key found |
| Qimei-derived keys | Device fingerprint as key | All failed |
| Filename hash keys | MD5/SHA256 of filenames | All failed |
| Common keys | ASCII patterns | All failed |

---

## 📊 Comparison with Trae Project

| Aspect | Trae SOLO CN | QQ Music |
|---|---|---|
| **Encryption** | AES-128-CBC | AES-128-CBC |
| **Key Storage** | Hardcoded `LEFT_SECRET` + `RIGHT_SECRET` (64-byte arrays) | Unknown (`CEncryptFile` class) |
| **Envelope Format** | HEADER(6) + randomKey(32) + AES-CBC(SHA512+payload) | Unknown (possibly IV + AES-CBC) |
| **Key Extraction** | ✅ Successful (static binary analysis) | ❌ Failed (key not in obvious location) |
| **Plaintext Files** | `storage.json` (encrypted) | `config.xml`, `*.ini` (plaintext) |
| **Data Richness** | Full auth chain (token, RSA keys, signing keys) | Partial (account ID, device ID, hosts) |

---

## 🔮 Future Work

To fully decrypt QQ Music's encrypted files, the following approaches are recommended:

1. **Static Analysis with IDA Pro/Ghidra**
   - Disassemble `CEncryptFile::EncryptData` in `QQMusicCommon.dll`
   - Trace the key loading mechanism
   - Identify the key derivation function

2. **Dynamic Debugging with x64dbg**
   - Attach to running `QQMusic.exe` process
   - Set breakpoints on `EncryptData`/`DecryptData`
   - Extract AES key and IV from memory/registers

3. **Network Traffic Analysis**
   - Use Wireshark/Fiddler to capture API traffic
   - Analyze authentication headers (Cookie, Authorization, Signatures)
   - Identify token format and validation mechanism

4. **Memory Dump Analysis**
   - Dump process memory during active session
   - Search for token patterns (JWT, session IDs, etc.)
   - Extract credentials from heap/stack

5. **Cross-Machine Comparison**
   - Compare encrypted files across different machines
   - Identify machine-specific vs. universal key components

---

## ⚠️ Disclaimer

This project is for **educational and research purposes only**. The techniques described are intended to:
- Understand desktop application security
- Improve credential protection mechanisms
- Advance reverse engineering knowledge

**Do NOT use these techniques to:**
- Access others' accounts without authorization
- Circumvent license or access controls
- Violate QQ Music's Terms of Service

---

## 📄 License

[MIT License](LICENSE) — Feel free to use, modify, and distribute.

---

<div align="center">

⭐ **Star this repo if you find it useful!** ⭐

[🇨🇳 中文文档](README_zh.md) | [🇺🇸 English](README.md)

</div>
