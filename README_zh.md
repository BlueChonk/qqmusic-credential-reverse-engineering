# QQ Music 本地凭证逆向工程

[English](README.md) | [中文](README_zh.md)

QQ 音乐桌面客户端本地凭证存储的逆向工程 — AES-128-CBC 加密分析、二进制密钥提取、MMKV/ConfigInfo/Cookie 解密研究。

## 目录

- [概述](#概述)
- [研究目标](#研究目标)
- [数据存储地图](#数据存储地图)
- [详细步骤](#详细步骤)
- [成果总结](#成果总结)
- [加密分析](#加密分析)
- [失败尝试](#失败尝试)
- [后续工作](#后续工作)
- [免责声明](#免责声明)
- [许可证](#许可证)

## 概述

本项目完整记录了 Windows 上 QQ 音乐桌面客户端本地凭证存储的逆向工程过程。目标是从本地存储中提取认证令牌、设备指纹和其他敏感数据。

**核心发现：**

- QQ 音乐将数据存储在 `%APPDATA%\Tencent\QQMusic\` 下，包含 18+ 个文件
- 三个关键文件使用 AES-128-CBC 加密（通过 `QMNetwork.dll` 中的 OpenSSL 字符串确认）
- `QQMusicCommon.dll` 中的 `CEncryptFile` 类管理加密/解密
- 多个明文文件暴露了账号 ID、设备指纹、DNS 缓存和 API 端点
- AES 密钥无法通过静态二进制分析单独提取

## 研究目标

目标是从 QQ 音乐本地存储中提取以下凭证字段：

| 字段 | 说明 | 状态 |
|---|---|---|
| `token` | JWT 认证令牌 | 已加密 |
| `refreshToken` | 刷新令牌 | 已加密 |
| `expiresAt` | 令牌过期时间 | 已加密 |
| `deviceId` | 设备指纹 ID | 部分获取 |
| `machineId` | 机器硬件 ID | 已加密 |
| `privateKeyPEM` | RSA 私钥 | 已加密 |
| `publicKeyPEM` | RSA 公钥 | 已加密 |
| `userId` | 用户账号标识 | 已找到 |
| `host` | API 服务器地址 | 部分获取 |
| `authInfo` | 完整认证信息对象 | 已加密 |
| `signingKeyEntries` | 签名密钥条目 | 已加密 |

## 数据存储地图

```
%APPDATA%\Tencent\QQMusic\
├── WNS\
│   └── 201915\
│       ├── config.xml          [明文] — WNS 网络配置 (uin, deviceId, 服务器地址)
│       └── data\
│           ├── user.data       [二进制] (进程锁定)
│           └── report.data     [二进制]
├── ComData\
│   └── qmcomdata.ini           [明文] — COM 数据 (uin, 路径)
├── QQMusicServiceConfig.ini    [明文] — 服务配置 (Uin=2131899634)
├── DomainCache.ini             [明文] — DNS 缓存 (API 服务器 IP)
├── startup.ini                 [明文] — 启动配置 (硬件信息)
├── WebkitCachePath.ini         [明文] — Webkit 缓存路径
├── MonitorQQMusic.ini          [明文] — 监控配置
├── QQMusicConfV3.dat           [加密] — 主配置文件 (245KB, 可能含认证令牌)
├── ConfigInfoXML1.dat          [加密] — 配置 XML (270KB, 可能含完整认证信息)
├── SetCookie.dat               [加密] — Cookie (1.7KB, 登录 Cookie)
├── mmkv\
│   ├── mmkv.default            [混淆] — MMKV 键值存储 (16KB)
│   └── mmkv.default.crc        [二进制] — MMKV CRC 数据
├── qmlist64.db                 [SQLite] (锁定) — 音乐列表数据库
├── weiyun.file.2131899634.v27.db  [SQLite] — 微云数据库
├── block.dat                   [二进制] — 黑名单数据
├── CrashDump\                  崩溃日志
├── Pic\                        皮肤资源
├── SSN\                        音效资源
└── Logs\                       应用日志
```

此外，QQ 音乐使用腾讯 Qimei 设备指纹服务：

```
%APPDATA%\Tencent\qimei\
├── A201CFB4C8D73FBE6916E0F5A2D14D39  [加密] 128 字节设备指纹哈希
├── Config.ini                           [加密] 16 字节加密配置
├── Global.db                            [加密] 64 字节全局数据
└── RanMgr.db                            [明文] — Profile 配置 (5 个 MD5 哈希)
```

## 详细步骤

### 步骤 1：定位数据存储

在多个位置搜索 QQ 音乐数据目录：

```powershell
# 搜索 AppData\Roaming
Get-ChildItem "$env:APPDATA" -Directory | Where-Object { $_.Name -like '*QQMusic*' }

# 搜索 AppData\Local
Get-ChildItem "$env:LOCALAPPDATA" -Directory | Where-Object { $_.Name -like '*QQMusic*' }

# 搜索 Program Files 安装目录
Get-ChildItem "C:\Program Files\Tencent\QQMusic" -Recurse -File
```

**结果：** 找到 `%APPDATA%\Tencent\QQMusic\` 作为主数据目录，包含 18+ 个文件。

### 步骤 2：分析文件格式

读取每个文件的前 64 字节以确定格式：

| 文件 | 前导字节 (Hex) | 格式 |
|---|---|---|
| `config.xml` | `3C 63 6F 6E 66 69 67 3E` | 纯文本 XML (`<config>`) |
| `QQMusicConfV3.dat` | `49 A4 31 2D 3C B1 5A B0` | 加密二进制 |
| `ConfigInfoXML1.dat` | `61 FD 30 60 24 16 02 26` | 加密二进制 |
| `SetCookie.dat` | `F2 FA 48 4C 94 D7 EF 7C` | 加密二进制 |
| `mmkv.default` | `86 3E 00 00 AF 23 79 03` | MMKV (混淆) |
| `qmlist64.db` | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | SQLite |
| `weiyun.file.*.db` | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | SQLite |

### 步骤 3：提取明文数据

#### 3.1 WNS 配置 (config.xml)

```xml
<config>
    <uin>5729475454240175104</uin>          <!-- QQ号 -->
    <appInfo>
        <appId>201915</appId>
        <appName>QQMusicPC</appName>
        <appVersion>2043.2858.1014</appVersion>
        <qua>V1_WPC_KG_20.43.2858_1014_GW_D</qua>
        <deviceInfo>qq=2131899634</deviceInfo>  <!-- 设备ID -->
    </appInfo>
    <configCookie>417564696F506C617965725032503D333637343826417564696F506C617965725032505F4154563D343237343126...</configCookie>
</config>
```

**解码后的 configCookie：**

```
AudioPlayerP2P=36748&AudioPlayerP2P_ATV=42741&AudioPlayerP2P_PC=22525&RS=28461&WSL=3825915940&WS=14869
```

#### 3.2 服务配置 (QQMusicServiceConfig.ini)

```ini
[Account]
Uin=2131899634
```

#### 3.3 DNS 缓存 (DomainCache.ini)

```ini
[DomainCache]
stat.y.qq.com=14.116.237.185
c.y.qq.com=119.147.3.178
y.qq.com=222.216.230.128
isure.stream.qqmusic.qq.com=59.42.242.215
ws.stream.qqmusic.qq.com=172.29.0.20
```

#### 3.4 Qimei 设备指纹 (RanMgr.db)

```ini
[Profile]
config1=0b2046113648735db393bd41e57e2f27
config2=8ebe7490a0833980dfb4a2078754c3f0
config3=99f81b52128f485ba4945335e3fbf7bf
config4=3a24b6d78920b969577820e04eb1160c
config5=1
```

#### 3.5 Webkit 缓存 (本地存储与 Cookie)

使用 Node.js 内置 `node:sqlite` 模块读取 Chromium SQLite 数据库：

```javascript
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync('path/to/localstorage.db');
const rows = db.prepare('SELECT * FROM "ItemTable"').all();
```

**本地存储 (i2.y.qq.com)：**

```json
{"key": "pc_alert_countdown_end", "value": "1786642509238"}
{"key": "imusictjStockData", "value": "{...追踪数据...}"}
```

**Cookie：**

```
.qq.com    | fqm_pvqid | 244f761f-2783-4c5c-8ba0-414061248390
.qq.com    | pgv_pvid  | 7951749250
.y.qq.com  | ts_uid    | 5631091113
```

### 步骤 4：加密算法识别

#### 4.1 二进制字符串分析

在 `QMNetwork.dll` 中搜索加密相关字符串：

```
crypto\rand\md_rand.c
crypto\engine\eng_init.c
crypto\threads_win.c
crypto\init.c
crypto\evp\digest.c
id-aes128-wrap
aes128-wrap
AES-128-CBC        <-- 关键发现
AES128
aes128
id-aes192-wrap
aes129-wrap
AES-192-CBC
AES-256-CBC
```

**结论：** QQ 音乐使用 OpenSSL 配合 AES-128-CBC 作为主要加密算法。

#### 4.2 CEncryptFile 类分析

`QQMusicCommon.dll` 包含 `CEncryptFile` 类，方法如下（从 C++ 符号修饰解析）：

| 修饰名 | 方法 |
|---|---|
| `??0CEncryptFile@@IAE@XZ` | 默认构造函数 |
| `??0CEncryptFile@@IAE@ABV0@@Z` | 拷贝构造函数 |
| `??1CEncryptFile@@IAE@XZ` | 析构函数 |
| `??4CEncryptFile@@IAEAAV0@ABV0@@Z` | 赋值运算符 |
| `?AddRef@CEncryptFile@@QAEJXZ` | AddRef (引用计数) |
| `?EncryptData@...` | 加密方法 |
| `?DecryptData@...` | 解密方法 |

`AddRef` 方法表明这是一个类似 COM 的引用计数类设计。

#### 4.3 频率分析

```
SetCookie.dat:        熵 = 7.863 bits/byte (最大 = 8.0)
ConfigInfoXML1.dat:   熵 ≈ 7.86 bits/byte
QQMusicConfV3.dat:    熵 ≈ 7.86 bits/byte
```

熵接近 8.0 确认是强加密（AES 级别），而非简单 XOR 或替换密码。

### 步骤 5：密钥提取尝试

#### 5.1 高熵二进制扫描

扫描 `QQMusicCommon.dll` 中熵 >= 3.85 的 16 字节序列：

```javascript
// 在 EncryptData 函数附近搜索
const searchStart = encryptDataPos - 4096;
const searchEnd = encryptDataPos + 4096;
for (let i = searchStart; i < searchEnd - 16; i++) {
    const slice = commonDll.subarray(i, i + 16);
    if (entropy(slice) >= 3.85) {
        keyCandidates.push({ offset: i, data: slice });
    }
}
```

**结果：** 在 `EncryptData` 附近找到 914 个候选，整个二进制中找到 41,386 个候选。全部解密失败。

#### 5.2 已知明文攻击

假设 `ConfigInfoXML1.dat` 以 XML 开头：

```javascript
const knownPlaintexts = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<?xml version="1.0"?>',
    '<ConfigInfo>',
    '<Root>',
    '<config>',
];
```

**结果：** 未找到简单 XOR 密钥。确认加密方式为 AES 而非 XOR。

#### 5.3 Qimei 派生密钥尝试

尝试使用设备指纹数据作为 AES 密钥：
- Qimei 哈希文件 (128 字节) 作为密钥流
- Qimei Config.ini (16 字节) 作为重复密钥
- Profile 配置哈希 (MD5, 各 16 字节) 作为 AES 密钥

**结果：** 全部失败。

#### 5.4 常见密钥尝试

```javascript
const commonKeys = [
    Buffer.from('0123456789abcdef', 'utf8'),
    Buffer.from('QQMusic202400000', 'utf8'),
    Buffer.from(' TencentQQMusic', 'utf8'),
    // ... 10+ 常见密钥
];
```

**结果：** 全部失败。

## 成果总结

### 成功提取

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
  "qimeiHash": "27ebb697...128字节设备指纹",
  "profileConfigHashes": [
    "0b2046113648735db393bd41e57e2f27",
    "8ebe7490a0833980dfb4a2078754c3f0",
    "99f81b52128f485ba4945335e3fbf7bf",
    "3a24b6d78920b969577820e04eb1160c"
  ]
}
```

### 已加密 (未恢复)

| 文件 | 大小 | 内容 (推测) |
|---|---|---|
| `QQMusicConfV3.dat` | 245 KB | 认证令牌、会话密钥、API 凭证 |
| `ConfigInfoXML1.dat` | 270 KB | 完整认证信息、用户资料、签名密钥 |
| `SetCookie.dat` | 1.7 KB | 登录 Cookie、会话令牌 |
| `mmkv.default` | 16 KB | 运行时键值存储 (令牌缓存?) |

## 加密分析

### 算法：AES-128-CBC (已确认)

**证据：**

1. `QMNetwork.dll` 导入了 OpenSSL，包含 `AES-128-CBC` 字符串字面量
2. `QQMusicCommon.dll` 包含 `CEncryptFile` 类及 `EncryptData`/`DecryptData` 方法
3. 加密文件熵值 ~7.86 bits/byte (与 AES 输出一致)
4. 未检测到简单 XOR 或替换模式

### 密钥管理

`CEncryptFile` 类可能管理：
- **密钥存储：** 可能硬编码在 `QQMusicCommon.dll` 的 .rdata 段
- **IV (初始化向量)：** 可能是固定值 (全零) 或从文件元数据派生
- **密钥派生：** 可能涉及设备指纹 (qimei) 或机器特定值

### 文件格式 (推测)

```
[16 字节 IV][AES-128-CBC 加密数据][可选填充]
```

或类似的自定义头部格式。

## 失败尝试

| 尝试 | 方法 | 结果 |
|---|---|---|
| 单字节 XOR | 暴力破解 256 个密钥 | 无可读输出 |
| 多字节 XOR | 二进制模式密钥 | 无可读输出 |
| AES-128-CBC | 41,386 个二进制密钥候选 | 全部失败 |
| AES-128-ECB | 相同候选 | 全部失败 |
| AES-256-CBC | 32 字节二进制候选 | 全部失败 |
| 已知明文攻击 | XML 头作为已知明文 | 未找到 XOR 密钥 |
| Qimei 派生密钥 | 设备指纹作为密钥 | 全部失败 |
| 文件名哈希密钥 | MD5/SHA256 文件名 | 全部失败 |
| 常见密钥 | ASCII 模式 | 全部失败 |

## 后续工作

要完全破解 QQ 音乐加密文件，建议采用以下方法：

1. **IDA Pro/Ghidra 静态分析**
   - 反汇编 `QQMusicCommon.dll` 中的 `CEncryptFile::EncryptData`
   - 追踪密钥加载机制
   - 识别密钥派生函数

2. **x64dbg 动态调试**
   - 附加到运行中的 `QQMusic.exe` 进程
   - 在 `EncryptData`/`DecryptData` 设置断点
   - 从内存/寄存器提取 AES 密钥和 IV

3. **网络流量分析**
   - 使用 Wireshark/Fiddler 捕获 API 流量
   - 分析认证头 (Cookie, Authorization, 签名)
   - 识别令牌格式和验证机制

4. **内存转储分析**
   - 在活动会话期间转储进程内存
   - 搜索令牌模式 (JWT, 会话 ID 等)
   - 从堆/栈提取凭证

5. **跨机器对比**
   - 比较不同机器上的加密文件
   - 识别机器特定组件与通用密钥组件

## 免责声明

本项目仅供教育和研究目的。所述技术旨在：
- 理解桌面应用安全性
- 改进凭证保护机制
- 推进逆向工程知识

**请勿使用这些技术：**
- 未经授权访问他人账户
- 绕过许可或访问控制
- 违反 QQ 音乐的服务条款

## 许可证

[MIT 许可证](LICENSE) — 可自由使用、修改和分发。
