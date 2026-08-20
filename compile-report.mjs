import fs from 'node:fs';

// ============================================================
// QQ Music 本地凭证逆向提取报告
// ============================================================

const report = {
    metadata: {
        appName: 'QQ Music (QQ音乐)',
        exePath: 'C:\\Program Files\\Tencent\\QQMusic\\QQMusic.exe',
        dataPath: `${process.env.APPDATA}\\Tencent\\QQMusic`,
        appVersion: '2043.2858.1014',
        extractionTime: new Date().toISOString(),
        os: 'Windows',
    },

    // ============ 从明文文件提取的数据 ============
    
    // 1. config.xml (WNS config)
    wnsConfig: {
        source: '%APPDATA%\\Tencent\\QQMusic\\WNS\\201915\\config.xml',
        uin: '5729475454240175104',  // QQ号
        appId: '201915',
        appType: '2',
        appName: 'QQMusicPC',
        appVersion: '2043.2858.1014',
        qua: 'V1_WPC_KG_20.43.2858_1014_GW_D',
        releaseVersion: '2043.2858.1014',
        buildVersion: '2043.2858.1014',
        deviceInfo: 'qq=2131899634',
        channel: 'RDM',
        configCookie: 'AudioPlayerP2P=36748&AudioPlayerP2P_ATV=42741&AudioPlayerP2P_PC=22525&RS=28461&WSL=3825915940&WS=14869',
    },

    // 2. QQMusicServiceConfig.ini
    serviceConfig: {
        source: '%APPDATA%\\Tencent\\QQMusic\\QQMusicServiceConfig.ini',
        Uin: '2131899634',  // QQ音乐账号ID (非QQ号)
    },

    // 3. ComData/qmcomdata.ini
    comData: {
        source: '%APPDATA%\\Tencent\\QQMusic\\ComData\\qmcomdata.ini',
        uin: '0',  // COM接口uin (0 = 未通过COM登录)
        path: 'C:\\Program Files\\Tencent\\QQMusic\\QQMusic.exe',
    },

    // 4. RanMgr.db (Profile configs)
    profileConfigs: {
        source: '%APPDATA%\\Tencent\\qimei\\RanMgr.db',
        config1: '0b2046113648735db393bd41e57e2f27',
        config2: '8ebe7490a0833980dfb4a2078754c3f0',
        config3: '99f81b52128f485ba4945335e3fbf7bf',
        config4: '3a24b6d78920b969577820e04eb1160c',
        config5: '1',
    },

    // 5. Qimei device fingerprint
    qimei: {
        source: '%APPDATA%\\Tencent\\qimei\\',
        hashFile: 'A201CFB4C8D73FBE6916E0F5A2D14D39',
        hashFileHex: '27ebb697944b8cdff05b917588239e50745506eaf699ba428b7e791f39b8516f29d773f2ce3cd4007ab3ab83268cd1b68669706919d4ada86acb118a6c9be59c3eff09815e81d9f688d6bd8883f536ada7584b0d2120bff865c6ab22208dac096088752a7e7c9479688b04e5b630ffc88ea8721498f6b9b52e0a35742f02c2ed',
        configIniHex: '27c72b72f6ee91b6568d2e081d8cb01a',
        globalDbHex: 'b33b604b0518e784a379acd8fbd69fa0a8eda9f0538da7c09fe2f1f8314c9c5f0c3da01c44c19a639f8afcad4847d45c1d745e4ba6adb4a7df4b38f55e82715c',
    },

    // 6. WebkitCache (qmbrowser)
    webkitCache: {
        source: '%USERPROFILE%\\Music\\WebkitCache2\\',
        localStorage: {
            'i2.y.qq.com': {
                pc_alert_countdown_end: '1786642509238',
                imusictjStockData: '{...tracking data...}',
            },
            'y.qq.com': {
                skin_nav_last_tab: 'main',
                gray_filter_config: '{...}',
                imusictjStockData: '{...}',
            },
        },
        cookies: [
            { host: '.qq.com', name: 'fqm_pvqid', value: '244f761f-2783-4c5c-8ba0-414061248390' },
            { host: '.qq.com', name: 'pgv_pvid', value: '7951749250' },
            { host: '.y.qq.com', name: 'ts_uid', value: '5631091113' },
        ],
    },

    // 7. DomainCache (DNS缓存)
    domainCache: {
        source: '%APPDATA%\\Tencent\\QQMusic\\DomainCache.ini',
        entries: {
            'stat.y.qq.com': '14.116.237.185',
            'c.y.qq.com': '119.147.3.178',
            'y.qq.com': '222.216.230.128',
            'isure.stream.qqmusic.qq.com': '59.42.242.215',
            'ws.stream.qqmusic.qq.com': '172.29.0.20',
        },
    },

    // ============ 加密文件 (未能解密) ============
    
    encryptedFiles: [
        {
            name: 'QQMusicConfV3.dat',
            path: '%APPDATA%\\Tencent\\QQMusic\\QQMusicConfV3.dat',
            size: 245472,
            description: '主配置文件 (可能包含token、auth信息等)',
            encryption: 'AES-128-CBC (推测, 基于QMNetwork.dll中的OpenSSL AES引用)',
            firstBytes: '49a4312d3cb15ab0e0432aab64d8870fc5cf86836015e86485fb44981876f7f7',
            status: '解密失败 - 密钥未能从二进制中提取',
        },
        {
            name: 'ConfigInfoXML1.dat',
            path: '%APPDATA%\\Tencent\\QQMusic\\ConfigInfoXML1.dat',
            size: 270136,
            description: '配置XML文件 (可能包含完整认证信息)',
            encryption: 'AES-128-CBC (推测)',
            firstBytes: '97ba33434519a217fcb52449ed4bde107a20e9429ac5d7f40dff1c6cc886ddc6',
            status: '解密失败',
        },
        {
            name: 'SetCookie.dat',
            path: '%APPDATA%\\Tencent\\QQMusic\\SetCookie.dat',
            size: 1696,
            description: 'Cookie文件 (可能包含登录cookie)',
            encryption: 'AES-128-CBC (推测)',
            firstBytes: 'f2fa484c94d7ef7c76ad0c69696aacfefac5adade84eb748e3e704df089225f3',
            status: '解密失败',
        },
        {
            name: 'mmkv.default',
            path: '%APPDATA%\\Tencent\\QQMusic\\mmkv\\mmkv.default',
            size: 16384,
            description: 'MMKV键值存储 (Tencent MMKV格式)',
            encryption: '可能经过MMKV加密或混淆',
            firstBytes: '863e0000af2379037e69f2dc8cfc3625674cfee22cb513438eff00c8fcc9cc87',
            status: '解析失败 - 不是标准MMKV格式, 可能经过XOR混淆',
        },
    ],

    // ============ 用户请求的字段映射 ============
    
    requestedFields: {
        token: { status: 'NOT_FOUND', source: '加密文件 QQMusicConfV3.dat / ConfigInfoXML1.dat / mmkv.default' },
        refreshToken: { status: 'NOT_FOUND', source: '加密文件 QQMusicConfV3.dat / ConfigInfoXML1.dat' },
        expiresAt: { status: 'NOT_FOUND', source: '加密文件' },
        deviceId: { status: 'PARTIAL', value: 'qq=2131899634 (from config.xml deviceInfo)', source: 'WNS config.xml' },
        machineId: { status: 'NOT_FOUND', source: '加密文件' },
        privateKeyPEM: { status: 'NOT_FOUND', source: '加密文件' },
        publicKeyPEM: { status: 'NOT_FOUND', source: '加密文件' },
        userId: { status: 'FOUND', value: '2131899634 (QQ音乐ID) / 5729475454240175104 (QQ号)', source: 'config.xml uin / QQMusicServiceConfig.ini' },
        host: { status: 'PARTIAL', value: 'c.y.qq.com / y.qq.com / isure.stream.qqmusic.qq.com (from DomainCache)', source: 'DomainCache.ini' },
        authInfo: { status: 'NOT_FOUND', source: '加密文件' },
        signingKeyEntries: { status: 'NOT_FOUND', source: '加密文件' },
    },

    // ============ 提取的数据摘要 ============
    
    extractedData: {
        // 账号标识
        qqNumber: '5729475454240175104',
        qqMusicId: '2131899634',
        deviceId: 'qq=2131899634',
        
        // 应用信息
        appId: '201915',
        appVersion: '2043.2858.1014',
        qua: 'V1_WPC_KG_20.43.2858_1014_GW_D',
        
        // API服务器
        apiHosts: [
            'c.y.qq.com',
            'y.qq.com', 
            'i2.y.qq.com',
            'stat.y.qq.com',
            'isure.stream.qqmusic.qq.com',
            'ws.stream.qqmusic.qq.com',
        ],
        
        // Cookie
        cookies: {
            'fqm_pvqid': '244f761f-2783-4c5c-8ba0-414061248390',
            'pgv_pvid': '7951749250',
            'ts_uid': '5631091113',
        },
        
        // Qimei设备指纹
        qimeiHash: '27ebb697944b8cdff05b917588239e50745506eaf699ba428b7e791f39b8516f29d773f2ce3cd4007ab3ab83268cd1b68669706919d4ada86acb118a6c9be59c3eff09815e81d9f688d6bd8883f536ada7584b0d2120bff865c6ab22208dac096088752a7e7c9479688b04e5b630ffc88ea8721498f6b9b52e0a35742f02c2ed',
        
        // Profile configs (MD5 hashes)
        profileConfigHashes: [
            '0b2046113648735db393bd41e57e2f27',
            '8ebe7490a0833980dfb4a2078754c3f0',
            '99f81b52128f485ba4945335e3fbf7bf',
            '3a24b6d78920b969577820e04eb1160c',
        ],
    },

    // ============ 逆向分析结论 ============
    
    conclusions: {
        encryptionAlgorithm: 'AES-128-CBC (高度可能, 基于QMNetwork.dll中的OpenSSL AES-128-CBC引用)',
        keyStorage: '密钥可能通过CEncryptFile类管理, 密钥可能硬编码在QQMusicCommon.dll中或通过运行时推导',
        keyDerivation: '未知 - 可能是硬编码密钥 + IV, 或从设备指纹(qimei)推导',
        additionalAnalysis: '需要以下进一步分析: 1) 反汇编QQMusicCommon.dll找到CEncryptFile::EncryptData实现 2) 内存dump运行中的QQMusic进程 3) 网络流量分析获取API认证方式',
    },

    // ============ 文件清单 ============
    
    allDataFiles: [
        { path: '%APPDATA%\\Tencent\\QQMusic\\WNS\\201915\\config.xml', type: '明文XML', description: 'WNS网络配置' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\QQMusicServiceConfig.ini', type: '明文INI', description: '服务配置(含Uin)' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\ComData\\qmcomdata.ini', type: '明文INI', description: 'COM数据' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\DomainCache.ini', type: '明文INI', description: 'DNS缓存' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\startup.ini', type: '明文INI', description: '启动配置(含硬件信息)' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\WebkitCachePath.ini', type: '明文INI', description: 'Webkit缓存路径' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\MonitorQQMusic.ini', type: '明文INI', description: '监控配置' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\QQMusicConfV3.dat', type: '加密(AES?)', description: '主配置文件' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\ConfigInfoXML1.dat', type: '加密(AES?)', description: '配置XML' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\SetCookie.dat', type: '加密(AES?)', description: 'Cookie' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\mmkv\\mmkv.default', type: 'MMKV(混淆)', description: '键值存储' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\qmlist64.db', type: 'SQLite(锁定)', description: '音乐列表数据库' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\weiyun.file.2131899634.v27.db', type: 'SQLite', description: '微云数据库' },
        { path: '%APPDATA%\\Tencent\\QQMusic\\CrashDump\\', type: '崩溃转储', description: '崩溃日志目录' },
        { path: '%APPDATA%\\Tencent\\qqmusic-extract\\', type: '工具脚本', description: '提取工具目录' },
        { path: '%USERPROFILE%\\Music\\WebkitCache2\\', type: 'Webkit缓存', description: 'qmbrowser缓存(Cookie/LocalStorage)' },
        { path: '%APPDATA%\\Tencent\\qimei\\', type: '设备指纹', description: 'Tencent Qimei设备指纹服务' },
        { path: '%APPDATA%\\Tencent\\Logs\\QQMusic.tlg', type: '二进制日志', description: 'QQ音乐运行日志(加密/二进制格式)' },
    ],
};

// Print report
console.log(JSON.stringify(report, null, 2));

// Also save to file
fs.writeFileSync(
    'D:\\Projects\\qqmusic-extract\\extraction-report.json',
    JSON.stringify(report, null, 2),
    'utf8'
);
console.log('\n\nReport saved to D:\\Projects\\qqmusic-extract\\extraction-report.json');
