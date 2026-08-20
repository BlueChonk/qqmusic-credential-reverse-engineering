import fs from 'node:fs';

// Read the encrypted files
const configInfoDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\ConfigInfoXML1.dat`);
const setCookieDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\SetCookie.dat`);
const qqMusicConfDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\QQMusicConfV3.dat`);

console.log(`ConfigInfoXML1.dat: ${configInfoDat.length} bytes`);
console.log(`SetCookie.dat: ${setCookieDat.length} bytes`);
console.log(`QQMusicConfV3.dat: ${qqMusicConfDat.length} bytes`);

// The backup files
const backupConfigInfo = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\_ConfigInfoXML1.dat`);
const backupSetCookie = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\_SetCookie.dat`);

// If the encryption is XOR-based, we can try to find the key using known plaintext
// Let's assume ConfigInfoXML1.dat might contain XML-like data

// Strategy 1: Check if the file is XOR with a repeating key
// Try to find the key length by analyzing the XOR of the file with a shifted version

// Strategy 2: Look at the QQMusicCommon.dll binary for hardcoded keys
const commonDll = fs.readFileSync('C:\\Program Files\\Tencent\\QQMusic\\QQMusicCommon.dll');
console.log(`\nQQMusicCommon.dll: ${commonDll.length} bytes`);

// Search for potential AES-128 keys (16 bytes of high entropy)
// Look for the CEncryptFile string and nearby data
const encryptFileStr = 'CEncryptFile';
let encryptFilePos = -1;
for (let i = 0; i < commonDll.length - encryptFileStr.length; i++) {
    if (commonDll[i] === 0x43 && commonDll.subarray(i, i + 11).toString('ascii') === encryptFileStr) {
        encryptFilePos = i;
        console.log(`Found CEncryptFile at offset ${i} (0x${i.toString(16)})`);
        // Show surrounding bytes
        const start = Math.max(0, i - 64);
        const end = Math.min(commonDll.length, i + 200);
        console.log(`  Context: ${commonDll.subarray(start, end).toString('ascii').replace(/[^\x20-\x7e]/g, '.')}`);
        break;
    }
}

// Search for "ConfigInfo" string in the binary
const configInfoStr = 'ConfigInfo';
for (let i = 0; i < commonDll.length - configInfoStr.length; i++) {
    if (commonDll[i] === 0x43 && commonDll.subarray(i, i + 10).toString('ascii') === configInfoStr) {
        console.log(`\nFound ConfigInfo at offset ${i} (0x${i.toString(16)})`);
        const start = Math.max(0, i - 32);
        const end = Math.min(commonDll.length, i + 128);
        console.log(`  Context: ${commonDll.subarray(start, end).toString('ascii').replace(/[^\x20-\x7e]/g, '.')}`);
    }
}

// Search for "SetCookie" string
const setCookieStr = 'SetCookie';
for (let i = 0; i < commonDll.length - setCookieStr.length; i++) {
    if (commonDll[i] === 0x53 && commonDll.subarray(i, i + 9).toString('ascii') === setCookieStr) {
        console.log(`\nFound SetCookie at offset ${i} (0x${i.toString(16)})`);
        const start = Math.max(0, i - 32);
        const end = Math.min(commonDll.length, i + 128);
        console.log(`  Context: ${commonDll.subarray(start, end).toString('ascii').replace(/[^\x20-\x7e]/g, '.')}`);
    }
}

// Search for AES key-related strings
const aesKeywords = ['aes_128_cbc', 'AES_CBC', 'EncryptData', 'DecryptData', 'Encrypt', 'Decrypt'];
for (const kw of aesKeywords) {
    for (let i = 0; i < commonDll.length - kw.length; i++) {
        if (commonDll.subarray(i, i + kw.length).toString('ascii') === kw) {
            console.log(`\nFound "${kw}" at offset ${i} (0x${i.toString(16)})`);
            break;
        }
    }
}

// Search QMNetwork.dll for AES keys
const networkDll = fs.readFileSync('C:\\Program Files\\Tencent\\QQMusic\\QMNetwork.dll');
console.log(`\nQMNetwork.dll: ${networkDll.length} bytes`);

// Look for "AES-128-CBC" string and nearby data
const aesStr = 'AES-128-CBC';
for (let i = 0; i < networkDll.length - aesStr.length; i++) {
    if (networkDll.subarray(i, i + aesStr.length).toString('ascii') === aesStr) {
        console.log(`Found "AES-128-CBC" at offset ${i} (0x${i.toString(16)})`);
        // Show 256 bytes after
        const end = Math.min(networkDll.length, i + 256);
        const slice = networkDll.subarray(i, end);
        console.log(`  Hex: ${slice.toString('hex').match(/.{1,32}/g).join('\n  ')}`);
    }
}

// Look for "aes128" string
const aes128Str = 'aes128';
for (let i = 0; i < networkDll.length - aes128Str.length; i++) {
    if (networkDll.subarray(i, i + aes128Str.length).toString('ascii') === aes128Str) {
        console.log(`\nFound "aes128" at offset ${i} (0x${i.toString(16)})`);
    }
}
