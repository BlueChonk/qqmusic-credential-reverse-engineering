import fs from 'node:fs';
import crypto from 'node:crypto';

// Read encrypted files
const configInfoDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\ConfigInfoXML1.dat`);
const setCookieDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\SetCookie.dat`);

// Read binary
const commonDll = fs.readFileSync('C:\\Program Files\\Tencent\\QQMusic\\QQMusicCommon.dll');

// Strategy 1: Try to find the AES key by searching for high-entropy 16-byte sequences
// that appear near the EncryptData/DecryptData functions

function entropy(data) {
    const freq = new Array(256).fill(0);
    for (const b of data) freq[b]++;
    let ent = 0;
    for (const f of freq) {
        if (f > 0) {
            const p = f / data.length;
            ent -= p * Math.log2(p);
        }
    }
    return ent;
}

// Find EncryptData position
let encryptDataPos = -1;
const encryptStr = 'EncryptData';
for (let i = 0; i < commonDll.length - encryptStr.length; i++) {
    if (commonDll.subarray(i, i + encryptStr.length).toString('ascii') === encryptStr) {
        encryptDataPos = i;
        break;
    }
}

console.log(`EncryptData at offset: 0x${encryptDataPos.toString(16)}`);

// Search for AES keys near EncryptData
// Look for 16-byte sequences with entropy > 3.8
const keyCandidates = [];
const searchStart = Math.max(0, encryptDataPos - 4096);
const searchEnd = Math.min(commonDll.length, encryptDataPos + 4096);

for (let i = searchStart; i < searchEnd - 16; i++) {
    const slice = commonDll.subarray(i, i + 16);
    const ent = entropy(slice);
    if (ent >= 3.85) {
        keyCandidates.push({ offset: i, entropy: ent, data: Buffer.from(slice) });
    }
}

// Sort by entropy
keyCandidates.sort((a, b) => b.entropy - a.entropy);
console.log(`Found ${keyCandidates.length} key candidates near EncryptData`);

// Try each candidate as AES key on the SetCookie.dat file
console.log('\n=== Trying AES-128-CBC decryption ===');
for (const candidate of keyCandidates.slice(0, 20)) {
    try {
        // Try with zero IV
        const iv = Buffer.alloc(16, 0);
        const decipher = crypto.createDecipheriv('aes-128-cbc', candidate.data, iv);
        const decrypted = Buffer.concat([decipher.update(setCookieDat), decipher.final()]);
        
        // Check if decrypted data looks valid
        const text = decrypted.subarray(0, 100).toString('utf8');
        const printable = (text.match(/[\x20-\x7e\n\r\t]/g) || []).length / text.length;
        
        if (printable > 0.6) {
            console.log(`\n*** FOUND KEY! ***`);
            console.log(`Key: ${candidate.data.toString('hex')}`);
            console.log(`Entropy: ${candidate.entropy.toFixed(3)}`);
            console.log(`Offset: 0x${candidate.offset.toString(16)}`);
            console.log(`Decrypted SetCookie.dat (first 200 bytes):`);
            console.log(decrypted.subarray(0, 200).toString('utf8'));
            
            // Also try on ConfigInfoXML1.dat
            try {
                const decipher2 = crypto.createDecipheriv('aes-128-cbc', candidate.data, iv);
                const decrypted2 = Buffer.concat([decipher2.update(configInfoDat), decipher2.final()]);
                console.log(`\nDecrypted ConfigInfoXML1.dat (first 200 bytes):`);
                console.log(decrypted2.subarray(0, 200).toString('utf8'));
            } catch (e) {
                console.log(`ConfigInfoXML1.dat decryption failed: ${e.message}`);
            }
            break;
        }
    } catch (e) {
        // Decryption failed, try next candidate
    }
}

// Strategy 2: Search the entire binary for AES keys
// This is slower but more thorough
console.log('\n=== Full binary scan for AES keys ===');
const allKeyCandidates = [];
for (let i = 0; i < commonDll.length - 16; i += 1) {
    const slice = commonDll.subarray(i, i + 16);
    const ent = entropy(slice);
    if (ent >= 3.9) {
        allKeyCandidates.push({ offset: i, entropy: ent, data: Buffer.from(slice) });
    }
}
allKeyCandidates.sort((a, b) => b.entropy - a.entropy);
console.log(`Found ${allKeyCandidates.length} total key candidates`);

// Try top 50 candidates
for (const candidate of allKeyCandidates.slice(0, 50)) {
    try {
        const iv = Buffer.alloc(16, 0);
        const decipher = crypto.createDecipheriv('aes-128-cbc', candidate.data, iv);
        const decrypted = Buffer.concat([decipher.update(setCookieDat), decipher.final()]);
        const text = decrypted.subarray(0, 100).toString('utf8');
        const printable = (text.match(/[\x20-\x7e\n\r\t]/g) || []).length / text.length;
        
        if (printable > 0.6) {
            console.log(`\n*** FOUND KEY (full scan)! ***`);
            console.log(`Key: ${candidate.data.toString('hex')}`);
            console.log(`Offset: 0x${candidate.offset.toString(16)}`);
            console.log(`Decrypted (first 100 bytes): ${text.substring(0, 100)}`);
            break;
        }
    } catch (e) {}
}

// Strategy 3: Try common AES keys
console.log('\n=== Trying common AES keys ===');
const commonKeys = [
    Buffer.from('0123456789abcdef', 'utf8'),  // ASCII key
    Buffer.from('abcdefghijklmnop', 'utf8'),  // ASCII key
    Buffer.from('QQMusic202400000', 'utf8'),  // QQ Music themed
    Buffer.from(' TencentQQMusic', 'utf8'),   // Tencent themed
    Buffer.from('0000000000000000', 'utf8'),  // All zeros as ASCII
    Buffer.from('ffffffffffffffff', 'utf8'),  // All f's as ASCII
    Buffer.from([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]),  // Sequential
    Buffer.from([15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0]),  // Reverse
    Buffer.from('qqmusicencent00', 'utf8'),  // Mixed
    Buffer.from('00encentqqmusic', 'utf8'),  // Mixed
];

for (const key of commonKeys) {
    try {
        const iv = Buffer.alloc(16, 0);
        const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
        const decrypted = Buffer.concat([decipher.update(setCookieDat), decipher.final()]);
        const text = decrypted.subarray(0, 100).toString('utf8');
        const printable = (text.match(/[\x20-\x7e\n\r\t]/g) || []).length / text.length;
        
        if (printable > 0.5) {
            const keyStr = key.toString('utf8');
            console.log(`Key "${keyStr}" (hex: ${key.toString('hex')}): ${printable.toFixed(2)} readable`);
            console.log(`  First 80 bytes: ${text.substring(0, 80)}`);
        }
    } catch (e) {}
}

// Strategy 4: Check if the file might have a header before the encrypted data
console.log('\n=== Checking file structure ===');
console.log(`ConfigInfoXML1.dat first 32 bytes: ${configInfoDat.subarray(0, 32).toString('hex')}`);
console.log(`SetCookie.dat first 32 bytes: ${setCookieDat.subarray(0, 32).toString('hex')}`);

// Check if the first 16 bytes might be the IV
const possibleIv = setCookieDat.subarray(0, 16);
const possibleData = setCookieDat.subarray(16);
console.log(`\nIf first 16 bytes are IV:`);
console.log(`IV: ${possibleIv.toString('hex')}`);
console.log(`Data starts with: ${possibleData.subarray(0, 32).toString('hex')}`);
