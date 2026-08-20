import fs from 'node:fs';

// Read all key files
const configInfoDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\ConfigInfoXML1.dat`);
const setCookieDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\SetCookie.dat`);
const backupConfigInfo = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\_ConfigInfoXML1.dat`);
const backupSetCookie = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\_SetCookie.dat`);

// Qimei files
const qimeiHash = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\qimei\\A201CFB4C8D73FBE6916E0F5A2D14D39`);
const qimeiConfig = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\qimei\\Config.ini`);
const qimeiGlobal = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\qimei\\Global.db`);

// RanMgr.db data (the config hashes)
const configHashes = [
    '0b2046113648735db393bd41e57e2f27',
    '8ebe7490a0833980dfb4a2078754c3f0',
    '99f81b52128f485ba4945335e3fbf7bf',
    '3a24b6d78920b969577820e04eb1160c',
];

console.log("=== Qimei files ===");
console.log(`qimei hash file (128 bytes): ${qimeiHash.toString('hex')}`);
console.log(`qimei Config.ini (16 bytes): ${qimeiConfig.toString('hex')}`);
console.log(`qimei Global.db (64 bytes): ${qimeiGlobal.toString('hex')}`);

// Try XOR with qimei data
console.log("\n=== XOR SetCookie.dat with qimei hash ===");
const xor1 = Buffer.alloc(Math.min(setCookieDat.length, qimeiHash.length));
for (let i = 0; i < xor1.length; i++) {
    xor1[i] = setCookieDat[i] ^ qimeiHash[i];
}
console.log(`Result: ${xor1.subarray(0, 64).toString('hex')}`);
console.log(`As text: ${xor1.subarray(0, 64).toString('utf8').replace(/[^\x20-\x7e]/g, '.')}`);

// Try XOR with qimei Config.ini (repeating)
console.log("\n=== XOR SetCookie.dat with qimei Config.ini ===");
const xor2 = Buffer.alloc(setCookieDat.length);
for (let i = 0; i < setCookieDat.length; i++) {
    xor2[i] = setCookieDat[i] ^ qimeiConfig[i % qimeiConfig.length];
}
console.log(`Result: ${xor2.subarray(0, 64).toString('hex')}`);
console.log(`As text: ${xor2.subarray(0, 64).toString('utf8').replace(/[^\x20-\x7e]/g, '.')}`);

// Try XOR with config hashes concatenated
const hashKey = Buffer.concat(configHashes.map(h => Buffer.from(h, 'hex')));
console.log(`\n=== XOR SetCookie.dat with config hashes (${hashKey.length} bytes) ===`);
const xor3 = Buffer.alloc(Math.min(setCookieDat.length, hashKey.length));
for (let i = 0; i < xor3.length; i++) {
    xor3[i] = setCookieDat[i] ^ hashKey[i];
}
console.log(`Result: ${xor3.subarray(0, 64).toString('hex')}`);

// Try using the config hashes as AES keys
import crypto from 'node:crypto';

for (const hash of configHashes) {
    try {
        const key = Buffer.from(hash, 'hex');
        const iv = Buffer.alloc(16, 0);
        const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
        const decrypted = Buffer.concat([decipher.update(setCookieDat), decipher.final()]);
        const text = decrypted.subarray(0, 100).toString('utf8');
        const printable = (text.match(/[\x20-\x7e\n\r\t]/g) || []).length / text.length;
        if (printable > 0.5) {
            console.log(`\nFound AES key from hash ${hash}!`);
            console.log(`Decrypted: ${text.substring(0, 100)}`);
        }
    } catch (e) {}
}

// Try the full qimei hash file as a key stream
console.log("\n=== XOR with qimei hash as streaming key ===");
const xor4 = Buffer.alloc(setCookieDat.length);
for (let i = 0; i < setCookieDat.length; i++) {
    xor4[i] = setCookieDat[i] ^ qimeiHash[i % qimeiHash.length];
}
console.log(`First 100 bytes: ${xor4.subarray(0, 100).toString('utf8').replace(/[^\x20-\x7e]/g, '.')}`);

// Check if the backup files might be XORed with a simple key
console.log("\n=== Backup file analysis ===");
console.log(`_ConfigInfoXML1.dat first 32: ${backupConfigInfo.subarray(0, 32).toString('hex')}`);
console.log(`_SetCookie.dat first 32: ${backupSetCookie.subarray(0, 32).toString('hex')}`);

// The backup files might be encrypted with the same key as the originals
// Let me check if XORing them gives us useful info
const xorBackup = Buffer.alloc(Math.min(setCookieDat.length, backupSetCookie.length));
for (let i = 0; i < xorBackup.length; i++) {
    xorBackup[i] = setCookieDat[i] ^ backupSetCookie[i];
}
console.log(`\nXOR of SetCookie.dat and _SetCookie.dat:`);
console.log(`First 64 bytes: ${xorBackup.subarray(0, 64).toString('hex')}`);

// Check if XOR result has low entropy (which would indicate both files use the same key)
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

console.log(`XOR result entropy: ${entropy(xorBackup).toFixed(3)}`);
console.log(`SetCookie.dat entropy: ${entropy(setCookieDat).toFixed(3)}`);
console.log(`_SetCookie.dat entropy: ${entropy(backupSetCookie).toFixed(3)}`);

// If XOR entropy is much lower than individual entropies, same key is likely
