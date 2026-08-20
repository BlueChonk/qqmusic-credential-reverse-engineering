import fs from 'node:fs';

const configInfoDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\ConfigInfoXML1.dat`);
const setCookieDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\SetCookie.dat`);
const backupConfigInfo = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\_ConfigInfoXML1.dat`);
const backupSetCookie = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\_SetCookie.dat`);

// XOR the encrypted file with the backup to cancel out the key
// If both are encrypted with the same key: C1 XOR C2 = P1 XOR P2

// SetCookie.dat (1696 bytes) vs _SetCookie.dat (1712 bytes)
// They have different sizes, so they might use different keys or the backup has extra data

console.log("=== SetCookie.dat vs _SetCookie.dat ===");
console.log(`Sizes: ${setCookieDat.length} vs ${backupSetCookie.length}`);

// XOR the common length
const minLen = Math.min(setCookieDat.length, backupSetCookie.length);
const xorResult = Buffer.alloc(minLen);
for (let i = 0; i < minLen; i++) {
    xorResult[i] = setCookieDat[i] ^ backupSetCookie[i];
}

console.log(`XOR result first 100 bytes: ${xorResult.subarray(0, 100).toString('hex')}`);
console.log(`XOR result as text: ${xorResult.subarray(0, 100).toString('utf8').replace(/[^\x20-\x7e]/g, '.')}`);

// Check if XOR result has patterns
// If both plaintexts start with the same header, the XOR would start with zeros
let zeroCount = 0;
for (let i = 0; i < 32; i++) {
    if (xorResult[i] === 0) zeroCount++;
}
console.log(`Zero bytes in first 32: ${zeroCount}`);

// If the XOR result starts with many zeros, both files share the same header
if (zeroCount > 8) {
    console.log("Both files likely share the same header!");
}

// ConfigInfoXML1.dat (270136) vs _ConfigInfoXML1.dat (46656)
console.log("\n=== ConfigInfoXML1.dat vs _ConfigInfoXML1.dat ===");
console.log(`Sizes: ${configInfoDat.length} vs ${backupConfigInfo.length}`);

const minLen2 = Math.min(configInfoDat.length, backupConfigInfo.length);
const xorResult2 = Buffer.alloc(minLen2);
for (let i = 0; i < minLen2; i++) {
    xorResult2[i] = configInfoDat[i] ^ backupConfigInfo[i];
}

console.log(`XOR first 64 bytes hex: ${xorResult2.subarray(0, 64).toString('hex')}`);
console.log(`XOR first 64 bytes text: ${xorResult2.subarray(0, 64).toString('utf8').replace(/[^\x20-\x7e]/g, '.')}`);

let zeroCount2 = 0;
for (let i = 0; i < 64; i++) {
    if (xorResult2[i] === 0) zeroCount2++;
}
console.log(`Zero bytes in first 64: ${zeroCount2}`);

// Try to find XOR key from known file structure
// If we know what the plaintext should start with, we can derive the key
// Common XML headers: <?xml version="1.0" encoding="UTF-8"?>

// Actually, let me try a different approach: look for the key in the backup files
// The backup files might contain the key in their header or have a known structure

// Let me also check if the files might be using a simple XOR with a key derived from the file position
console.log("\n=== Position-based XOR analysis ===");
// Check if there's a pattern where the same plaintext byte always maps to the same ciphertext byte
// (which would indicate a simple substitution cipher)

// For SetCookie.dat, check if there are repeated patterns
const freq = new Array(256).fill(0);
for (let i = 0; i < setCookieDat.length; i++) {
    freq[setCookieDat[i]]++;
}
// Sort by frequency
const sortedFreq = freq.map((count, byte) => ({ byte, count })).sort((a, b) => b.count - a.count);
console.log("Top 10 most frequent bytes in SetCookie.dat:");
for (let i = 0; i < 10; i++) {
    console.log(`  0x${sortedFreq[i].byte.toString(16).padStart(2, '0')}: ${sortedFreq[i].count} times`);
}

// In English text, the most common byte is space (0x20), then 'e' (0x65), 't' (0x74), etc.
// In XML, the most common bytes are typically '<', '>', '=', '"', ' ', letters
// If the encryption is simple XOR, the frequency distribution should be similar to plaintext

// Check the frequency distribution
const total = setCookieDat.length;
const top10count = sortedFreq.slice(0, 10).reduce((sum, f) => sum + f.count, 0);
console.log(`Top 10 bytes account for ${(top10count/total*100).toFixed(1)}% of the file`);

// For comparison, random data would have ~3.9% for top 10 (10/256)
// English text typically has 50-60% for top 10
if (top10count / total > 0.15) {
    console.log("Frequency distribution suggests simple substitution or XOR");
} else {
    console.log("Frequency distribution suggests strong encryption (AES-like)");
}

// Now let me try to find the key by analyzing the structure
// If the file has a known header, we can derive the key

// Let me also check the QQMusicConfV3.dat file
const qqMusicConfDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\QQMusicConfV3.dat`);
const backupConf = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\_ConfigInfoXML1.dat`);

console.log("\n=== QQMusicConfV3.dat analysis ===");
console.log(`Size: ${qqMusicConfDat.length}`);
console.log(`First 32 bytes: ${qqMusicConfDat.subarray(0, 32).toString('hex')}`);

// Check frequency
const freq3 = new Array(256).fill(0);
for (let i = 0; i < qqMusicConfDat.length; i++) {
    freq3[qqMusicConfDat[i]]++;
}
const sortedFreq3 = freq3.map((count, byte) => ({ byte, count })).sort((a, b) => b.count - a.count);
const top10count3 = sortedFreq3.slice(0, 10).reduce((sum, f) => sum + f.count, 0);
console.log(`Top 10 bytes account for ${(top10count3/qqMusicConfDat.length*100).toFixed(1)}% of the file`);
console.log("Top 10 most frequent bytes:");
for (let i = 0; i < 10; i++) {
    console.log(`  0x${sortedFreq3[i].byte.toString(16).padStart(2, '0')}: ${sortedFreq3[i].count} times`);
}
