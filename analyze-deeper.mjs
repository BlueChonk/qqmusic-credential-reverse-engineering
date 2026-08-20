import fs from 'node:fs';
import crypto from 'node:crypto';

const configInfoDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\ConfigInfoXML1.dat`);
const setCookieDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\SetCookie.dat`);
const qqMusicConfDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\QQMusicConfV3.dat`);
const backupConfigInfo = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\_ConfigInfoXML1.dat`);
const backupSetCookie = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\_SetCookie.dat`);

// Strategy: Try AES-ECB (no IV), AES-256-CBC, and other modes

function tryDecrypt(data, key, iv, algorithm) {
    try {
        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    } catch (e) {
        return null;
    }
}

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

function isReadable(data, threshold = 0.7) {
    const text = data.subarray(0, Math.min(200, data.length)).toString('utf8');
    const printable = (text.match(/[\x20-\x7e\n\r\t]/g) || []).length / text.length;
    return printable >= threshold;
}

// Read the QMNetwork.dll for potential keys
const networkDll = fs.readFileSync('C:\\Program Files\\Tencent\\QQMusic\\QMNetwork.dll');

// Strategy 1: Try AES-ECB with high-entropy keys from QQMusicCommon.dll
const commonDll = fs.readFileSync('C:\\Program Files\\Tencent\\QQMusic\\QQMusicCommon.dll');

console.log("=== Strategy 1: AES-ECB ===");
// Find EncryptData position
let encryptDataPos = -1;
for (let i = 0; i < commonDll.length - 10; i++) {
    if (commonDll.subarray(i, i + 10).toString('ascii') === 'EncryptData') {
        encryptDataPos = i;
        break;
    }
}

// Search for keys near EncryptData
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
keyCandidates.sort((a, b) => b.entropy - a.entropy);

for (const candidate of keyCandidates.slice(0, 30)) {
    const decrypted = tryDecrypt(setCookieDat, candidate.data, null, 'aes-128-ecb');
    if (decrypted && isReadable(decrypted)) {
        console.log(`Found AES-ECB key! ${candidate.data.toString('hex')}`);
        console.log(`Decrypted: ${decrypted.subarray(0, 100).toString('utf8')}`);
    }
}

// Strategy 2: Try AES-256-CBC with 32-byte keys
console.log("\n=== Strategy 2: AES-256-CBC with 32-byte keys ===");
const key32Candidates = [];
for (let i = searchStart; i < searchEnd - 32; i++) {
    const slice = commonDll.subarray(i, i + 32);
    const ent = entropy(slice);
    if (ent >= 3.9) {
        key32Candidates.push({ offset: i, entropy: ent, data: Buffer.from(slice) });
    }
}
key32Candidates.sort((a, b) => b.entropy - a.entropy);

for (const candidate of key32Candidates.slice(0, 20)) {
    const iv = Buffer.alloc(16, 0);
    const decrypted = tryDecrypt(setCookieDat, candidate.data, iv, 'aes-256-cbc');
    if (decrypted && isReadable(decrypted)) {
        console.log(`Found AES-256-CBC key! ${candidate.data.toString('hex')}`);
        console.log(`Decrypted: ${decrypted.subarray(0, 100).toString('utf8')}`);
    }
}

// Strategy 3: Try XOR with various key lengths from the binary
console.log("\n=== Strategy 3: XOR with binary-derived keys ===");
for (const candidate of keyCandidates.slice(0, 30)) {
    // XOR decrypt with the 16-byte key
    const decrypted = Buffer.alloc(setCookieDat.length);
    for (let i = 0; i < setCookieDat.length; i++) {
        decrypted[i] = setCookieDat[i] ^ candidate.data[i % 16];
    }
    if (isReadable(decrypted)) {
        console.log(`Found XOR key! ${candidate.data.toString('hex')}`);
        console.log(`Decrypted: ${decrypted.subarray(0, 100).toString('utf8')}`);
    }
}

// Strategy 4: Try key derived from filename hash
console.log("\n=== Strategy 4: Key from filename hash ===");
const filenames = ['ConfigInfoXML1.dat', 'SetCookie.dat', 'QQMusicConfV3.dat', 'config', 'cookie'];
for (const name of filenames) {
    const hash = crypto.createHash('md5').update(name).digest();
    const decrypted = tryDecrypt(setCookieDat, hash, Buffer.alloc(16, 0), 'aes-128-cbc');
    if (decrypted && isReadable(decrypted)) {
        console.log(`Found key from MD5("${name}")! ${hash.toString('hex')}`);
        console.log(`Decrypted: ${decrypted.subarray(0, 100).toString('utf8')}`);
    }
    
    // Also try SHA256 first 16 bytes
    const hash256 = crypto.createHash('sha256').update(name).digest().subarray(0, 16);
    const decrypted2 = tryDecrypt(setCookieDat, hash256, Buffer.alloc(16, 0), 'aes-128-cbc');
    if (decrypted2 && isReadable(decrypted2)) {
        console.log(`Found key from SHA256("${name}")! ${hash256.toString('hex')}`);
    }
}

// Strategy 5: Check if the encrypted files might have a specific structure
// Some implementations use: [4-byte size][encrypted data]
console.log("\n=== Strategy 5: Check file structure ===");
// Check if first 4 bytes could be a size
const sizeLE = configInfoDat.readUInt32LE(0);
const sizeBE = configInfoDat.readUInt32BE(0);
console.log(`ConfigInfoXML1.dat: first 4 bytes LE=${sizeLE}, BE=${sizeBE}`);
console.log(`  If size header: ${sizeLE} + 4 = ${sizeLE + 4} (file size = ${configInfoDat.length})`);

const sizeLE2 = setCookieDat.readUInt32LE(0);
const sizeBE2 = setCookieDat.readUInt32BE(0);
console.log(`SetCookie.dat: first 4 bytes LE=${sizeLE2}, BE=${sizeBE2}`);

// Strategy 6: Look for the key in QMNetwork.dll
console.log("\n=== Strategy 6: Search QMNetwork.dll for keys ===");
const netKeyCandidates = [];
for (let i = 0; i < networkDll.length - 16; i++) {
    const slice = networkDll.subarray(i, i + 16);
    const ent = entropy(slice);
    if (ent >= 3.9) {
        netKeyCandidates.push({ offset: i, entropy: ent, data: Buffer.from(slice) });
    }
}
netKeyCandidates.sort((a, b) => b.entropy - a.entropy);
console.log(`Found ${netKeyCandidates.length} key candidates in QMNetwork.dll`);

for (const candidate of netKeyCandidates.slice(0, 30)) {
    const decrypted = tryDecrypt(setCookieDat, candidate.data, Buffer.alloc(16, 0), 'aes-128-cbc');
    if (decrypted && isReadable(decrypted)) {
        console.log(`Found key in QMNetwork.dll! ${candidate.data.toString('hex')}`);
        console.log(`Decrypted: ${decrypted.subarray(0, 100).toString('utf8')}`);
    }
}

// Strategy 7: Try keys from QQMusic.exe
console.log("\n=== Strategy 7: Search QQMusic.exe for keys ===");
const exeData = fs.readFileSync('C:\\Program Files\\Tencent\\QQMusic\\QQMusic.exe');
const exeKeyCandidates = [];
for (let i = 0; i < exeData.length - 16; i++) {
    const slice = exeData.subarray(i, i + 16);
    const ent = entropy(slice);
    if (ent >= 3.95) {
        exeKeyCandidates.push({ offset: i, entropy: ent, data: Buffer.from(slice) });
    }
}
exeKeyCandidates.sort((a, b) => b.entropy - a.entropy);
console.log(`Found ${exeKeyCandidates.length} key candidates in QQMusic.exe`);

for (const candidate of exeKeyCandidates.slice(0, 50)) {
    const decrypted = tryDecrypt(setCookieDat, candidate.data, Buffer.alloc(16, 0), 'aes-128-cbc');
    if (decrypted && isReadable(decrypted)) {
        console.log(`Found key in QQMusic.exe! ${candidate.data.toString('hex')}`);
        console.log(`Decrypted: ${decrypted.subarray(0, 100).toString('utf8')}`);
    }
}
