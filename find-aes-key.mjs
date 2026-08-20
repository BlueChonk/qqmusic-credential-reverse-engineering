import fs from 'node:fs';
import crypto from 'node:crypto';

// Read the encrypted files
const configInfoDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\ConfigInfoXML1.dat`);
const setCookieDat = fs.readFileSync(`${process.env.APPDATA}\\Tencent\\QQMusic\\SetCookie.dat`);

// Read the binary
const commonDll = fs.readFileSync('C:\\Program Files\\Tencent\\QQMusic\\QQMusicCommon.dll');

// Find all occurrences of "EncryptData" and nearby data
const target = 'EncryptData';
const positions = [];
for (let i = 0; i < commonDll.length - target.length; i++) {
    if (commonDll.subarray(i, i + target.length).toString('ascii') === target) {
        positions.push(i);
    }
}
console.log(`Found "EncryptData" at ${positions.length} positions: ${positions.join(', ')}`);

// For each position, look for nearby 16-byte sequences that could be AES keys
// AES keys are typically stored as constants in the .rdata section
// Let's look at the surrounding 512 bytes for high-entropy 16-byte sequences

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

// Search for potential AES keys near EncryptData references
for (const pos of positions) {
    const start = Math.max(0, pos - 2048);
    const end = Math.min(commonDll.length, pos + 2048);
    
    console.log(`\nSearching near offset 0x${pos.toString(16)}...`);
    
    // Look for 16-byte aligned sequences with high entropy
    const candidates = [];
    for (let i = start; i < end - 16; i++) {
        const slice = commonDll.subarray(i, i + 16);
        const ent = entropy(slice);
        if (ent > 3.5 && ent < 4.0) {  // High entropy but not random
            // Check if it looks like a key (not all same byte, not sequential)
            const unique = new Set(slice);
            if (unique.size > 8) {
                candidates.push({ offset: i, entropy: ent, data: slice });
            }
        }
    }
    
    // Show top candidates
    candidates.sort((a, b) => b.entropy - a.entropy);
    for (const c of candidates.slice(0, 5)) {
        console.log(`  Offset 0x${c.offset.toString(16)}: entropy=${c.entropy.toFixed(3)} data=${c.data.toString('hex')}`);
    }
}

// Also search for the key near "ConfigInfo" string references
const configInfoStr = 'ConfigInfo';
const configPositions = [];
for (let i = 0; i < commonDll.length - configInfoStr.length; i++) {
    if (commonDll.subarray(i, i + configInfoStr.length).toString('ascii') === configInfoStr) {
        configPositions.push(i);
    }
}
console.log(`\nFound "ConfigInfo" at positions: ${configPositions.slice(0, 10).join(', ')}`);

// Look for keys near ConfigInfo references (the key might be stored near the filename)
for (const pos of configPositions.slice(0, 5)) {
    const start = Math.max(0, pos - 1024);
    const end = Math.min(commonDll.length, pos + 1024);
    
    const candidates = [];
    for (let i = start; i < end - 16; i++) {
        const slice = commonDll.subarray(i, i + 16);
        const ent = entropy(slice);
        if (ent > 3.5 && ent < 4.0) {
            const unique = new Set(slice);
            if (unique.size > 8) {
                candidates.push({ offset: i, entropy: ent, data: slice });
            }
        }
    }
    
    candidates.sort((a, b) => b.entropy - a.entropy);
    if (candidates.length > 0) {
        console.log(`\nNear ConfigInfo @ 0x${pos.toString(16)}:`);
        for (const c of candidates.slice(0, 3)) {
            console.log(`  Offset 0x${c.offset.toString(16)}: entropy=${c.entropy.toFixed(3)} data=${c.data.toString('hex')}`);
        }
    }
}

// Now try known-plaintext attack
// If ConfigInfoXML1.dat is XML, it likely starts with: <?xml version="1.0" encoding="UTF-8"?>
// Or maybe: <ConfigInfo>
// Or: <Root>

const knownPlaintexts = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<?xml version="1.0"?>',
    '<ConfigInfo>',
    '<Root>',
    '<config>',
    '<?xml version=\\"1.0\\"',
    '{\\n  "config"',
    '{\\r\\n  "config"',
];

console.log('\n=== Known-plaintext attack (XOR) ===');
for (const plain of knownPlaintexts) {
    const plainBytes = Buffer.from(plain, 'utf8');
    // Derive XOR key from first N bytes
    const key = Buffer.alloc(plainBytes.length);
    for (let i = 0; i < plainBytes.length; i++) {
        key[i] = configInfoDat[i] ^ plainBytes[i];
    }
    
    // Check if the key has a pattern (repeating, etc.)
    // For a 1-byte XOR key
    const key1 = key[0];
    let allSame1 = true;
    for (let i = 1; i < key.length; i++) {
        if (key[i] !== key1) { allSame1 = false; break; }
    }
    if (allSame1) {
        console.log(`  1-byte XOR key 0x${key1.toString(16)} with plaintext "${plain.substring(0, 30)}..."`);
    }
    
    // For a 2-byte XOR key
    if (key.length >= 4) {
        const key2 = [key[0], key[1]];
        let allSame2 = true;
        for (let i = 0; i < key.length; i++) {
            if (key[i] !== key2[i % 2]) { allSame2 = false; break; }
        }
        if (allSame2) {
            console.log(`  2-byte XOR key ${key2.map(k => '0x' + k.toString(16)).join(' ')} with plaintext "${plain.substring(0, 30)}..."`);
        }
    }
    
    // For a 4-byte XOR key
    if (key.length >= 8) {
        const key4 = [key[0], key[1], key[2], key[3]];
        let allSame4 = true;
        for (let i = 0; i < key.length; i++) {
            if (key[i] !== key4[i % 4]) { allSame4 = false; break; }
        }
        if (allSame4) {
            console.log(`  4-byte XOR key ${key4.map(k => '0x' + k.toString(16)).join(' ')} with plaintext "${plain.substring(0, 30)}..."`);
        }
    }
    
    // For an 8-byte XOR key
    if (key.length >= 16) {
        const key8 = Array.from(key.subarray(0, 8));
        let allSame8 = true;
        for (let i = 0; i < key.length; i++) {
            if (key[i] !== key8[i % 8]) { allSame8 = false; break; }
        }
        if (allSame8) {
            console.log(`  8-byte XOR key ${key8.map(k => '0x' + k.toString(16)).join(' ')} with plaintext "${plain.substring(0, 30)}..."`);
        }
    }
    
    // For a 16-byte XOR key (AES block size)
    if (key.length >= 16) {
        const key16 = Array.from(key.subarray(0, 16));
        // Apply this key to the entire file and check if it produces readable text
        const decrypted = Buffer.alloc(configInfoDat.length);
        for (let i = 0; i < configInfoDat.length; i++) {
            decrypted[i] = configInfoDat[i] ^ key16[i % 16];
        }
        // Check first 100 bytes for readable text
        const decText = decrypted.subarray(0, 100).toString('utf8');
        const printableRatio = (decText.match(/[\x20-\x7e\n\r\t]/g) || []).length / decText.length;
        if (printableRatio > 0.7) {
            console.log(`  16-byte XOR key (produces ${printableRatio.toFixed(2)} readable): ${decText.substring(0, 80)}`);
        }
    }
}
