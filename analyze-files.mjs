import fs from 'node:fs';

// ============ 1. Analyze MMKV file ============
function analyzeMMKV(filePath) {
    console.log(`\n=== MMKV: ${filePath.split('\\').pop()} ===`);
    const buf = fs.readFileSync(filePath);
    console.log(`  Size: ${buf.length}`);
    
    // MMKV format: 4 bytes header, then key-value pairs
    // Each entry: 4 bytes key_length (little-endian) + key + 4 bytes value_length (little-endian) + value
    // But MMKV may also start with a different header
    
    // Try parsing as MMKV
    let pos = 0;
    
    // First 4 bytes could be version/flags
    const header = buf.readUInt32LE(0);
    console.log(`  Header (LE): 0x${header.toString(16)} (${header})`);
    
    pos = 4;
    const entries = [];
    let count = 0;
    while (pos < buf.length - 8 && count < 200) {
        // Read key length
        const keyLen = buf.readUInt32LE(pos);
        if (keyLen <= 0 || keyLen > 1000 || pos + 4 + keyLen > buf.length) break;
        pos += 4;
        const key = buf.subarray(pos, pos + keyLen).toString('utf8');
        pos += keyLen;
        
        // Read value length
        if (pos + 4 > buf.length) break;
        const valLen = buf.readUInt32LE(pos);
        if (valLen < 0 || valLen > 10000 || pos + 4 + valLen > buf.length) break;
        pos += 4;
        
        // Read value as text
        let val = '';
        try {
            val = buf.subarray(pos, pos + valLen).toString('utf8');
        } catch {
            val = `(binary: ${valLen} bytes)`;
        }
        pos += valLen;
        
        entries.push({ key, val: val.substring(0, 200) });
        count++;
    }
    
    console.log(`  Entries found: ${entries.length}`);
    for (const e of entries) {
        console.log(`    "${e.key}" = "${e.val}"`);
    }
    
    // If that didn't work, try without header
    if (entries.length === 0) {
        console.log("  Trying without header...");
        pos = 0;
        count = 0;
        while (pos < buf.length - 8 && count < 200) {
            const keyLen = buf.readUInt32LE(pos);
            if (keyLen <= 0 || keyLen > 1000 || pos + 4 + keyLen > buf.length) break;
            pos += 4;
            const key = buf.subarray(pos, pos + keyLen).toString('utf8');
            pos += keyLen;
            if (pos + 4 > buf.length) break;
            const valLen = buf.readUInt32LE(pos);
            if (valLen < 0 || valLen > 10000 || pos + 4 + valLen > buf.length) break;
            pos += 4;
            let val = buf.subarray(pos, pos + valLen).toString('utf8');
            pos += valLen;
            console.log(`    "${key}" = "${val.substring(0, 100)}"`);
            count++;
        }
    }
}

// ============ 2. Analyze encrypted .dat files ============
function analyzeEncrypted(filePath) {
    console.log(`\n=== Encrypted: ${filePath.split('\\').pop()} ===`);
    const buf = fs.readFileSync(filePath);
    console.log(`  Size: ${buf.length}`);
    
    // Show first 128 bytes in hex
    const hex = [];
    for (let i = 0; i < Math.min(128, buf.length); i++) {
        hex.push(buf[i].toString(16).padStart(2, '0'));
        if ((i + 1) % 16 === 0) hex.push('\n    ');
        else hex.push(' ');
    }
    console.log(`  First 128 bytes:\n    ${hex.join('')}`);
    
    // Check for XOR patterns
    // Try XOR with first byte
    const xorKey = buf[0];
    const decrypted = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
        decrypted[i] = buf[i] ^ xorKey;
    }
    const decText = decrypted.subarray(0, 100).toString('utf8');
    console.log(`  XOR with 0x${xorKey.toString(16)}: ${decText.substring(0, 80)}`);
    
    // Try common XOR keys
    for (const key of [0xFF, 0xAA, 0x55, 0xA4, 0x61, 0x49]) {
        const d = Buffer.alloc(buf.length);
        for (let i = 0; i < buf.length; i++) d[i] = buf[i] ^ key;
        const t = d.subarray(0, 60).toString('utf8');
        if (/^[a-zA-Z0-9\-_<>\s.\/\\]+$/.test(t.substring(0, 20))) {
            console.log(`  XOR with 0x${key.toString(16)}: ${t.substring(0, 60)}`);
        }
    }
    
    // Check for repeating XOR key (2-byte, 4-byte)
    console.log("\n  Trying to detect XOR key pattern...");
    // Compare known plaintext positions with ciphertext
    // If the file contains XML like "<?xml" or "<config", we can find the XOR key
    const knownPlain = "<?xml version=";
    const possibleKey4 = [];
    for (let k0 = 0; k0 < 256; k0++) {
        for (let k1 = 0; k1 < 256; k1++) {
            for (let k2 = 0; k2 < 256; k2++) {
                for (let k3 = 0; k3 < 256; k3++) {
                    if (buf[0] ^ k0 === knownPlain.charCodeAt(0) &&
                        buf[1] ^ k1 === knownPlain.charCodeAt(1) &&
                        buf[2] ^ k2 === knownPlain.charCodeAt(2) &&
                        buf[3] ^ k3 === knownPlain.charCodeAt(3) &&
                        buf[4] ^ k0 === knownPlain.charCodeAt(4) &&
                        buf[5] ^ k1 === knownPlain.charCodeAt(5) &&
                        buf[6] ^ k2 === knownPlain.charCodeAt(6) &&
                        buf[7] ^ k3 === knownPlain.charCodeAt(7)) {
                        possibleKey4.push([k0, k1, k2, k3]);
                    }
                }
            }
        }
    }
    if (possibleKey4.length > 0 && possibleKey4.length < 20) {
        console.log(`  Found ${possibleKey4.length} possible 4-byte XOR keys`);
        for (const key of possibleKey4.slice(0, 5)) {
            console.log(`    Key: ${key.map(k => '0x' + k.toString(16)).join(' ')}`);
        }
    }
}

// ============ Run analysis ============
const mmkvPath = `${process.env.APPDATA}\\Tencent\\QQMusic\\mmkv\\mmkv.default`;
if (fs.existsSync(mmkvPath)) analyzeMMKV(mmkvPath);

const encFiles = [
    `${process.env.APPDATA}\\Tencent\\QQMusic\\QQMusicConfV3.dat`,
    `${process.env.APPDATA}\\Tencent\\QQMusic\\ConfigInfoXML1.dat`,
    `${process.env.APPDATA}\\Tencent\\QQMusic\\SetCookie.dat`,
    `${process.env.APPDATA}\\Tencent\\QQMusic\\_ConfigInfoXML1.dat`,
    `${process.env.APPDATA}\\Tencent\\QQMusic\\_SetCookie.dat`,
];

for (const f of encFiles) {
    if (fs.existsSync(f)) analyzeEncrypted(f);
}
