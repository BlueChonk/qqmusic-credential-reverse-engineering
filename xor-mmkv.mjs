import fs from 'node:fs';

const mmkvPath = `${process.env.APPDATA}\\Tencent\\QQMusic\\mmkv\\mmkv.default`;
const buf = fs.readFileSync(mmkvPath);

console.log(`MMKV file size: ${buf.length}`);

// Try XOR with single byte keys
console.log("\n=== XOR with single byte keys ===");
for (let key = 0; key < 256; key++) {
    const decrypted = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
        decrypted[i] = buf[i] ^ key;
    }
    
    // Check if first bytes look like a valid MMKV header
    const version = decrypted.readUInt32LE(0);
    if (version === 0 || version === 1) {
        console.log(`Key 0x${key.toString(16)}: version=${version}`);
        // Try to parse the first few entries
        let pos = 4;
        let valid = true;
        for (let e = 0; e < 3; e++) {
            if (pos + 4 > buf.length) { valid = false; break; }
            const keyLen = decrypted.readUInt32LE(pos); pos += 4;
            if (keyLen <= 0 || keyLen > 200) { valid = false; break; }
            const k = decrypted.subarray(pos, pos + keyLen).toString('utf8');
            pos += keyLen;
            if (pos + 4 > buf.length) { valid = false; break; }
            const valLen = decrypted.readUInt32LE(pos); pos += 4;
            if (valLen < 0 || valLen > 5000) { valid = false; break; }
            const v = decrypted.subarray(pos, pos + valLen).toString('utf8');
            pos += valLen;
            console.log(`  Entry ${e}: "${k}" = "${v.substring(0, 50)}"`);
        }
        if (valid) {
            console.log("  *** VALID MMKV FORMAT! ***");
            // Decrypt full file and show all entries
            pos = 4;
            let entryCount = 0;
            while (pos < buf.length - 8 && entryCount < 50) {
                const keyLen = decrypted.readUInt32LE(pos); pos += 4;
                if (keyLen <= 0 || keyLen > 200) break;
                const k = decrypted.subarray(pos, pos + keyLen).toString('utf8');
                pos += keyLen;
                if (pos + 4 > buf.length) break;
                const valLen = decrypted.readUInt32LE(pos); pos += 4;
                if (valLen < 0 || valLen > 5000) break;
                const v = decrypted.subarray(pos, pos + valLen).toString('utf8');
                pos += valLen;
                console.log(`  ${entryCount}: "${k}" = "${v.substring(0, 100)}"`);
                entryCount++;
            }
            break;
        }
    }
}

// Also try XOR with multi-byte keys derived from known data
console.log("\n=== XOR with derived keys ===");
const knownData = [
    'mmkv.default',
    'QQMusic',
    'Tencent',
    'QQMusicConfV3',
    'ConfigInfoXML1',
    'SetCookie',
    '2131899634',
    '5729475454240175104',
];

for (const data of knownData) {
    const key = Buffer.from(data, 'utf8');
    const decrypted = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
        decrypted[i] = buf[i] ^ key[i % key.length];
    }
    
    // Check if it produces readable data
    const text = decrypted.subarray(0, 200).toString('utf8');
    const printable = (text.match(/[\x20-\x7e]/g) || []).length / text.length;
    if (printable > 0.5) {
        console.log(`Key "${data}": ${printable.toFixed(2)} readable`);
        console.log(`  First 100: ${text.substring(0, 100)}`);
    }
}

// Try the CRC file for clues
const crcPath = `${process.env.APPDATA}\\Tencent\\QQMusic\\mmkv\\mmkv.default.crc`;
if (fs.existsSync(crcPath)) {
    const crcBuf = fs.readFileSync(crcPath);
    console.log(`\n=== MMKV CRC file ===`);
    console.log(`Size: ${crcBuf.length}`);
    console.log(`Hex: ${crcBuf.toString('hex')}`);
    const text = crcBuf.toString('utf8');
    if (text.match(/^[\x20-\x7e\s]+$/)) {
        console.log(`Text: ${text}`);
    }
}
