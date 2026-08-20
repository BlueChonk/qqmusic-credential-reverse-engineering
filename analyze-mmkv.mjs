import fs from 'node:fs';

const mmkvPath = `${process.env.APPDATA}\\Tencent\\QQMusic\\mmkv\\mmkv.default`;
const buf = fs.readFileSync(mmkvPath);

console.log(`MMKV file size: ${buf.length}`);
console.log(`First 32 bytes hex: ${buf.subarray(0, 32).toString('hex')}`);
console.log(`First 32 bytes: ${Array.from(buf.subarray(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);

// Try different MMKV parsing approaches

// Approach 1: MMKV standard format (4-byte version + 4-byte actualSize + KV pairs)
// version(4) + actualSize(4) + keyLen(4) + key + valueLen(4) + value ...
console.log("\n--- Approach 1: Standard MMKV ---");
let pos = 0;
const version = buf.readUInt32LE(pos); pos += 4;
console.log(`Version: ${version} (0x${version.toString(16)})`);
const actualSize = buf.readUInt32LE(pos); pos += 4;
console.log(`ActualSize: ${actualSize}`);

let count = 0;
while (pos < buf.length - 8 && count < 100) {
    if (pos + 4 > buf.length) break;
    const keyLen = buf.readUInt32LE(pos); pos += 4;
    if (keyLen <= 0 || keyLen > 200 || pos + keyLen > buf.length) {
        console.log(`  Invalid keyLen=${keyLen} at pos=${pos-4}, stopping`);
        break;
    }
    const key = buf.subarray(pos, pos + keyLen).toString('utf8');
    pos += keyLen;
    if (pos + 4 > buf.length) break;
    const valLen = buf.readUInt32LE(pos); pos += 4;
    if (valLen < 0 || valLen > 5000 || pos + valLen > buf.length) {
        console.log(`  Invalid valLen=${valLen} for key="${key}" at pos=${pos-4}, stopping`);
        break;
    }
    let val = '';
    try {
        val = buf.subarray(pos, pos + valLen).toString('utf8');
    } catch { val = `<binary ${valLen}B>`; }
    pos += valLen;
    console.log(`  [${count}] "${key}" = "${val.substring(0, 150)}"`);
    count++;
}
console.log(`Parsed ${count} entries, remaining bytes: ${buf.length - pos}`);

// Approach 2: No header, just KV pairs from start
console.log("\n--- Approach 2: Raw KV pairs from offset 0 ---");
pos = 0;
count = 0;
while (pos < buf.length - 8 && count < 50) {
    const keyLen = buf.readUInt32LE(pos); pos += 4;
    if (keyLen <= 0 || keyLen > 200 || pos + keyLen > buf.length) break;
    const key = buf.subarray(pos, pos + keyLen).toString('utf8');
    pos += keyLen;
    if (pos + 4 > buf.length) break;
    const valLen = buf.readUInt32LE(pos); pos += 4;
    if (valLen < 0 || valLen > 5000 || pos + valLen > buf.length) break;
    let val = buf.subarray(pos, pos + valLen).toString('utf8');
    pos += valLen;
    console.log(`  [${count}] "${key}" = "${val.substring(0, 100)}"`);
    count++;
}
console.log(`Parsed ${count} entries, remaining bytes: ${buf.length - pos}`);

// Approach 3: Check if there's a mini-gzip or other encoding
console.log("\n--- Approach 3: Check for gzip ---");
if (buf[0] === 0x1f && buf[1] === 0x8b) {
    console.log("GZIP detected!");
}

// Approach 4: Search for readable strings
console.log("\n--- Approach 4: Search for readable strings ---");
let str = '';
for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b >= 0x20 && b < 0x7f) {
        str += String.fromCharCode(b);
    } else {
        if (str.length >= 4) {
            console.log(`  Offset ${i - str.length}: "${str}"`);
        }
        str = '';
    }
}
if (str.length >= 4) {
    console.log(`  Offset ${buf.length - str.length}: "${str}"`);
}
