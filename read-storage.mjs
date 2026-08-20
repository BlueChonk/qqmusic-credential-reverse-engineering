import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';

const targets = [
    'C:\\Users\\Cecilia\\Music\\WebkitCache2\\5039\\Local Storage\\https_i2.y.qq.com_0.localstorage',
    'C:\\Users\\Cecilia\\Music\\WebkitCache2\\5039\\Local Storage\\https_y.qq.com_0.localstorage',
    'C:\\Users\\Cecilia\\Music\\WebkitCache2\\5040\\Local Storage\\https_i2.y.qq.com_0.localstorage',
    'C:\\Users\\Cecilia\\Music\\WebkitCache2\\5040\\Local Storage\\https_y.qq.com_0.localstorage',
    'C:\\Users\\Cecilia\\Music\\WebkitCache2\\5040\\Local Storage\\http_y.qq.com_0.localstorage',
    'C:\\Users\\Cecilia\\Music\\WebkitCache2\\5038\\Local Storage\\https_i2.y.qq.com_0.localstorage',
];

for (const dbPath of targets) {
    if (!fs.existsSync(dbPath)) continue;
    const label = dbPath.split('\\').slice(-2).join('/');
    console.log(`\n=== ${label} ===`);
    try {
        const db = new DatabaseSync(dbPath);
        const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
        for (const t of tables) {
            console.log(`  Table: ${t.name}`);
            try {
                const rows = db.prepare(`SELECT * FROM "${t.name}"`).all();
                for (const row of rows) {
                    // Convert any blob columns to string
                    const cleaned = {};
                    for (const [k, v] of Object.entries(row)) {
                        if (v instanceof Buffer) {
                            cleaned[k] = v.toString('utf16le').replace(/\0/g, '');
                        } else if (v instanceof Uint8Array) {
                            cleaned[k] = Buffer.from(v).toString('utf16le').replace(/\0/g, '');
                        } else {
                            cleaned[k] = v;
                        }
                    }
                    console.log(`    ${JSON.stringify(cleaned)}`);
                }
            } catch (e) {
                console.log(`    Error: ${e.message}`);
            }
        }
        db.close();
    } catch (e) {
        console.log(`  Error: ${e.message}`);
    }
}
