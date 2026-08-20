import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';

const cookieFiles = [
    'C:\\Users\\Cecilia\\Music\\WebkitCache2\\5039\\Cookies',
    'C:\\Users\\Cecilia\\Music\\WebkitCache2\\5040\\Cookies',
];

for (const dbPath of cookieFiles) {
    if (!fs.existsSync(dbPath)) continue;
    const label = dbPath.split('\\').slice(-2, -1)[0] + '/' + dbPath.split('\\').slice(-1)[0];
    console.log(`\n=== ${label} ===`);
    try {
        const db = new DatabaseSync(dbPath);
        // Get cookies table schema
        const schema = db.prepare("PRAGMA table_info(cookies)").all();
        console.log("  Schema:", JSON.stringify(schema.map(c => c.name)));
        
        // Get all cookies with all columns
        const rows = db.prepare('SELECT * FROM cookies ORDER BY expires_utc DESC LIMIT 50').all();
        for (const row of rows) {
            // Show key fields
            const host = row.host_key || row.host || '';
            const name = row.name || '';
            const encLen = row.encrypted_value ? row.encrypted_value.length : 0;
            const expires = row.expires_utc || 0;
            const path = row.path || '';
            console.log(`    ${host} | ${name} | enc_len=${encLen} | expires=${expires} | path=${path}`);
        }
        const count = db.prepare('SELECT COUNT(*) as cnt FROM cookies').get();
        console.log(`  Total cookies: ${count.cnt}`);
        db.close();
    } catch (e) {
        console.log(`  Error: ${e.message}`);
    }
}
