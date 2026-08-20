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
        // Cast BigInt to TEXT to avoid JS number issues
        const rows = db.prepare('SELECT host_key, name, value, length(encrypted_value) as enc_len, CAST(expires_utc AS TEXT) as expires, secure, httponly, path FROM cookies ORDER BY CAST(expires_utc AS TEXT) DESC LIMIT 50').all();
        for (const row of rows) {
            const encLen = row.enc_len || 0;
            const val = row.value ? row.value.substring(0, 100) : '';
            console.log(`    ${row.host_key} | ${row.name} | val="${val}" | enc_len=${encLen} | secure=${row.secure}`);
        }
        const count = db.prepare('SELECT COUNT(*) as cnt FROM cookies').get();
        console.log(`  Total cookies: ${count.cnt}`);
        
        // Show unique hosts
        const hosts = db.prepare('SELECT DISTINCT host_key FROM cookies ORDER BY host_key').all();
        console.log(`  Hosts: ${hosts.map(h => h.host_key).join(', ')}`);
        
        // Show cookies with non-empty values (decrypted)
        const decrypted = db.prepare('SELECT host_key, name, value, length(encrypted_value) as enc_len FROM cookies WHERE length(value) > 0 ORDER BY host_key, name').all();
        console.log(`\n  Decrypted cookies (${decrypted.length}):`);
        for (const row of decrypted) {
            console.log(`    ${row.host_key} | ${row.name} = ${row.value}`);
        }
        
        db.close();
    } catch (e) {
        console.log(`  Error: ${e.message}`);
    }
}
