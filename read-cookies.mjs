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
        // List tables
        const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
        for (const t of tables) {
            console.log(`  Table: ${t.name}`);
            if (t.name === 'cookies') {
                const rows = db.prepare('SELECT host_key, name, length(encrypted_value), expires_utc, is_secure FROM cookies ORDER BY expires_utc DESC LIMIT 30').all();
                for (const row of rows) {
                    console.log(`    ${row.host_key} | ${row.name} | enc_len=${row['length(encrypted_value)']} | expires=${row.expires_utc} | secure=${row.is_secure}`);
                }
                // Count total
                const count = db.prepare('SELECT COUNT(*) as cnt FROM cookies').get();
                console.log(`  Total cookies: ${count.cnt}`);
            } else {
                try {
                    const rows = db.prepare(`SELECT * FROM "${t.name}" LIMIT 5`).all();
                    for (const row of rows) {
                        console.log(`    ${JSON.stringify(row)}`);
                    }
                } catch (e) {}
            }
        }
        db.close();
    } catch (e) {
        console.log(`  Error: ${e.message}`);
    }
}
