const fs = require('fs'), path = require('path');
const pool = require('../server/db');
(async () => {
  await pool.query(fs.readFileSync(path.join(__dirname, '../db/schema.sql'), 'utf8'));
  console.log('Schema ready.'); await pool.end();
})().catch(e => { console.error(e.message); process.exit(1); });
