require('dotenv').config();
const bcrypt = require('bcryptjs');
const pool = require('../server/db');
(async () => {
  const { ADMIN_NAME, ADMIN_EMAIL, ADMIN_PASSWORD } = process.env;
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) throw new Error('Set ADMIN_EMAIL and ADMIN_PASSWORD in .env');
  const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  await pool.query(
    `INSERT INTO users (name,email,password_hash,role) VALUES ($1,$2,$3,'admin')
     ON CONFLICT (email) DO UPDATE SET password_hash=EXCLUDED.password_hash, role='admin', active=TRUE`,
    [ADMIN_NAME || 'Clinic Admin', ADMIN_EMAIL.toLowerCase(), hash]);
  console.log('Admin ready:', ADMIN_EMAIL); await pool.end();
})().catch(e => { console.error(e.message); process.exit(1); });
