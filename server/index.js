require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express'), cors = require('cors');
const bcrypt = require('bcryptjs');
const pool = require('./db');
const { sign, required, adminOnly } = require('./auth');

const app = express();
const allowedOrigins = new Set(
  (process.env.CORS_ORIGIN || 'http://localhost:5173').split(',').map(origin => origin.trim()).filter(Boolean)
);
allowedOrigins.add('https://52-dental-clinic.pages.dev');
app.use(cors({ origin: [...allowedOrigins] }));
app.use(express.json());

const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const q = (text, p) => pool.query(text, p).then(r => r.rows);

async function start() {
  const schema = fs.readFileSync(path.join(__dirname, '../db/schema.sql'), 'utf8');
  await pool.query(schema);
  console.log('Database schema ready.');

  const { ADMIN_NAME, ADMIN_EMAIL, ADMIN_PASSWORD } = process.env;
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const inserted = await q(
      `INSERT INTO users (name,email,password_hash,role)
       VALUES ($1,$2,$3,'admin') ON CONFLICT (email) DO NOTHING RETURNING id`,
      [ADMIN_NAME || 'Clinic Admin', ADMIN_EMAIL.trim().toLowerCase(), await bcrypt.hash(ADMIN_PASSWORD, 10)]
    );
    if (inserted.length) console.log('Initial admin account created.');
  } else if (ADMIN_EMAIL || ADMIN_PASSWORD) {
    console.warn('Set both ADMIN_EMAIL and ADMIN_PASSWORD to provision the initial admin account.');
  }

  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`52-Dental Clinic API running at http://localhost:${port}/api`));
}

// ---------- Auth ----------
app.post('/api/auth/login', wrap(async (req, res) => {
  const { email = '', password = '' } = req.body;
  const [u] = await q('SELECT * FROM users WHERE email=$1 AND active', [email.trim().toLowerCase()]);
  if (!u || !(await bcrypt.compare(password, u.password_hash)))
    return res.status(401).json({ error: 'Wrong email or password. Check both and try again.' });
  res.json({ token: sign(u), user: { id: u.id, name: u.name, role: u.role, email: u.email } });
}));

app.use('/api', required);

// ---------- Dashboard ----------
app.get('/api/dashboard', wrap(async (req, res) => {
  const [r] = await q(`SELECT
    (SELECT COALESCE(SUM(amount),0) FROM payments WHERE paid_at=CURRENT_DATE) AS payments_today,
    (SELECT COALESCE(SUM(amount),0) FROM payments WHERE paid_at=CURRENT_DATE)
      - (SELECT COALESCE(SUM(amount),0) FROM expenses WHERE spent_at=CURRENT_DATE) AS box,
    (SELECT COUNT(*) FROM patients) AS patients,
    (SELECT COUNT(*) FROM appointments WHERE appt_at::date=CURRENT_DATE AND status='scheduled') AS appointments,
    (SELECT COUNT(*) FROM users WHERE active) AS users,
    (SELECT COUNT(*) FROM sessions WHERE session_date=CURRENT_DATE) AS reviews`);
  res.json(r);
}));

// ---------- Patients ----------
app.get('/api/patients', wrap(async (req, res) => {
  const { name = '', from = '' } = req.query;
  res.json(await q(
    `SELECT * FROM patients WHERE name ILIKE $1 AND ($2='' OR created_at::date >= $2::date)
     ORDER BY created_at DESC, id DESC LIMIT 500`, [`%${name}%`, from]));
}));
app.post('/api/patients', wrap(async (req, res) => {
  const { name, phone, gender, note } = req.body;
  if (!name || !phone) return res.status(400).json({ error: 'Patient name and telephone number are required.' });
  const [p] = await q('INSERT INTO patients (name,phone,gender,note) VALUES ($1,$2,$3,$4) RETURNING *',
    [name.trim(), phone.trim(), gender || null, note || null]);
  res.status(201).json(p);
}));
app.get('/api/patients/:id', wrap(async (req, res) => {
  const [p] = await q('SELECT * FROM patients WHERE id=$1', [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Patient file not found.' });
  p.sessions = await q('SELECT * FROM sessions WHERE patient_id=$1 ORDER BY session_date DESC, id DESC', [p.id]);
  res.json(p);
}));
app.put('/api/patients/:id', wrap(async (req, res) => {
  const { name, phone, gender, note } = req.body;
  const [p] = await q('UPDATE patients SET name=$1,phone=$2,gender=$3,note=$4 WHERE id=$5 RETURNING *',
    [name, phone, gender || null, note || null, req.params.id]);
  p ? res.json(p) : res.status(404).json({ error: 'Patient file not found.' });
}));
app.delete('/api/patients/:id', wrap(async (req, res) => {
  await q('DELETE FROM patients WHERE id=$1', [req.params.id]); res.json({ ok: true });
}));

// ---------- Statement ----------
app.get('/api/patients/:id/statement', wrap(async (req, res) => {
  const [p] = await q('SELECT id,name FROM patients WHERE id=$1', [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Patient file not found.' });
  const [t] = await q(`SELECT
    (SELECT COUNT(*) FROM sessions WHERE patient_id=$1) AS sessions,
    (SELECT COALESCE(SUM(cost),0) FROM sessions WHERE patient_id=$1) AS charged,
    (SELECT COALESCE(SUM(amount),0) FROM payments WHERE patient_id=$1) AS paid`, [p.id]);
  const payments = await q('SELECT * FROM payments WHERE patient_id=$1 ORDER BY paid_at DESC, id DESC', [p.id]);
  res.json({ patient: p, sessions: +t.sessions, charged: +t.charged, paid: +t.paid,
             debt: Math.max(+t.charged - +t.paid, 0), payments });
}));

// ---------- Sessions & tooth chart ----------
app.post('/api/patients/:id/sessions', wrap(async (req, res) => {
  const { session_date, cost = 0, notes } = req.body;
  const [s] = await q(
    `INSERT INTO sessions (patient_id,session_date,cost,notes,created_by)
     VALUES ($1,COALESCE($2::date,CURRENT_DATE),$3,$4,$5) RETURNING *`,
    [req.params.id, session_date || null, cost, notes || null, req.user.id]);
  res.status(201).json(s);
}));
app.get('/api/sessions/:id', wrap(async (req, res) => {
  const [s] = await q('SELECT s.*, p.name AS patient_name FROM sessions s JOIN patients p ON p.id=s.patient_id WHERE s.id=$1', [req.params.id]);
  if (!s) return res.status(404).json({ error: 'Session not found.' });
  s.teeth = await q('SELECT tooth,condition,details,surfaces,note FROM session_teeth WHERE session_id=$1 ORDER BY tooth', [s.id]);
  res.json(s);
}));
app.put('/api/sessions/:id', wrap(async (req, res) => {
  const { session_date, cost = 0, notes, teeth = [] } = req.body;
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query('UPDATE sessions SET session_date=COALESCE($1::date,session_date),cost=$2,notes=$3 WHERE id=$4',
      [session_date || null, cost, notes || null, req.params.id]);
    await c.query('DELETE FROM session_teeth WHERE session_id=$1', [req.params.id]);
    for (const t of teeth)
      await c.query('INSERT INTO session_teeth (session_id,tooth,condition,details,surfaces,note) VALUES ($1,$2,$3,$4,$5,$6)',
        [req.params.id, t.tooth, t.condition || 'Normal', t.details || [], t.surfaces || [], t.note || null]);
    await c.query('COMMIT'); res.json({ ok: true });
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}));
app.delete('/api/sessions/:id', wrap(async (req, res) => {
  await q('DELETE FROM sessions WHERE id=$1', [req.params.id]); res.json({ ok: true });
}));

// ---------- Payments ----------
app.get('/api/payments', wrap(async (req, res) => {
  const { date = '', name = '', amount = '', batch = '' } = req.query;
  res.json(await q(
    `SELECT pay.*, p.name AS patient_name FROM payments pay JOIN patients p ON p.id=pay.patient_id
     WHERE ($1='' OR pay.paid_at=$1::date) AND p.name ILIKE $2
       AND ($3='' OR pay.amount=$3::numeric) AND ($4='' OR pay.batch_number ILIKE $5)
     ORDER BY pay.paid_at DESC, pay.id DESC LIMIT 500`, [date, `%${name}%`, amount, batch, `%${batch}%`]));
}));
app.post('/api/payments', wrap(async (req, res) => {
  const { patient_id, session_id, amount, type, batch_number, paid_at } = req.body;
  if (!patient_id || !(+amount > 0)) return res.status(400).json({ error: 'Choose a patient and enter an amount above 0.' });
  const [r] = await q(
    `INSERT INTO payments (patient_id,session_id,amount,type,batch_number,paid_at)
     VALUES ($1,$2,$3,$4,$5,COALESCE($6::date,CURRENT_DATE)) RETURNING *`,
    [patient_id, session_id || null, amount, type || 'Cash', batch_number || null, paid_at || null]);
  res.status(201).json(r);
}));
app.delete('/api/payments/:id', wrap(async (req, res) => {
  await q('DELETE FROM payments WHERE id=$1', [req.params.id]); res.json({ ok: true });
}));

// ---------- Expenses ----------
app.get('/api/expenses', wrap(async (req, res) => res.json(await q('SELECT * FROM expenses ORDER BY spent_at DESC, id DESC LIMIT 500'))));
app.post('/api/expenses', wrap(async (req, res) => {
  const { title, amount, spent_at, note } = req.body;
  if (!title || !(+amount > 0)) return res.status(400).json({ error: 'Enter a title and an amount above 0.' });
  const [r] = await q('INSERT INTO expenses (title,amount,spent_at,note) VALUES ($1,$2,COALESCE($3::date,CURRENT_DATE),$4) RETURNING *',
    [title, amount, spent_at || null, note || null]);
  res.status(201).json(r);
}));
app.delete('/api/expenses/:id', wrap(async (req, res) => {
  await q('DELETE FROM expenses WHERE id=$1', [req.params.id]); res.json({ ok: true });
}));

// ---------- Appointments ----------
app.get('/api/appointments', wrap(async (req, res) => {
  const { day = '' } = req.query;
  res.json(await q(
    `SELECT a.*, p.name AS patient_name, p.phone FROM appointments a JOIN patients p ON p.id=a.patient_id
     WHERE ($1='' OR a.appt_at::date=$1::date) ORDER BY a.appt_at LIMIT 500`, [day]));
}));
app.post('/api/appointments', wrap(async (req, res) => {
  const { patient_id, appt_at, reason } = req.body;
  if (!patient_id || !appt_at) return res.status(400).json({ error: 'Choose a patient and a date and time.' });
  const [r] = await q('INSERT INTO appointments (patient_id,appt_at,reason) VALUES ($1,$2,$3) RETURNING *', [patient_id, appt_at, reason || null]);
  res.status(201).json(r);
}));
app.patch('/api/appointments/:id', wrap(async (req, res) => {
  const [r] = await q('UPDATE appointments SET status=$1 WHERE id=$2 RETURNING *', [req.body.status, req.params.id]);
  res.json(r);
}));
app.delete('/api/appointments/:id', wrap(async (req, res) => {
  await q('DELETE FROM appointments WHERE id=$1', [req.params.id]); res.json({ ok: true });
}));

// ---------- Users (admin) ----------
app.get('/api/users', adminOnly, wrap(async (req, res) =>
  res.json(await q('SELECT id,name,email,role,phone,active,created_at FROM users ORDER BY id'))));
app.post('/api/users', adminOnly, wrap(async (req, res) => {
  const { name, email, password, role = 'doctor', phone } = req.body;
  if (!name || !email || !password || password.length < 8)
    return res.status(400).json({ error: 'Name, email and a password of at least 8 characters are required.' });
  const [u] = await q('INSERT INTO users (name,email,password_hash,role,phone) VALUES ($1,$2,$3,$4,$5) RETURNING id,name,email,role',
    [name, email.toLowerCase(), await bcrypt.hash(password, 10), role, phone || null]);
  res.status(201).json(u);
}));
app.patch('/api/users/:id', adminOnly, wrap(async (req, res) => {
  const { active, role, password } = req.body;
  if (password) await q('UPDATE users SET password_hash=$1 WHERE id=$2', [await bcrypt.hash(password, 10), req.params.id]);
  if (role) await q('UPDATE users SET role=$1 WHERE id=$2', [role, req.params.id]);
  if (typeof active === 'boolean' && +req.params.id !== req.user.id) await q('UPDATE users SET active=$1 WHERE id=$2', [active, req.params.id]);
  res.json({ ok: true });
}));

// Own password change
app.post('/api/me/password', wrap(async (req, res) => {
  const { current, next } = req.body;
  const [u] = await q('SELECT * FROM users WHERE id=$1', [req.user.id]);
  if (!(await bcrypt.compare(current || '', u.password_hash))) return res.status(400).json({ error: 'Current password is wrong.' });
  if (!next || next.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  await q('UPDATE users SET password_hash=$1 WHERE id=$2', [await bcrypt.hash(next, 10), u.id]);
  res.json({ ok: true });
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.code === '23505' ? 409 : 500).json({ error: err.code === '23505' ? 'That value already exists.' : 'Something went wrong on the server.' });
});

start().catch(error => {
  console.error('Failed to initialize the database:', error);
  process.exit(1);
});
