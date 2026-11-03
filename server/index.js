require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { randomUUID } = require('crypto');
const express = require('express'), cors = require('cors');
const bcrypt = require('bcryptjs');
const pool = require('./db');
const { sign, required, adminOnly, requirePermission, requireAllPermissions, requireAnyPermission } = require('./auth');
const {
  DEFAULT_ROLE_PERMISSIONS,
  normalizePermissions,
  constrainRolePermissions
} = require('./permissions');

const app = express();
const allowedOrigins = new Set(
  (process.env.CORS_ORIGIN || 'http://localhost:5173').split(',').map(origin => origin.trim()).filter(Boolean)
);
allowedOrigins.add('http://localhost:5173');
allowedOrigins.add('https://52-dental-clinic.pages.dev');
app.use(cors({ origin: [...allowedOrigins] }));
app.use(express.json({ limit: '2mb' }));

const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const q = (text, p) => pool.query(text, p).then(r => r.rows);

async function start() {
  const schema = fs.readFileSync(path.join(__dirname, '../db/schema.sql'), 'utf8');
  await pool.query(schema);
  for (const [role, permissions] of Object.entries(DEFAULT_ROLE_PERMISSIONS)) {
    await pool.query(
      'INSERT INTO role_permissions (role,permissions) VALUES ($1,$2::jsonb) ON CONFLICT (role) DO NOTHING',
      [role, JSON.stringify(permissions)]
    );
  }
  for (const role of await q('SELECT role,permissions FROM role_permissions')) {
    const permissions = constrainRolePermissions(role.permissions);
    await q('UPDATE role_permissions SET permissions=$1::jsonb WHERE role=$2', [JSON.stringify(permissions), role.role]);
  }
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
  res.json({ token: sign(u), user: { id: u.id, name: u.name, role: u.role, email: u.email, photo: u.photo } });
}));

app.use('/api', required);

// ---------- Clinic print template ----------
app.get('/api/print-template', wrap(async (req, res) => {
  const [template] = await q(
    `SELECT header_mode,header_text,header_image,footer_mode,footer_text,footer_image,updated_at
     FROM clinic_print_template WHERE id=1`
  );
  res.json(template);
}));
app.patch('/api/print-template', requirePermission('settings', 'edit'), wrap(async (req, res) => {
  const { header_mode, header_text = '', header_image = null, footer_mode, footer_text = '', footer_image = null } = req.body || {};
  const validModes = new Set(['none', 'text', 'image', 'both']);
  const validImage = image => {
    if (image === null) return true;
    if (typeof image !== 'string' || image.length > 600000) return false;
    const match = image.match(/^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/);
    if (!match) return false;
    const bytes = Buffer.from(match[1], 'base64');
    return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  };
  if (!validModes.has(header_mode) || !validModes.has(footer_mode) ||
      typeof header_text !== 'string' || header_text.length > 2000 ||
      typeof footer_text !== 'string' || footer_text.length > 2000 ||
      !validImage(header_image) || !validImage(footer_image) ||
      (['image', 'both'].includes(header_mode) && !header_image) ||
      (['image', 'both'].includes(footer_mode) && !footer_image)) {
    return res.status(400).json({ error: 'Choose a valid header and footer layout, enter text under 2000 characters, and upload valid images for image layouts.' });
  }
  const [template] = await q(
    `UPDATE clinic_print_template
     SET header_mode=$1,header_text=$2,header_image=$3,footer_mode=$4,footer_text=$5,footer_image=$6,updated_at=NOW()
     WHERE id=1
     RETURNING header_mode,header_text,header_image,footer_mode,footer_text,footer_image,updated_at`,
    [header_mode, header_text.trim(), header_image, footer_mode, footer_text.trim(), footer_image]
  );
  res.json(template);
}));

// ---------- Services ----------
app.get('/api/services', requireAnyPermission(['sessions', 'view'], ['services', 'view']), wrap(async (req, res) => {
  const includeInactive = (req.user.role === 'admin' || req.user.permissions.services?.edit) && req.query.include_inactive === 'true';
  res.json(await q(
    `SELECT id,service_key,name,icon,duration_minutes,price,active,sort_order
     FROM services ${includeInactive ? '' : 'WHERE active'}
     ORDER BY sort_order,id`
  ));
}));
app.post('/api/services', requirePermission('services', 'create'), wrap(async (req, res) => {
  const { name, icon = '🦷', duration_minutes, price = 0 } = req.body;
  const duration = Number(duration_minutes), amount = Number(price);
  if (typeof name !== 'string' || !name.trim() || name.trim().length > 100 ||
      typeof icon !== 'string' || icon.length > 16 ||
      !Number.isInteger(duration) || duration < 1 || duration > 1440 ||
      !Number.isFinite(amount) || amount < 0) {
    return res.status(400).json({ error: 'Enter a service name, a duration from 1 to 1440 minutes, and a valid non-negative price.' });
  }
  const [service] = await q(
    `INSERT INTO services (service_key,name,icon,duration_minutes,price,sort_order)
     VALUES ($1,$2,$3,$4,$5,COALESCE((SELECT MAX(sort_order)+1 FROM services),1))
     RETURNING id,service_key,name,icon,duration_minutes,price,active,sort_order`,
    [`custom-${randomUUID()}`, name.trim(), icon || '🦷', duration, amount]
  );
  res.status(201).json(service);
}));
app.patch('/api/services/:id', requirePermission('services', 'edit'), wrap(async (req, res) => {
  if (Object.keys(req.body).length === 1 && typeof req.body.active === 'boolean') {
    const [service] = await q(
      'UPDATE services SET active=$1 WHERE id=$2 RETURNING id,service_key,name,icon,duration_minutes,price,active,sort_order',
      [req.body.active, req.params.id]
    );
    return service ? res.json(service) : res.status(404).json({ error: 'Service not found.' });
  }

  const { name, icon, duration_minutes, price } = req.body;
  const duration = Number(duration_minutes), amount = Number(price);
  if (typeof name !== 'string' || !name.trim() || name.trim().length > 100 ||
      typeof icon !== 'string' || icon.length > 16 ||
      !Number.isInteger(duration) || duration < 1 || duration > 1440 ||
      !Number.isFinite(amount) || amount < 0) {
    return res.status(400).json({ error: 'Enter a service name, a duration from 1 to 1440 minutes, and a valid non-negative price.' });
  }
  const [service] = await q(
    `UPDATE services SET name=$1,icon=$2,duration_minutes=$3,price=$4
     WHERE id=$5 RETURNING id,service_key,name,icon,duration_minutes,price,active,sort_order`,
    [name.trim(), icon || '🦷', duration, amount, req.params.id]
  );
  if (!service) return res.status(404).json({ error: 'Service not found.' });
  res.json(service);
}));

// ---------- Dashboard ----------
app.get('/api/dashboard', wrap(async (req, res) => {
  const [r] = await q(`SELECT
    ((SELECT COALESCE(SUM(amount),0) FROM payments WHERE paid_at=CURRENT_DATE)
      -(SELECT COALESCE(SUM(amount),0) FROM invoice_refunds WHERE refunded_at=CURRENT_DATE)) AS payments_today,
    (SELECT COALESCE(SUM(amount),0) FROM payments WHERE paid_at=CURRENT_DATE)
      -(SELECT COALESCE(SUM(amount),0) FROM invoice_refunds WHERE refunded_at=CURRENT_DATE)
      - (SELECT COALESCE(SUM(amount),0) FROM expenses WHERE spent_at=CURRENT_DATE) AS box,
    (SELECT COUNT(*) FROM patients) AS patients,
    (SELECT COUNT(*) FROM appointments WHERE appt_at::date=CURRENT_DATE AND status='scheduled') AS appointments,
    (SELECT COUNT(*) FROM users WHERE active) AS users,
    (SELECT COUNT(*) FROM sessions WHERE session_date=CURRENT_DATE) AS reviews`);
  const visible = {
    payments_today: req.user.permissions.payments.view,
    box: req.user.permissions.payments.view && req.user.permissions.expenses.view,
    patients: req.user.permissions.patients.view,
    appointments: req.user.permissions.appointments.view,
    users: req.user.permissions.users.view,
    reviews: req.user.permissions.sessions.view
  };
  for (const [key, allowed] of Object.entries(visible))
    if (!allowed) r[key] = null;
  res.json(r);
}));

// ---------- Patients ----------
app.get('/api/patients', requirePermission('patients', 'view'), wrap(async (req, res) => {
  const { name = '', from = '' } = req.query;
  res.json(await q(
    `SELECT * FROM patients WHERE name ILIKE $1 AND ($2='' OR created_at::date >= $2::date)
     ORDER BY created_at DESC, id DESC LIMIT 500`, [`%${name}%`, from]));
}));
app.post('/api/patients', requirePermission('patients', 'create'), wrap(async (req, res) => {
  const { name, phone, gender, note } = req.body;
  if (!name || !phone) return res.status(400).json({ error: 'Patient name and telephone number are required.' });
  const [p] = await q('INSERT INTO patients (name,phone,gender,note) VALUES ($1,$2,$3,$4) RETURNING *',
    [name.trim(), phone.trim(), gender || null, note || null]);
  res.status(201).json(p);
}));
app.get('/api/patients/:id', requirePermission('patients', 'view'), wrap(async (req, res) => {
  const [p] = await q('SELECT * FROM patients WHERE id=$1', [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Patient file not found.' });
  p.sessions = req.user.permissions.sessions.view
    ? await q('SELECT * FROM sessions WHERE patient_id=$1 ORDER BY session_date DESC, id DESC', [p.id])
    : [];
  res.json(p);
}));
app.put('/api/patients/:id', requirePermission('patients', 'edit'), wrap(async (req, res) => {
  const { name, phone, gender, note } = req.body;
  const [p] = await q('UPDATE patients SET name=$1,phone=$2,gender=$3,note=$4 WHERE id=$5 RETURNING *',
    [name, phone, gender || null, note || null, req.params.id]);
  p ? res.json(p) : res.status(404).json({ error: 'Patient file not found.' });
}));
app.delete('/api/patients/:id', requirePermission('patients', 'delete'), wrap(async (req, res) => {
  await q('DELETE FROM patients WHERE id=$1', [req.params.id]); res.json({ ok: true });
}));

// ---------- Statement ----------
app.get('/api/patients/:id/statement', requirePermission('reports', 'view'), wrap(async (req, res) => {
  const [p] = await q('SELECT id,name FROM patients WHERE id=$1', [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Patient file not found.' });
  const [t] = await q(`SELECT
    (SELECT COUNT(*) FROM sessions WHERE patient_id=$1) AS sessions,
    ((SELECT COALESCE(SUM(s.cost),0) FROM sessions s
      WHERE s.patient_id=$1 AND NOT EXISTS (SELECT 1 FROM invoices i WHERE i.session_id=s.id AND i.status='open'))
     +(SELECT COALESCE(SUM(total),0) FROM invoices WHERE patient_id=$1 AND status='open')) AS charged,
    ((SELECT COALESCE(SUM(amount),0) FROM payments WHERE patient_id=$1)
     -(SELECT COALESCE(SUM(r.amount),0) FROM invoice_refunds r JOIN invoices i ON i.id=r.invoice_id WHERE i.patient_id=$1)) AS paid`, [p.id]);
  const payments = req.user.permissions.payments.view
    ? await q('SELECT * FROM payments WHERE patient_id=$1 ORDER BY paid_at DESC, id DESC', [p.id])
    : [];
  const invoices = await q(
    `SELECT i.id,i.invoice_number,i.issue_date,i.due_date,i.total,i.status,
       COALESCE(pay.paid,0) AS paid,COALESCE(ref.refunded,0) AS refunded
     FROM invoices i
     LEFT JOIN LATERAL (SELECT SUM(amount) AS paid FROM payments WHERE invoice_id=i.id) pay ON TRUE
     LEFT JOIN LATERAL (SELECT SUM(amount) AS refunded FROM invoice_refunds WHERE invoice_id=i.id) ref ON TRUE
     WHERE i.patient_id=$1 ORDER BY i.issue_date DESC,i.id DESC`, [p.id]);
  invoices.forEach(invoice => {
    invoice.balance = Math.max(Number(invoice.total) - Number(invoice.paid) + Number(invoice.refunded), 0);
    invoice.payment_status = invoiceStatus(invoice);
  });
  if (!req.user.permissions.payments.view)
    invoices.forEach(invoice => { delete invoice.paid; delete invoice.refunded; });
  res.json({ patient: p, sessions: +t.sessions, charged: +t.charged, paid: +t.paid,
             debt: Math.max(+t.charged - +t.paid, 0), payments, invoices });
}));

// ---------- Sessions & tooth chart ----------
app.post('/api/patients/:id/sessions', requireAllPermissions(['patients', 'view'], ['sessions', 'create'], ['sessions', 'edit']), wrap(async (req, res) => {
  const { session_date, cost = 0, notes } = req.body;
  const [s] = await q(
    `INSERT INTO sessions (patient_id,session_date,cost,other_cost,notes,created_by)
     VALUES ($1,COALESCE($2::date,CURRENT_DATE),$3,$3,$4,$5) RETURNING *`,
    [req.params.id, session_date || null, cost, notes || null, req.user.id]);
  res.status(201).json(s);
}));
app.get('/api/sessions/:id', requirePermission('sessions', 'view'), wrap(async (req, res) => {
  const [s] = await q('SELECT s.*, p.name AS patient_name FROM sessions s JOIN patients p ON p.id=s.patient_id WHERE s.id=$1', [req.params.id]);
  if (!s) return res.status(404).json({ error: 'Session not found.' });
  s.teeth = await q('SELECT tooth,condition,details,surfaces,note FROM session_teeth WHERE session_id=$1 ORDER BY tooth', [s.id]);
  s.services = await q(
    'SELECT session_services.service_id AS id,service_name AS name,icon,duration_minutes,unit_price AS price FROM session_services WHERE session_id=$1 ORDER BY session_services.id',
    [s.id]
  );
  res.json(s);
}));
app.put('/api/sessions/:id', requirePermission('sessions', 'edit'), wrap(async (req, res) => {
  const { session_date, cost, other_cost, service_ids, notes, teeth = [] } = req.body;
  if (!Array.isArray(teeth))
    return res.status(400).json({ error: 'Session teeth must be a list.' });

  const usesServices = Object.prototype.hasOwnProperty.call(req.body, 'service_ids');
  const selectedIds = service_ids === undefined ? [] : service_ids;
  if (!Array.isArray(selectedIds) ||
      selectedIds.some(id => !Number.isInteger(Number(id)) || Number(id) < 1) ||
      new Set(selectedIds.map(Number)).size !== selectedIds.length)
    return res.status(400).json({ error: 'Selected services are invalid.' });

  const manualCost = Number(cost);
  const additionalCost = Number(other_cost);
  if ((!usesServices && (!Number.isFinite(manualCost) || manualCost < 0)) ||
      (usesServices && (!Number.isFinite(additionalCost) || additionalCost < 0)))
    return res.status(400).json({ error: 'Session cost must be a valid non-negative amount.' });

  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const existing = await c.query('SELECT id,patient_id FROM sessions WHERE id=$1 FOR UPDATE', [req.params.id]);
    if (!existing.rowCount) {
      await c.query('ROLLBACK');
      return res.status(404).json({ error: 'Session not found.' });
    }

    let totalCost = manualCost;
    if (usesServices) {
      const currentServices = await c.query(
        'SELECT id,name,icon,duration_minutes,price,active FROM services WHERE id=ANY($1::int[]) FOR SHARE',
        [selectedIds.map(Number)]
      );
      const previousServices = await c.query(
        'SELECT service_id,service_name,icon,duration_minutes,unit_price FROM session_services WHERE session_id=$1',
        [req.params.id]
      );
      const previousById = new Map(previousServices.rows.map(service => [service.service_id, service]));
      const currentById = new Map(currentServices.rows.map(service => [service.id, service]));
      const invalid = selectedIds.map(Number).some(id => {
        const service = currentById.get(id);
        return !service || (!service.active && !previousById.has(id));
      });
      if (invalid) {
        await c.query('ROLLBACK');
        return res.status(400).json({ error: 'One or more selected services are unavailable. Refresh the page and try again.' });
      }

      await c.query('DELETE FROM session_services WHERE session_id=$1', [req.params.id]);
      let servicesTotal = 0;
      for (const id of selectedIds.map(Number)) {
        const service = currentById.get(id);
        const previous = previousById.get(id);
        const name = previous ? previous.service_name : service.name;
        const icon = previous ? previous.icon : service.icon;
        const duration = previous ? previous.duration_minutes : service.duration_minutes;
        const price = previous ? previous.unit_price : service.price;
        servicesTotal += Math.round(Number(price) * 100);
        await c.query(
          `INSERT INTO session_services (session_id,service_id,service_name,icon,duration_minutes,unit_price)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          [req.params.id, id, name, icon, duration, price]
        );
      }
      totalCost = (servicesTotal + Math.round(additionalCost * 100)) / 100;
    }

    await c.query(
      `UPDATE sessions SET session_date=COALESCE($1::date,session_date),cost=$2,
       other_cost=CASE WHEN $3 THEN $4 ELSE other_cost END,notes=$5 WHERE id=$6`,
      [session_date || null, totalCost, usesServices, usesServices ? additionalCost : null, notes || null, req.params.id]
    );
    await c.query('DELETE FROM session_teeth WHERE session_id=$1', [req.params.id]);
    for (const t of teeth)
      await c.query('INSERT INTO session_teeth (session_id,tooth,condition,details,surfaces,note) VALUES ($1,$2,$3,$4,$5,$6)',
        [req.params.id, t.tooth, t.condition || 'Normal', t.details || [], t.surfaces || [], t.note || null]);
    await c.query('COMMIT'); res.json({ ok: true, payment_recorded: false });
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}));
app.delete('/api/sessions/:id', requirePermission('sessions', 'delete'), wrap(async (req, res) => {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query('DELETE FROM payments WHERE session_id=$1 AND auto_session_payment AND invoice_id IS NULL', [req.params.id]);
    await c.query('DELETE FROM sessions WHERE id=$1', [req.params.id]);
    await c.query('COMMIT');
    res.json({ ok: true });
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}));

// ---------- Invoices ----------
const invoiceSummarySql = `SELECT i.*,p.name AS patient_name,p.phone AS patient_phone,p.gender AS patient_gender,
  COALESCE(pay.paid,0) AS paid,COALESCE(ref.refunded,0) AS refunded
  FROM invoices i JOIN patients p ON p.id=i.patient_id
  LEFT JOIN LATERAL (SELECT SUM(amount) AS paid FROM payments WHERE invoice_id=i.id) pay ON TRUE
  LEFT JOIN LATERAL (SELECT SUM(amount) AS refunded FROM invoice_refunds WHERE invoice_id=i.id) ref ON TRUE`;
function invoiceStatus(invoice) {
  if (invoice.status === 'void') return 'void';
  const remaining = Math.max(Number(invoice.total) - Number(invoice.paid) + Number(invoice.refunded), 0);
  if (remaining < 0.005) return 'paid';
  if (Number(invoice.paid) > Number(invoice.refunded)) return 'partially paid';
  if (invoice.due_date && String(invoice.due_date).slice(0, 10) < new Date().toISOString().slice(0, 10)) return 'overdue';
  return 'unpaid';
}
async function getInvoice(id, includePaymentHistory = true) {
  const [invoice] = await q(`${invoiceSummarySql} WHERE i.id=$1`, [id]);
  if (!invoice) return null;
  invoice.paid = Number(invoice.paid);
  invoice.refunded = Number(invoice.refunded);
  invoice.balance = Math.max(Number(invoice.total) - invoice.paid + invoice.refunded, 0);
  invoice.payment_status = invoiceStatus(invoice);
  invoice.can_void = invoice.status !== 'void' && invoice.paid <= invoice.refunded;
  invoice.items = await q('SELECT id,description,quantity,unit_price,line_total FROM invoice_items WHERE invoice_id=$1 ORDER BY id', [id]);
  invoice.payments = includePaymentHistory
    ? await q('SELECT id,amount,type,batch_number,paid_at FROM payments WHERE invoice_id=$1 ORDER BY paid_at,id', [id])
    : [];
  invoice.refunds = includePaymentHistory
    ? await q('SELECT id,amount,type,reason,refunded_at FROM invoice_refunds WHERE invoice_id=$1 ORDER BY refunded_at,id', [id])
    : [];
  if (!includePaymentHistory) {
    invoice.paid = null;
    invoice.refunded = null;
  }
  return invoice;
}
async function nextInvoiceNumber(client, issueDate) {
  const [{ number }] = (await client.query("SELECT nextval('invoice_number_seq') AS number")).rows;
  return `INV-${String(issueDate).slice(0, 4)}-${String(number).padStart(6, '0')}`;
}
function validDate(value) {
  if (!value) return true;
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

app.get('/api/invoices', requirePermission('invoices', 'view'), wrap(async (req, res) => {
  const { name = '', status = '' } = req.query;
  const invoices = await q(`${invoiceSummarySql}
    WHERE p.name ILIKE $1 ORDER BY i.issue_date DESC,i.id DESC LIMIT 500`, [`%${name}%`]);
  const result = invoices.map(invoice => {
    const row = { ...invoice, payment_status: invoiceStatus(invoice),
      balance: Math.max(Number(invoice.total) - Number(invoice.paid) + Number(invoice.refunded), 0),
      can_void: invoice.status !== 'void' && Number(invoice.paid) <= Number(invoice.refunded) };
    if (!req.user.permissions.payments.view) {
      delete row.paid;
      delete row.refunded;
    }
    return row;
  });
  res.json(status ? result.filter(invoice => invoice.payment_status === status) : result);
}));
app.get('/api/invoices/:id', requirePermission('invoices', 'view'), wrap(async (req, res) => {
  const invoice = await getInvoice(req.params.id, req.user.permissions.payments.view);
  invoice ? res.json(invoice) : res.status(404).json({ error: 'Invoice not found.' });
}));
app.post('/api/sessions/:id/invoice', requireAllPermissions(['sessions', 'view'], ['invoices', 'create']), wrap(async (req, res) => {
  const client = await pool.connect();
  let invoiceId;
  let created = false;
  try {
    await client.query('BEGIN');
    const [session] = (await client.query(
      `SELECT s.*,p.name AS patient_name FROM sessions s JOIN patients p ON p.id=s.patient_id
       WHERE s.id=$1 FOR UPDATE OF s`, [req.params.id])).rows;
    if (!session) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Session not found.' }); }
    const [existing] = (await client.query("SELECT id FROM invoices WHERE session_id=$1 AND status='open'", [session.id])).rows;
    if (existing) {
      invoiceId = existing.id;
    } else {
      const items = (await client.query(
        'SELECT service_name AS description,unit_price AS price FROM session_services WHERE session_id=$1 ORDER BY id',
        [session.id])).rows.map(item => ({ description: item.description, quantity: 1, unit_price: Number(item.price) }));
      const servicesTotal = items.reduce((sum, item) => sum + Math.round(item.unit_price * 100), 0);
      const total = Math.round(Number(session.cost) * 100);
      const additional = total - servicesTotal;
      if (additional > 0) items.push({ description: items.length ? 'Additional session cost' : `Dental session #${session.id}`, quantity: 1, unit_price: additional / 100 });
      if (!items.length && total > 0) items.push({ description: `Dental session #${session.id}`, quantity: 1, unit_price: total / 100 });
      if (total <= 0) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'A zero-value session cannot be invoiced.' }); }
      const [{ today }] = (await client.query('SELECT CURRENT_DATE::text AS today')).rows;
      const issueDate = req.body?.issue_date || today;
      const dueDate = req.body?.due_date || null;
      if (!validDate(issueDate) || !validDate(dueDate)) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Enter valid issue and due dates.' }); }
      const number = await nextInvoiceNumber(client, issueDate);
      const [invoice] = (await client.query(
        `INSERT INTO invoices (invoice_number,patient_id,session_id,issue_date,due_date,subtotal,total,created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$6,$7) RETURNING id`,
        [number, session.patient_id, session.id, issueDate, dueDate, total / 100, req.user.id])).rows;
      invoiceId = invoice.id;
      for (const item of items) {
        const lineTotal = Math.round(item.quantity * item.unit_price * 100) / 100;
        await client.query(
          'INSERT INTO invoice_items (invoice_id,description,quantity,unit_price,line_total) VALUES ($1,$2,$3,$4,$5)',
          [invoiceId, item.description, item.quantity, item.unit_price, lineTotal]);
      }
      await client.query(
        'UPDATE payments SET invoice_id=$1 WHERE session_id=$2 AND auto_session_payment AND invoice_id IS NULL AND amount<=$3',
        [invoiceId, session.id, total / 100]);
      created = true;
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
  res.status(created ? 201 : 200).json({ id: invoiceId, created, invoice: await getInvoice(invoiceId, req.user.permissions.payments.view) });
}));
app.post('/api/invoices', requireAllPermissions(['patients', 'view'], ['invoices', 'create']), wrap(async (req, res) => {
  const { patient_id, issue_date, due_date, discount = 0, items } = req.body || {};
  if (!Number.isInteger(Number(patient_id)) || Number(patient_id) < 1 ||
      !Array.isArray(items) || items.length < 1 || items.length > 50 ||
      !validDate(issue_date) || !validDate(due_date)) {
    return res.status(400).json({ error: 'Choose a patient, valid dates, and between 1 and 50 invoice items.' });
  }
  const normalized = [];
  for (const item of items) {
    const quantity = Number(item?.quantity), unitPrice = Number(item?.unit_price);
    if (typeof item?.description !== 'string' || !item.description.trim() || item.description.trim().length > 200 ||
        !Number.isFinite(quantity) || quantity <= 0 || quantity > 10000 ||
        Math.abs(quantity * 100 - Math.round(quantity * 100)) > 1e-8 ||
        !Number.isFinite(unitPrice) || unitPrice < 0 || unitPrice > 100000000 ||
        Math.abs(unitPrice * 100 - Math.round(unitPrice * 100)) > 1e-8) {
      return res.status(400).json({ error: 'Each item needs a description, positive quantity, and non-negative price.' });
    }
    normalized.push({ description: item.description.trim(), quantity, unitPrice });
  }
  const subtotalCents = normalized.reduce((sum, item) => sum + Math.round(item.quantity * item.unitPrice * 100), 0);
  const discountCents = Math.round(Number(discount) * 100);
  if (!Number.isSafeInteger(subtotalCents) || subtotalCents > 999999999999 ||
      !Number.isFinite(Number(discount)) || discountCents < 0 || discountCents >= subtotalCents) {
    return res.status(400).json({ error: 'Discount must be non-negative and less than the invoice subtotal.' });
  }
  const client = await pool.connect();
  let invoiceId;
  try {
    await client.query('BEGIN');
    const [patient] = (await client.query('SELECT id FROM patients WHERE id=$1', [patient_id])).rows;
    if (!patient) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Patient file not found.' }); }
    const [{ today }] = (await client.query('SELECT CURRENT_DATE::text AS today')).rows;
    const date = issue_date || today;
    const number = await nextInvoiceNumber(client, date);
    const subtotal = subtotalCents / 100, reduction = discountCents / 100;
    const [invoice] = (await client.query(
      `INSERT INTO invoices (invoice_number,patient_id,issue_date,due_date,subtotal,discount,total,created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [number, patient_id, date, due_date || null, subtotal, reduction, subtotal - reduction, req.user.id])).rows;
    invoiceId = invoice.id;
    for (const item of normalized) {
      const lineTotal = Math.round(item.quantity * item.unitPrice * 100) / 100;
      await client.query(
        'INSERT INTO invoice_items (invoice_id,description,quantity,unit_price,line_total) VALUES ($1,$2,$3,$4,$5)',
        [invoiceId, item.description, item.quantity, item.unitPrice, lineTotal]);
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
  res.status(201).json(await getInvoice(invoiceId, req.user.permissions.payments.view));
}));
app.post('/api/invoices/:id/payments', requireAllPermissions(['invoices', 'view'], ['payments', 'create']), wrap(async (req, res) => {
  const { amount, type = 'Cash', batch_number, paid_at } = req.body || {};
  const value = Number(amount), date = paid_at || null;
  if (!Number.isFinite(value) || value <= 0 || value > 9999999999.99 ||
      Math.abs(value * 100 - Math.round(value * 100)) > 1e-8 ||
      !validDate(date) || !['Cash', 'Card', 'Transfer'].includes(type)) {
    return res.status(400).json({ error: 'Enter a valid payment amount, date, and payment method.' });
  }
  const client = await pool.connect();
  let payment;
  try {
    await client.query('BEGIN');
    const [invoice] = (await client.query('SELECT * FROM invoices WHERE id=$1 FOR UPDATE', [req.params.id])).rows;
    if (!invoice) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Invoice not found.' }); }
    if (invoice.status === 'void') { await client.query('ROLLBACK'); return res.status(409).json({ error: 'A void invoice cannot receive payments.' }); }
    const [totals] = (await client.query(
      `SELECT (SELECT COALESCE(SUM(amount),0) FROM payments WHERE invoice_id=$1) AS paid,
              (SELECT COALESCE(SUM(amount),0) FROM invoice_refunds WHERE invoice_id=$1) AS refunded`,
      [invoice.id])).rows;
    const balance = Number(invoice.total) - Number(totals.paid) + Number(totals.refunded);
    if (value > balance + 0.001) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Payment exceeds the invoice balance of $${Math.max(balance, 0).toFixed(2)}.` }); }
    [payment] = (await client.query(
      `INSERT INTO payments (patient_id,session_id,invoice_id,amount,type,batch_number,paid_at)
       VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7::date,CURRENT_DATE)) RETURNING *`,
      [invoice.patient_id, invoice.session_id, invoice.id, value, type, batch_number || null, date])).rows;
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
  res.status(201).json({ payment, invoice: await getInvoice(req.params.id, req.user.permissions.payments.view) });
}));
app.post('/api/invoices/:id/refunds', requireAllPermissions(['invoices', 'view'], ['payments', 'view'], ['payments', 'edit']), wrap(async (req, res) => {
  const { amount, type = 'Cash', reason, refunded_at } = req.body || {};
  const value = Number(amount), date = refunded_at || null;
  if (!Number.isFinite(value) || value <= 0 || value > 9999999999.99 ||
      Math.abs(value * 100 - Math.round(value * 100)) > 1e-8 || !validDate(date) ||
      !['Cash', 'Card', 'Transfer'].includes(type) || typeof reason !== 'string' || !reason.trim() || reason.trim().length > 500) {
    return res.status(400).json({ error: 'Enter a valid refund amount, method, date, and reason.' });
  }
  const client = await pool.connect();
  let refund;
  try {
    await client.query('BEGIN');
    const [invoice] = (await client.query('SELECT * FROM invoices WHERE id=$1 FOR UPDATE', [req.params.id])).rows;
    if (!invoice) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Invoice not found.' }); }
    const [totals] = (await client.query(
      `SELECT (SELECT COALESCE(SUM(amount),0) FROM payments WHERE invoice_id=$1) AS paid,
              (SELECT COALESCE(SUM(amount),0) FROM invoice_refunds WHERE invoice_id=$1) AS refunded`,
      [invoice.id])).rows;
    const refundable = Number(totals.paid) - Number(totals.refunded);
    if (value > refundable + 0.001) { await client.query('ROLLBACK'); return res.status(400).json({ error: `Refund exceeds the refundable amount of $${Math.max(refundable, 0).toFixed(2)}.` }); }
    [refund] = (await client.query(
      `INSERT INTO invoice_refunds (invoice_id,amount,type,reason,refunded_at,created_by)
       VALUES ($1,$2,$3,$4,COALESCE($5::date,CURRENT_DATE),$6) RETURNING *`,
      [invoice.id, value, type, reason.trim(), date, req.user.id])).rows;
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
  res.status(201).json({ refund, invoice: await getInvoice(req.params.id, req.user.permissions.payments.view) });
}));
app.patch('/api/invoices/:id/void', requireAllPermissions(['invoices', 'view'], ['invoices', 'edit']), wrap(async (req, res) => {
  const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim() : '';
  if (!reason || reason.length > 500) return res.status(400).json({ error: 'Enter a reason for voiding this invoice.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const [invoice] = (await client.query('SELECT * FROM invoices WHERE id=$1 FOR UPDATE', [req.params.id])).rows;
    if (!invoice) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Invoice not found.' }); }
    const [totals] = (await client.query(
      `SELECT (SELECT COALESCE(SUM(amount),0) FROM payments WHERE invoice_id=$1) AS paid,
              (SELECT COALESCE(SUM(amount),0) FROM invoice_refunds WHERE invoice_id=$1) AS refunded`,
      [invoice.id])).rows;
    if (invoice.status !== 'void' && Number(totals.paid) > Number(totals.refunded)) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Refund all recorded invoice payments before voiding this invoice.' });
    }
    await client.query("UPDATE invoices SET status='void',voided_at=NOW(),void_reason=$1 WHERE id=$2", [reason, invoice.id]);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally { client.release(); }
  res.json(await getInvoice(req.params.id, req.user.permissions.payments.view));
}));

// ---------- Payments ----------
app.get('/api/payments', requirePermission('payments', 'view'), wrap(async (req, res) => {
  const { date = '', name = '', amount = '', batch = '' } = req.query;
  res.json(await q(
    `SELECT * FROM (
       SELECT pay.id,pay.patient_id,pay.session_id,pay.invoice_id,pay.auto_session_payment,
         pay.amount,pay.type,pay.batch_number,pay.paid_at,p.name AS patient_name
       FROM payments pay JOIN patients p ON p.id=pay.patient_id
       UNION ALL
       SELECT -refund.id,i.patient_id,i.session_id,i.id AS invoice_id,FALSE AS auto_session_payment,
         -refund.amount AS amount,'Refund: ' || refund.type AS type,refund.reason AS batch_number,
         refund.refunded_at AS paid_at,p.name AS patient_name
       FROM invoice_refunds refund JOIN invoices i ON i.id=refund.invoice_id
       JOIN patients p ON p.id=i.patient_id
     ) activity
     WHERE ($1='' OR paid_at=$1::date) AND patient_name ILIKE $2
       AND ($3='' OR amount=$3::numeric) AND ($4='' OR batch_number ILIKE $5)
     ORDER BY paid_at DESC, id DESC LIMIT 500`, [date, `%${name}%`, amount, batch, `%${batch}%`]));
}));
app.post('/api/payments', requirePermission('payments', 'create'), wrap(async (req, res) => {
  const { patient_id, session_id, amount, type, batch_number, paid_at } = req.body;
  if (!patient_id || !(+amount > 0)) return res.status(400).json({ error: 'Choose a patient and enter an amount above 0.' });
  const [r] = await q(
    `INSERT INTO payments (patient_id,session_id,amount,type,batch_number,paid_at)
     VALUES ($1,$2,$3,$4,$5,COALESCE($6::date,CURRENT_DATE)) RETURNING *`,
    [patient_id, session_id || null, amount, type || 'Cash', batch_number || null, paid_at || null]);
  res.status(201).json(r);
}));
app.delete('/api/payments/:id', requirePermission('payments', 'delete'), wrap(async (req, res) => {
  const [payment] = await q('SELECT invoice_id FROM payments WHERE id=$1', [req.params.id]);
  if (!payment) return res.status(404).json({ error: 'Payment not found.' });
  if (payment.invoice_id) return res.status(409).json({ error: 'Invoice payments must be reversed using the invoice refund action.' });
  await q('DELETE FROM payments WHERE id=$1', [req.params.id]); res.json({ ok: true });
}));

// ---------- Expenses ----------
app.get('/api/expenses', requirePermission('expenses', 'view'), wrap(async (req, res) => res.json(await q('SELECT * FROM expenses ORDER BY spent_at DESC, id DESC LIMIT 500'))));
app.post('/api/expenses', requirePermission('expenses', 'create'), wrap(async (req, res) => {
  const { title, amount, spent_at, note } = req.body;
  if (!title || !(+amount > 0)) return res.status(400).json({ error: 'Enter a title and an amount above 0.' });
  const [r] = await q('INSERT INTO expenses (title,amount,spent_at,note) VALUES ($1,$2,COALESCE($3::date,CURRENT_DATE),$4) RETURNING *',
    [title, amount, spent_at || null, note || null]);
  res.status(201).json(r);
}));
app.delete('/api/expenses/:id', requirePermission('expenses', 'delete'), wrap(async (req, res) => {
  await q('DELETE FROM expenses WHERE id=$1', [req.params.id]); res.json({ ok: true });
}));

// ---------- Appointments ----------
app.get('/api/appointments', requirePermission('appointments', 'view'), wrap(async (req, res) => {
  const { day = '' } = req.query;
  res.json(await q(
    `SELECT a.*, p.name AS patient_name, p.phone FROM appointments a JOIN patients p ON p.id=a.patient_id
     WHERE ($1='' OR a.appt_at::date=$1::date) ORDER BY a.appt_at LIMIT 500`, [day]));
}));
app.post('/api/appointments', requireAllPermissions(['patients', 'view'], ['appointments', 'create']), wrap(async (req, res) => {
  const { patient_id, appt_at, reason } = req.body;
  if (!patient_id || !appt_at) return res.status(400).json({ error: 'Choose a patient and a date and time.' });
  const [r] = await q('INSERT INTO appointments (patient_id,appt_at,reason) VALUES ($1,$2,$3) RETURNING *', [patient_id, appt_at, reason || null]);
  res.status(201).json(r);
}));
app.patch('/api/appointments/:id', requirePermission('appointments', 'edit'), wrap(async (req, res) => {
  const [r] = await q('UPDATE appointments SET status=$1 WHERE id=$2 RETURNING *', [req.body.status, req.params.id]);
  res.json(r);
}));
app.delete('/api/appointments/:id', requirePermission('appointments', 'delete'), wrap(async (req, res) => {
  await q('DELETE FROM appointments WHERE id=$1', [req.params.id]); res.json({ ok: true });
}));

// ---------- Users (admin) ----------
app.get('/api/users', requirePermission('users', 'view'), wrap(async (req, res) =>
  res.json(await q(req.user.role === 'admin'
    ? 'SELECT id,name,email,role,phone,active,created_at FROM users ORDER BY id'
    : 'SELECT id,name,role,active FROM users ORDER BY id'))));
app.post('/api/users', adminOnly, wrap(async (req, res) => {
  const { name, email, password, role = 'doctor', phone } = req.body;
  if (!name || !email || !password || password.length < 8)
    return res.status(400).json({ error: 'Name, email and a password of at least 8 characters are required.' });
  if (!['doctor', 'assistant', 'receptionist', 'admin'].includes(role))
    return res.status(400).json({ error: 'Choose a valid user role.' });
  const [u] = await q('INSERT INTO users (name,email,password_hash,role,phone) VALUES ($1,$2,$3,$4,$5) RETURNING id,name,email,role',
    [name, email.toLowerCase(), await bcrypt.hash(password, 10), role, phone || null]);
  res.status(201).json(u);
}));
app.patch('/api/users/:id', adminOnly, wrap(async (req, res) => {
  const { active, role, password, name, email, phone } = req.body;
  if (role !== undefined && !['doctor', 'assistant', 'receptionist', 'admin'].includes(role))
    return res.status(400).json({ error: 'Choose a valid user role.' });
  if (name !== undefined && (typeof name !== 'string' || !name.trim()))
    return res.status(400).json({ error: 'A name is required.' });
  if (email !== undefined && (typeof email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())))
    return res.status(400).json({ error: 'Enter a valid e-mail address.' });
  if (phone !== undefined && phone !== null && typeof phone !== 'string')
    return res.status(400).json({ error: 'Enter a valid phone number.' });
  if (password !== undefined && password !== '' && (typeof password !== 'string' || password.length < 8))
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });

  const updates = [];
  const values = [];
  const set = (column, value) => {
    values.push(value);
    updates.push(`${column}=$${values.length}`);
  };
  if (name !== undefined) set('name', name.trim());
  if (email !== undefined) set('email', email.trim().toLowerCase());
  if (phone !== undefined) set('phone', phone || null);
  if (role !== undefined) set('role', role);
  if (password) set('password_hash', await bcrypt.hash(password, 10));
  if (typeof active === 'boolean' && +req.params.id !== req.user.id) set('active', active);
  if (updates.length) {
    values.push(req.params.id);
    const updated = await q(`UPDATE users SET ${updates.join(',')} WHERE id=$${values.length} RETURNING id`, values);
    if (!updated.length) return res.status(404).json({ error: 'User not found.' });
  }
  res.json({ ok: true });
}));

app.get('/api/permissions', adminOnly, wrap(async (req, res) => {
  const roles = await q('SELECT role,permissions FROM role_permissions ORDER BY role');
  res.json({ roles });
}));
app.put('/api/permissions/roles/:role', adminOnly, wrap(async (req, res) => {
  const { role } = req.params;
  if (!['doctor', 'assistant', 'receptionist'].includes(role))
    return res.status(400).json({ error: 'Choose a non-admin role.' });
  let permissions;
  try { permissions = normalizePermissions(req.body?.permissions); }
  catch (error) { return res.status(400).json({ error: error.message }); }
  const [saved] = await q(
    `INSERT INTO role_permissions (role,permissions) VALUES ($1,$2::jsonb)
     ON CONFLICT (role) DO UPDATE SET permissions=EXCLUDED.permissions
     RETURNING role,permissions`,
    [role, JSON.stringify(permissions)]
  );
  res.json(saved);
}));
// Own password change
app.get('/api/me', wrap(async (req, res) => {
  const [user] = await q('SELECT id,name,email,role,phone,photo FROM users WHERE id=$1 AND active', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'User profile not found.' });
  res.json({ ...user, permissions: req.user.permissions });
}));

app.patch('/api/me/profile', wrap(async (req, res) => {
  const { photo } = req.body;
  if (photo !== null && (typeof photo !== 'string' || photo.length > 900000 ||
      !/^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(photo))) {
    return res.status(400).json({ error: 'Choose a valid photo and try again.' });
  }
  const [user] = await q(
    'UPDATE users SET photo=$1 WHERE id=$2 AND active RETURNING id,name,email,role,phone,photo',
    [photo, req.user.id]
  );
  if (!user) return res.status(404).json({ error: 'User profile not found.' });
  res.json(user);
}));

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
