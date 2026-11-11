-- 52-Dental Clinic schema (PostgreSQL). Run in pgAdmin Query Tool or `npm run db:init`.
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'doctor' CHECK (role IN ('admin','doctor','assistant','receptionist')),
  phone TEXT,
  photo TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS photo TEXT;

CREATE TABLE IF NOT EXISTS role_permissions (
  role TEXT PRIMARY KEY CHECK (role IN ('doctor','assistant','receptionist')),
  permissions JSONB NOT NULL
);
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin','doctor','assistant','receptionist'));
ALTER TABLE role_permissions DROP CONSTRAINT IF EXISTS role_permissions_role_check;
ALTER TABLE role_permissions ADD CONSTRAINT role_permissions_role_check CHECK (role IN ('doctor','assistant','receptionist'));

CREATE TABLE IF NOT EXISTS patients (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  gender TEXT CHECK (gender IN ('Male','Female')),
  note TEXT,
  telegram_chat_id TEXT,
  age INT CHECK (age IS NULL OR age BETWEEN 0 AND 150),
  address TEXT,
  medical_history TEXT,
  dental_noted BOOLEAN NOT NULL DEFAULT FALSE,
  implant_noted BOOLEAN NOT NULL DEFAULT FALSE,
  doctor_assigned INT REFERENCES users(id) ON DELETE SET NULL,
  photo TEXT,
  registration_date DATE NOT NULL DEFAULT CURRENT_DATE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
ALTER TABLE patients ADD COLUMN IF NOT EXISTS telegram_chat_id TEXT;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS age INT CHECK (age IS NULL OR age BETWEEN 0 AND 150);
ALTER TABLE patients ADD COLUMN IF NOT EXISTS address TEXT;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS medical_history TEXT;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS dental_noted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS implant_noted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS doctor_assigned INT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS photo TEXT;
ALTER TABLE patients ADD COLUMN IF NOT EXISTS registration_date DATE;
UPDATE patients SET registration_date=created_at::date WHERE registration_date IS NULL;
ALTER TABLE patients ALTER COLUMN registration_date SET DEFAULT CURRENT_DATE;
ALTER TABLE patients ALTER COLUMN registration_date SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_patients_name ON patients (LOWER(name));

CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  patient_id INT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  session_date DATE NOT NULL DEFAULT CURRENT_DATE,
  cost NUMERIC(12,2) NOT NULL DEFAULT 0,
  other_cost NUMERIC(12,2),
  notes TEXT,
  created_by INT REFERENCES users(id) ON DELETE SET NULL
);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS other_cost NUMERIC(12,2);

CREATE TABLE IF NOT EXISTS services (
  id SERIAL PRIMARY KEY,
  service_key TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT '🦷',
  duration_minutes INT NOT NULL CHECK (duration_minutes > 0),
  price NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (price >= 0),
  active BOOLEAN NOT NULL DEFAULT TRUE,
  sort_order INT NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

INSERT INTO services (service_key,name,icon,duration_minutes,price,sort_order) VALUES
  ('checkup','Checkup','🩺',30,0,1),
  ('cleaning','Cleaning','✨',45,0,2),
  ('filling','Filling','✚',60,0,3),
  ('root-canal','Root Canal','〽️',90,0,4),
  ('extraction','Extraction','✂️',45,0,5),
  ('whitening','Whitening','☀️',60,0,6),
  ('consultation','Consultation','🗨️',30,0,7),
  ('orthodontics','Orthodontics','🦷',60,0,8),
  ('orthodontic-treatment','Orthodontic Treatment','😁',60,0,9),
  ('implantology','Implantology','🦷',90,0,10),
  ('oral-surgery','Oral Surgery','🩺',60,0,11),
  ('preventive-dentistry','Preventive Dentistry','🛡️',45,0,12),
  ('screening','Screening','🔎',30,0,13),
  ('periodontics-dentistry','Periodontics Dentistry','🦷',60,0,14),
  ('aesthetics-dentistry','Aesthetics Dentistry','✨',60,0,15),
  ('endodontics-dentistry','Endodontics Dentistry','〽️',90,0,16),
  ('prosthodontics-dentistry','Prosthodontics Dentistry','🦷',60,0,17),
  ('restorative-dentistry','Restorative Dentistry','✚',60,0,18),
  ('x-ray','X-ray','🩻',20,0,19),
  ('crowns','Crowns','🦷',60,0,20),
  ('bridges','Bridges','🦷',60,0,21)
ON CONFLICT (service_key) DO NOTHING;

CREATE TABLE IF NOT EXISTS session_services (
  id SERIAL PRIMARY KEY,
  session_id INT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  service_id INT REFERENCES services(id) ON DELETE SET NULL,
  service_name TEXT NOT NULL,
  icon TEXT NOT NULL DEFAULT '🦷',
  duration_minutes INT NOT NULL CHECK (duration_minutes > 0),
  unit_price NUMERIC(12,2) NOT NULL CHECK (unit_price >= 0),
  UNIQUE (session_id, service_id)
);

CREATE TABLE IF NOT EXISTS session_teeth (
  id SERIAL PRIMARY KEY,
  session_id INT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  tooth INT NOT NULL,                       -- FDI number, e.g. 11..48
  condition TEXT NOT NULL DEFAULT 'Normal', -- Normal | Bad | Extracted | Traded
  details TEXT[] NOT NULL DEFAULT '{}',     -- Cares, Coron, Implant, RR, mobility, X-RAY, Impacted, XOP, RCT, C&C
  surfaces TEXT[] NOT NULL DEFAULT '{}',    -- top, bottom, left, right, center
  note TEXT,
  UNIQUE (session_id, tooth)
);

CREATE TABLE IF NOT EXISTS consultations (
  id SERIAL PRIMARY KEY,
  patient_id INT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  record_date DATE NOT NULL DEFAULT CURRENT_DATE,
  name_kh TEXT,
  name_en TEXT,
  sex TEXT,
  nationality TEXT,
  dob DATE,
  occupation TEXT,
  address TEXT,
  phone TEXT,
  dentition TEXT NOT NULL DEFAULT 'adult' CHECK (dentition IN ('adult','pediatric')),
  chief_complaint TEXT,
  medical_alert TEXT,
  odontogram JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by INT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_consultations_patient_date ON consultations (patient_id,record_date DESC,id DESC);

CREATE SEQUENCE IF NOT EXISTS invoice_number_seq;
CREATE TABLE IF NOT EXISTS invoices (
  id SERIAL PRIMARY KEY,
  invoice_number TEXT NOT NULL UNIQUE,
  patient_id INT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  session_id INT REFERENCES sessions(id) ON DELETE SET NULL,
  issue_date DATE NOT NULL DEFAULT CURRENT_DATE,
  due_date DATE,
  subtotal NUMERIC(12,2) NOT NULL CHECK (subtotal >= 0),
  discount NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (discount >= 0),
  total NUMERIC(12,2) NOT NULL CHECK (total > 0),
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','void')),
  voided_at TIMESTAMP,
  void_reason TEXT,
  created_by INT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  CHECK (discount <= subtotal),
  CHECK (total = subtotal - discount)
);
ALTER TABLE invoices DROP CONSTRAINT IF EXISTS invoices_session_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_invoices_open_session
  ON invoices (session_id) WHERE session_id IS NOT NULL AND status='open';
CREATE INDEX IF NOT EXISTS idx_invoices_patient_date ON invoices (patient_id, issue_date DESC);

CREATE TABLE IF NOT EXISTS invoice_items (
  id SERIAL PRIMARY KEY,
  invoice_id INT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  description TEXT NOT NULL,
  quantity NUMERIC(10,2) NOT NULL CHECK (quantity > 0),
  unit_price NUMERIC(12,2) NOT NULL CHECK (unit_price >= 0),
  line_total NUMERIC(12,2) NOT NULL CHECK (line_total >= 0)
);

CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY,
  patient_id INT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  session_id INT REFERENCES sessions(id) ON DELETE SET NULL,
  invoice_id INT REFERENCES invoices(id) ON DELETE SET NULL,
  auto_session_payment BOOLEAN NOT NULL DEFAULT FALSE,
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  type TEXT NOT NULL DEFAULT 'Cash',
  batch_number TEXT,
  paid_at DATE NOT NULL DEFAULT CURRENT_DATE
);
ALTER TABLE payments ADD COLUMN IF NOT EXISTS auto_session_payment BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE payments ADD COLUMN IF NOT EXISTS invoice_id INT REFERENCES invoices(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_auto_session
  ON payments (session_id) WHERE auto_session_payment AND session_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS invoice_refunds (
  id SERIAL PRIMARY KEY,
  invoice_id INT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  type TEXT NOT NULL DEFAULT 'Cash',
  reason TEXT NOT NULL,
  refunded_at DATE NOT NULL DEFAULT CURRENT_DATE,
  created_by INT REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS clinic_print_template (
  id INT PRIMARY KEY CHECK (id = 1),
  header_mode TEXT NOT NULL DEFAULT 'none' CHECK (header_mode IN ('none','text','image','both')),
  header_text TEXT NOT NULL DEFAULT '',
  header_image TEXT,
  footer_mode TEXT NOT NULL DEFAULT 'none' CHECK (footer_mode IN ('none','text','image','both')),
  footer_text TEXT NOT NULL DEFAULT '',
  footer_image TEXT,
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
INSERT INTO clinic_print_template (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS expenses (
  id SERIAL PRIMARY KEY,
  title TEXT NOT NULL,
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  spent_at DATE NOT NULL DEFAULT CURRENT_DATE,
  note TEXT
);

CREATE TABLE IF NOT EXISTS appointments (
  id SERIAL PRIMARY KEY,
  patient_id INT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  appt_at TIMESTAMP NOT NULL,
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled','done','cancelled'))
);
CREATE INDEX IF NOT EXISTS idx_appt_at ON appointments (appt_at);
