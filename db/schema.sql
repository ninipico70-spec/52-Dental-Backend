-- 52-Dental Clinic schema (PostgreSQL). Run in pgAdmin Query Tool or `npm run db:init`.
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'doctor' CHECK (role IN ('admin','doctor','assistant')),
  phone TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS patients (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  gender TEXT CHECK (gender IN ('Male','Female')),
  note TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_patients_name ON patients (LOWER(name));

CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  patient_id INT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  session_date DATE NOT NULL DEFAULT CURRENT_DATE,
  cost NUMERIC(12,2) NOT NULL DEFAULT 0,
  notes TEXT,
  created_by INT REFERENCES users(id) ON DELETE SET NULL
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

CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY,
  patient_id INT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  session_id INT REFERENCES sessions(id) ON DELETE SET NULL,
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  type TEXT NOT NULL DEFAULT 'Cash',
  batch_number TEXT,
  paid_at DATE NOT NULL DEFAULT CURRENT_DATE
);

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
