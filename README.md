# 52-Dental Clinic Backend

The API uses Express and PostgreSQL. Configure the database and admin account
with environment variables before starting the service:

- `CORS_ORIGIN` for the deployed frontend origin(s), separated by commas.
  `http://localhost:5173` is also allowed for local development.
- `DATABASE_URL` for the PostgreSQL connection, or `DB_HOST`, `DB_PORT`,
  `DB_NAME`, `DB_USER`, and `DB_PASSWORD` for individual connection settings.
- `JWT_SECRET` for signing login tokens.
- `ADMIN_NAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` to create the initial
  administrator account.

Run `npm install` and then `npm start`. At startup, the API creates any missing
tables from `db/schema.sql`. If both admin variables are set, it creates the
admin account only when that email does not already exist. Existing passwords
are not changed. To intentionally reset the configured admin password, run
`npm run seed`.

The schema seeds the initial dental services if they are missing. Admins can
edit the service catalog from the Services page; treatment selections and
price snapshots are saved with each patient session.

Admins can configure Doctor, Assistant, and Receptionist role defaults in User
Management. Permissions cover supported view, create, edit, and delete
actions for each feature and are checked by the API on every request. Admin
accounts always retain full access. Some workflows require related grants (for
example, creating an appointment requires patient view, and creating a session
requires session edit to complete the record). The database preserves
configured role defaults when the service restarts.

The Billing & Invoices page creates invoices manually or from a saved session.
Invoice records include itemized totals, discounts, due dates, partial payments,
refunds, and void history. Saving a session does not record a payment; record
payments on the invoice. Existing automatic session payments remain in the
history and are linked to an invoice when one is created for that session.
