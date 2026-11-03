require('dotenv').config();
const { Pool, types } = require('pg');
const databaseUrl = process.env.DATABASE_URL;

types.setTypeParser(1082, value => value);

module.exports = new Pool(databaseUrl
  ? {
      connectionString: databaseUrl,
      ssl: { rejectUnauthorized: false },
    }
  : {
      host: process.env.DB_HOST, port: +process.env.DB_PORT || 5432,
      database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    });
