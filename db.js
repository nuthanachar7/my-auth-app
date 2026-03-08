const mysql = require('mysql2/promise');
require('dotenv').config();
const fs = require('fs');
const path = require('path');

const sslCaPath = path.isAbsolute(process.env.DB_SSL_CA)
  ? process.env.DB_SSL_CA
  : path.join(__dirname, process.env.DB_SSL_CA);

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { ca: fs.readFileSync(sslCaPath) }
});

// Log pool errors at runtime (still return 500 to client)
pool.on('error', (err) => {
  console.error('Database pool error:', err.message);
});

module.exports = pool;
