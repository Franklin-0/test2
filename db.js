const mysql = require('mysql2/promise');

const db = mysql.createPool({
  host: process.env.MYSQLHOST || process.env.DB_HOST || 'localhost',
  user: process.env.MYSQLUSER || process.env.DB_USER || 'root',
  password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD || '',
  database: process.env.MYSQLDATABASE || process.env.DB_DATABASE || 'shoe_store',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // --- IMPORTANT: SSL Configuration for Railway ---
  ssl: {
    // Do not reject the connection for self-signed certificates
    rejectUnauthorized: false 
  }
});

module.exports = db;