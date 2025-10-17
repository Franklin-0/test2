// db.js
const mysql = require('mysql2/promise');

// Detect environment
const isProduction = process.env.NODE_ENV === 'production';

// Configure DB connection
const dbConfig = {
  host: isProduction
    ? process.env.MYSQL_HOST || process.env.MYSQLHOST
    : process.env.DB_HOST || '127.0.0.1', // force IPv4 locally
  user: isProduction
    ? process.env.MYSQL_USER || process.env.MYSQLUSER
    : process.env.DB_USER || 'root',
  password: isProduction
    ? process.env.MYSQL_PASSWORD || process.env.MYSQLPASSWORD
    : process.env.DB_PASSWORD || '',
  database: isProduction
    ? process.env.MYSQL_DATABASE || process.env.MYSQLDATABASE
    : process.env.DB_DATABASE || 'shoe_store',
  port: isProduction
    ? process.env.MYSQL_PORT || 3306
    : process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: isProduction ? { rejectUnauthorized: false } : undefined
};

// Create a connection pool
const db = mysql.createPool(dbConfig);

// Test connection on startup
(async () => {
  try {
    const connection = await db.getConnection();
    console.log('✅ Database connected successfully!');
    connection.release();
  } catch (err) {
    console.error('❌ Failed to connect to database.');
    if (!isProduction) {
      console.error('Used connection config:', { host: dbConfig.host, port: dbConfig.port, user: dbConfig.user, database: dbConfig.database });
    }
    console.error(err);
  }
})();

module.exports = { db, dbConfig };
