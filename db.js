const mysql = require('mysql2/promise');

// Detect environment
const isProduction = process.env.NODE_ENV === 'production';

// Use Railway variables in production, local variables otherwise
const dbConfig = {
  host: isProduction 
        ? process.env.MYSQL_HOST || process.env.MYSQLHOST 
        : process.env.DB_HOST || 'localhost',
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

const db = mysql.createPool(dbConfig);

module.exports = db;
