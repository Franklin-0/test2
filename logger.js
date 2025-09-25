const winston = require('winston');

// Define log format
const logFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
  let msg = `${timestamp} [${level}] : ${message} `;
  if (Object.keys(metadata).length > 0) {
    // Only stringify metadata if it's not empty
    msg += JSON.stringify(metadata);
  }
  return msg;
});

const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.timestamp(),
    logFormat
  ),
  transports: [
    new winston.transports.Console(),
    // In production, you would add file transports:
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/mpesa.log', level: 'info' }),
    // new winston.transports.File({ filename: 'combined.log' })
  ],
  exceptionHandlers: [
    // Log unhandled exceptions to a file
    new winston.transports.File({ filename: 'exceptions.log' })
  ],
  rejectionHandlers: [
    // Log unhandled promise rejections
    new winston.transports.File({ filename: 'rejections.log' })
  ]
});

module.exports = logger;