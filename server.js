const dotenvResult = require('dotenv').config();
if (dotenvResult.error && dotenvResult.error.code !== 'ENOENT') {
  console.error('FATAL: Error parsing .env file', dotenvResult.error);
  process.exit(1);
}
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { Resend } = require('resend');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const axios = require('axios');
const mpesaRoutes = require('./routes/mpesa'); 
const logger = require('./logger');


// --- Express App Initialization ---
const app = express();
const PORT = process.env.PORT || 1000;

// --- Environment Setup ---
const isProduction = process.env.NODE_ENV === 'production';
const FRONTEND_URL = isProduction ? process.env.FRONTEND_URL_PROD : process.env.FRONTEND_URL_DEV;
const GOOGLE_CALLBACK_URL = isProduction ? process.env.GOOGLE_CALLBACK_URL_PROD : process.env.GOOGLE_CALLBACK_URL_DEV;

// --- Resend Initialization ---
if (!process.env.RESEND_API_KEY) {
  console.error('FATAL: RESEND_API_KEY is not defined in your .env file.');
  console.error('The server cannot start without a Resend API key.');
  process.exit(1); // Exit the process with an error code
}
const resend = new Resend(process.env.RESEND_API_KEY);

// --- Middleware Setup ---
// CORS (Cross-Origin Resource Sharing) configuration
const allowedOrigins = [
  process.env.FRONTEND_URL_PROD,
  process.env.FRONTEND_URL_DEV,
  process.env.FRONTEND_URL_DEV2,
  'https://testfront2.onrender.com',
  'http://localhost:3000',
  'http://localhost:5501' 
].filter(Boolean); // Remove undefined values

const corsOptions = {
  origin: function (origin, callback) {
    console.log("🌍 Incoming request origin:", origin);

    if (!origin || allowedOrigins.some(o => origin.startsWith(o))) {
      callback(null, true);
    } else {
      console.error("❌ Blocked by CORS:", origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
};

app.use(cors(corsOptions));

// --- M-Pesa Callback Route ---

const safaricomIpCheck = (req, res, next) => {
  const allowedIps = [
    '196.201.214.200', '196.201.214.206', '196.201.213.114',//need to check after going live
    '196.201.212.127', '196.201.212.138', '196.201.212.129',
    '196.201.212.136', '196.201.213.44', '196.201.213.50',
    '196.201.214.208'
  ];

  let requestIp = req.ip || req.connection.remoteAddress;
  if (requestIp && requestIp.startsWith('::ffff:')) {
    requestIp = requestIp.substring(7);
  }


  if (process.env.MPESA_ENV === 'production' && !allowedIps.includes(requestIp)) {
    logger.warn(`🚫 Denied callback request from untrusted IP: ${requestIp}`);
    return res.status(403).json({ error: 'Forbidden' });
  }

  next();
};

app.post("/api/mpesa/stk-callback", express.json(), safaricomIpCheck, async (req, res) => {
  logger.info("📩 M-Pesa Callback Received in server.js", { body: req.body });

  const callbackData = req.body?.Body?.stkCallback;

  if (!callbackData) {
    logger.error('Invalid M-Pesa callback format received.', { body: req.body });
    return res.status(200).json({ ResultCode: 1, ResultDesc: 'Failed' });
  }

  const checkoutRequestID = callbackData.CheckoutRequestID;
  const resultCode = callbackData.ResultCode;

  if (resultCode !== 0) {
    logger.error(`❌ Payment failed for ${checkoutRequestID}.`, { checkoutRequestID, resultCode, reason: callbackData.ResultDesc });
    const failureReason = callbackData.ResultDesc || 'Payment failed or was cancelled by user.';
    await db.query(
      'UPDATE orders SET status = ?, failure_reason = ? WHERE mpesa_checkout_id = ?',
      ['failed', failureReason, checkoutRequestID]
    );
    return res.status(200).json({ ResultCode: 0, ResultDesc: 'Accepted' });
  }

  logger.info(`🎉 Payment successful for ${checkoutRequestID}`, { checkoutRequestID });
  const metadata = callbackData.CallbackMetadata.Item;
  const parsedMeta = {};
  metadata.forEach(item => {
    parsedMeta[item.Name] = item.Value;
  });

  const mpesaReceipt = parsedMeta.MpesaReceiptNumber;
  const amountPaid = parsedMeta.Amount;

  let connection;
  try {
    connection = await db.getConnection();
    await connection.beginTransaction();

    const [[order]] = await connection.query(
      'SELECT * FROM orders WHERE mpesa_checkout_id = ? AND status = ?',
      [checkoutRequestID, 'pending']
    );

    if (!order) {
      logger.warn(`⚠️ Order with CheckoutID ${checkoutRequestID} not found or not pending. No action taken.`, { checkoutRequestID });
      await connection.commit();
      return res.status(200).json({ ResultCode: 0, ResultDesc: "Accepted" });
    }

    if (parseInt(amountPaid, 10) < order.amount) {
      logger.error(`❌ Payment amount mismatch for order ${order.id}.`, { orderId: order.id, expected: order.amount, paid: amountPaid });
      await connection.query('UPDATE orders SET status = ? WHERE id = ?', ['payment_mismatch', order.id]);
      await connection.commit();
      return res.status(200).json({ ResultCode: 0, ResultDesc: "Accepted" });
    }

    await connection.query(
      'UPDATE orders SET status = ?, mpesa_receipt = ?, amount_paid = ? WHERE mpesa_checkout_id = ? AND status = ?',
      ['paid', mpesaReceipt, amountPaid, checkoutRequestID, 'pending']
    );
    logger.info(`✅ Order ${order.id} updated to 'paid'.`, { orderId: order.id, receipt: mpesaReceipt });

    if (order.user_id) {
      await connection.query('DELETE FROM cart_items WHERE user_id = ?', [order.user_id]);
      logger.info(`🛒 Cart cleared for user ${order.user_id}.`, { userId: order.user_id });
    }

    await connection.commit();
    // TODO: Send a confirmation email here.

  } catch (dbError) {
    logger.error('DATABASE TRANSACTION ERROR during M-Pesa callback processing:', { checkoutRequestID, error: dbError.message });
    if (connection) await connection.rollback();
  } finally {
    if (connection) connection.release();
  }

  res.status(200).json({ ResultCode: 0, ResultDesc: "Accepted" });
});


// --- General Middleware ---
app.use(express.json());
app.use(bodyParser.json()); 

// --- Database Connection ---
const { db, dbConfig } = require('./db');

// --- Session Setup ---
if (isProduction) {
  app.set('trust proxy', 1); // trust first proxy
}

const sessionStore = new MySQLStore(dbConfig);

app.use(session({
  secret: process.env.SESSION_SECRET || 'a_very_long_and_super_random_secret_string_!@#$_for_security',
  resave: false,
  saveUninitialized: false, 
  cookie: { 
    secure: isProduction, 
    httpOnly: true, // Prevents client-side JS from accessing the cookie
    sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-domain requests in prod, 'lax' for dev
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  },
  store: sessionStore,
}));

// --- Passport Setup ---
app.use(passport.initialize());
app.use(passport.session());

// --- Passport Google Strategy ---
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {

    const { id, displayName, emails, } = profile;
    const email = emails[0].value;

    try {
      // Check if a user already exists with this Google ID or email address.
      const [rows] = await db.query('SELECT * FROM users WHERE google_id = ? OR email = ?', [id, email]);

      if (rows.length > 0) {
        // User exists, log them in.
        const user = rows[0];
        user.isNewUser = false; 
        if (!user.google_id) {
          await db.query('UPDATE users SET google_id = ? WHERE id = ?', [id, user.id]);
        }

        return done(null, user);
      } else {
        const newUser = {
          google_id: id,
          email,
          name: displayName,
        };
        const [result] = await db.query('INSERT INTO users SET ?', newUser);
        newUser.id = result.insertId;

        // Send a welcome email to the new user
        const subject = 'Welcome to Fashionable Baby Shoes!';
        const html = `<h1>Welcome, ${displayName}!</h1><p>Thank you for signing up with Google. We're excited to have you with us. Happy shopping!</p>`;
        sendEmail(email, subject, html).catch(console.error);

        newUser.isNewUser = true; // Mark as a new user
        return done(null, newUser); // Passport proceeds with the newly created user object
      }
    } catch (err) {
      return done(err, null); 
    }
  }
));

// --- Passport Serialization/Deserialization ---
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const [[user]] = await db.query('SELECT * FROM users WHERE id = ?', [id]); // Find user by ID
    done(null, user); 
  } catch (err) {
    done(err, null);
  }
});

/**
 * Sends an email using the configured Nodemailer transporter.
 * @param {string} to - The recipient's email address.
 * @param {string} subject - The subject of the email.
 * @param {string} html - The HTML body of the email.
 */
async function sendEmail(to, subject, html) {
  try {
    const { data, error } = await resend.emails.send({
      // IMPORTANT: You must use a verified domain with Resend.
      // The 'onboarding@resend.dev' is for testing only.                     
      // Replace with your own, e.g., 'noreply@yourdomain.com'
      from: 'Fashionable Baby Shoes <onboarding@resend.dev>',
      to: [to], // Resend expects an array of recipients
      subject: subject,
      html: html,
    });

    if (error) {
      // If Resend returns an error, log it and re-throw it.
      logger.error(`Failed to send email to ${to}. Subject: "${subject}".`, { error });
      throw error;
    }

    logger.info(`Email sent successfully to ${to}`, { emailId: data.id });
    return data;
  } catch (e) {
    logger.error(`Exception caught while sending email to ${to}.`, { error: e.message });
    throw e; // Re-throw to let the caller handle it.
  }
}

// --- API Routes ---
// GET /api/products - Fetches all products from the database.
app.get('/api/products', async (req, res) => {
  try {
    const [products] = await db.query(`
      SELECT 
        p.*, 
        GROUP_CONCAT(ps.size ORDER BY ps.size) AS sizes
      FROM product p
      LEFT JOIN product_size ps ON p.id = ps.product_id
      GROUP BY p.id
    `);
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/products/:id 
app.get('/api/products/:id', async (req, res) => {
  try {
    const productId = req.params.id;
    const [[product]] = await db.query(`
      SELECT 
        p.*, 
        GROUP_CONCAT(ps.size ORDER BY ps.size) AS sizes
      FROM product p
      LEFT JOIN product_size ps ON p.id = ps.product_id
      WHERE p.id = ?
      GROUP BY p.id
    `, [productId]);
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/register - Handles new user registration.
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  console.log("📩 Incoming /api/register request body:", req.body);

  // --- Backend Validation ---
  if (!email || !password || !name) {
    console.warn("⚠️ Validation failed: Missing fields");
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  // Validate email format
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    console.warn("⚠️ Validation failed: Invalid email format", email);
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  // Validate password length
  if (password.length < 8) {
    console.warn("⚠️ Validation failed: Password too short");
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  // Validate password complexity (matching frontend)
  if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password)) {
    console.warn("⚠️ Validation failed: Password missing complexity");
    return res.status(400).json({ error: 'Password must contain an uppercase letter, a lowercase letter, and a number.' });
  }

  try {
    // Hash the password before storing it for security. 10 is the salt round count.
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user into the database.
    const [result] = await db.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    console.log("✅ User registered successfully:", { userId: result.insertId, email });

    // Send a welcome email (async, don’t block response)
    const subject = 'Welcome to Fashionable Baby Shoes!';
    const html = `<h1>Welcome, ${name || 'friend'}!</h1><p>Thank you for signing up. We're excited to have you with us. Happy shopping!</p>`;
    sendEmail(email, subject, html).catch(err => {
      console.error("📧 Failed to send welcome email:", err);
    });

    res.status(201).json({ success: true, userId: result.insertId });
  } catch (err) {
    console.error("❌ Registration failed:", err);

    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Email already exists' });
    }

    res.status(500).json({ error: 'Server error during registration', details: err.message });
  }
});


// POST /api/login 
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {    
    // Find a user with the given email who registered via email (has a password).
    const [[user]] = await db.query('SELECT * FROM users WHERE email = ? AND password IS NOT NULL', [email]);
    // If no user is found or they signed up with Google (no password), deny access.
    if (!user || !user.password) return res.status(401).json({ error: 'Invalid credentials' });

    // Compare the provided password with the hashed password in the database.
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    req.login(user, (err) => {
      if (err) {
        return res.status(500).json({ error: 'Could not log in user.' });
      }
      // Upon successful login, merge the guest cart (if any) into the database.
      mergeCartsOnLogin(req.session, user.id)
        .then(() => {
          console.log(`User ${user.id} logged in. Carts merged.`);
          // Send a "welcome back" email
          const subject = 'Welcome Back!';
          const html = `<h1>Welcome back, ${user.name || 'friend'}!</h1><p>We're glad to see you again. Check out our latest arrivals!</p>`;
          sendEmail(user.email, subject, html).catch(console.error);

          res.json({ success: true, message: 'Login successful', user: { name: user.name } });
        })
        .catch(mergeErr => {
          console.error("Cart merge failed on login:", mergeErr);
          res.status(500).json({ error: 'Login successful, but failed to merge cart.' });
        });

    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/forgot-password - Initiates the password reset process.
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const [[user]] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      return res.json({ success: true, message: 'If a user with that email exists, a reset link has been sent.' });
    }
    const token = crypto.randomBytes(32).toString('hex'); 
    const expires = Date.now() + 3600000; // Token expires in 1 hour 
    // Store the token and its expiration date in the database for the user.
    await db.query('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?', [token, expires, user.id]);
    const resetUrl = `${FRONTEND_URL}/Frontend-babyshoe/reset-password.html?token=${token}`;
    const subject = 'Password Reset Request';
    const html = `<p>You requested a password reset. Click the link below to reset your password:</p><a href="${resetUrl}">${resetUrl}</a><p>This link will expire in one hour.</p>`;

    await sendEmail(user.email, subject, html);
    res.json({ success: true, message: 'If a user with that email exists, a reset link has been sent.' });

  } catch (err) {
    console.error("FORGOT PASSWORD ERROR:", err);
    res.status(500).json({ error: 'Failed to send reset email.', details: err.message });
  }
});

// POST /api/reset-password - Completes the password reset process.
app.post('/api/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).json({ error: 'Token and new password are required.' });
  }

  try {    
    // Find a user with a matching token that has not expired.
    const [[user]] = await db.query('SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?', [token, Date.now()]);
    if (!user) return res.status(400).json({ error: 'Password reset token is invalid or has expired.' });

    // Hash the new password.
    const hashedPassword = await bcrypt.hash(password, 10);
    // Update the user's password and clear the reset token fields.
    await db.query('UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?', [hashedPassword, user.id]);

    res.json({ success: true, message: 'Password has been updated successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Cart API Routes (Session-based) ---

/**
 * Middleware to ensure the user is authenticated before accessing cart routes.
 */
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: 'You must be logged in to perform this action.' });
};

/**
 * Initializes the cart in the session if it doesn't exist.
 */
const initializeCart = (req, res, next) => {
  if (!req.session.cart) {
    req.session.cart = [];
  }
  next();
};

// Apply middleware to all /api/cart routes
app.use('/api/cart', initializeCart);

/**
 * GET /api/cart - Fetches the user's cart from the session.
 */
app.get('/api/cart', (req, res) => {
  // If user is not logged in, return the session cart for guests
  if (!req.isAuthenticated()) {
    return res.json(req.session.cart || []);
  }

  // If user is logged in, fetch the cart from the database
  const userId = req.user.id;
  db.query(`
    SELECT 
      ci.product_id AS productId, 
      ci.size, 
      ci.quantity, 
      p.name, 
      p.price, 
      p.image_url AS image,
      CONCAT(ci.product_id, '-', ci.size) AS id
    FROM cart_items ci
    JOIN product p ON ci.product_id = p.id
    WHERE ci.user_id = ?
  `, [userId])
  .then(([cartItems]) => {
    req.session.cart = cartItems; // Keep session in sync
    res.json(cartItems);
  })
  .catch(error => {
    console.error('Error fetching DB cart:', error);
    res.status(500).json({ error: 'Could not retrieve cart.' });
  });
});


/**
 * POST /api/cart - Adds an item to the cart.
 */
app.post('/api/cart', async (req, res) => {
  const { productId, size, quantity } = req.body;

  // --- Server-side Validation ---
  if (!productId || !size || !quantity || quantity < 1) {
    return res.status(400).json({ error: 'Product ID, size, and a valid quantity are required.' });
  }

  try {
    // 1. Verify the product exists and get its real price from the DB.
    const [[product]] = await db.query('SELECT * FROM product WHERE id = ?', [productId]);
    if (!product) {
      return res.status(404).json({ error: 'Product not found.' });
    }

    // If user is logged in, add/update the item in the database
    if (req.isAuthenticated()) {
      const userId = req.user.id;

      // Check if the exact item (product + size) already exists for the user
      const [[existingItem]] = await db.query(
        'SELECT * FROM cart_items WHERE user_id = ? AND product_id = ? AND size = ?',
        [userId, productId, size]
      );

      if (existingItem) {
        // If it exists, update the quantity
        await db.query('UPDATE cart_items SET quantity = quantity + ? WHERE id = ?', [quantity, existingItem.id]);
      } else {
        // If not, insert a new row
        await db.query('INSERT INTO cart_items (user_id, product_id, size, quantity, price) VALUES (?, ?, ?, ?, ?)', [userId, productId, size, quantity, product.price]);
      }

      // Fetch the entire updated cart to send back to the client
      const [updatedCart] = await db.query(`
        SELECT ci.product_id AS productId, ci.size, ci.quantity, p.name, p.price, p.image_url AS image, CONCAT(ci.product_id, '-', ci.size) AS id
        FROM cart_items ci JOIN product p ON ci.product_id = p.id WHERE ci.user_id = ?
      `, [userId]);
      
      req.session.cart = updatedCart; // Sync session
      return res.status(200).json(updatedCart);
    }

    // --- Logic for Guest Users (not logged in) ---
    const cartItemId = `${product.id}-${size}`;
    const existingItem = req.session.cart.find(item => item.id === cartItemId);

    if (existingItem) {
      existingItem.quantity += parseInt(quantity, 10);// If item already exists, just update its quantity.
    } else {
      // If it's a new item, add it to the cart.
      req.session.cart.push({
        id: cartItemId, // Use the composite ID
        productId: product.id,
        name: product.name,
        price: product.price, // Use the price from the database, not the client.
        size: size, // The specific size for this item
        quantity: quantity,
        image: product.image_url
      });
    }
    
    res.status(200).json(req.session.cart);
  } catch (error) {
    console.error('Error adding to cart:', error);
    res.status(500).json({ error: 'Could not add item to cart.' });
  }
});

/**
 * PUT /api/cart - Updates an item's quantity in the cart.
 */
app.put('/api/cart', async (req, res) => {
  const { cartItemId, quantity } = req.body;
  if (!cartItemId || !quantity || quantity < 1) {
    return res.status(400).json({ error: 'Cart item ID and a valid quantity are required.' });
  }

  // Ensure quantity is an integer
  const parsedQuantity = parseInt(quantity, 10);
  if (isNaN(parsedQuantity) || parsedQuantity < 1) {
    return res.status(400).json({ error: 'Invalid quantity provided.' });
  }

  // If user is logged in, update the database
  if (req.isAuthenticated()) {
    const [productId, size] = cartItemId.split('-');
    try {
      await db.query(
        'UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ? AND size = ?',
        [parsedQuantity, req.user.id, productId, size]
      );
      // Fetch and return the updated cart
      const [updatedCart] = await db.query(`
        SELECT ci.product_id AS productId, ci.size, ci.quantity, p.name, p.price, p.image_url AS image, CONCAT(ci.product_id, '-', ci.size) AS id
        FROM cart_items ci JOIN product p ON ci.product_id = p.id WHERE ci.user_id = ?
      `, [req.user.id]);
      req.session.cart = updatedCart;
      return res.status(200).json(updatedCart);
    } catch (error) {
      console.error('Error updating DB cart:', error);
      return res.status(500).json({ error: 'Could not update cart.' });
    }
  }

  // --- Logic for Guest Users ---
  const itemToUpdate = req.session.cart.find(item => item.id === cartItemId);
  if (itemToUpdate) {
    itemToUpdate.quantity = parsedQuantity;
    res.status(200).json(req.session.cart);
  } else {
    res.status(404).json({ error: 'Item not found in cart.' });
  }
});

/**
 * DELETE /api/cart - Removes an item from the cart or clears the whole cart.
 */
app.delete('/api/cart', async (req, res) => {
  // Safely check for cartItemId, even if req.body is undefined.
  const cartItemId = req.body ? req.body.cartItemId : null;

  if (cartItemId) {
    // If logged in, delete the specific item from the database
    if (req.isAuthenticated()) {
      const [productId, size] = cartItemId.split('-');
      await db.query('DELETE FROM cart_items WHERE user_id = ? AND product_id = ? AND size = ?', [req.user.id, productId, size]);
    }
    // Also remove from session (for guests or to keep sync)
    req.session.cart = req.session.cart.filter(item => item.id !== cartItemId);
  } else {
    // If no cartItemId, clear the entire cart.
    // If logged in, clear their entire cart from the database
    if (req.isAuthenticated()) {
      await db.query('DELETE FROM cart_items WHERE user_id = ?', [req.user.id]);
    }
    // Also clear session cart
    req.session.cart = [];
  }
  res.status(200).json(req.session.cart);
});

/**
 * GET /api/cart/count - Fetches the total number of items in the cart.
 */
app.get('/api/cart/count', async (req, res) => {
  // If logged in, get the count from the database for accuracy
  if (req.isAuthenticated()) {
    try {
      const [[{ count }]] = await db.query('SELECT SUM(quantity) as count FROM cart_items WHERE user_id = ?', [req.user.id]);
      return res.json({ count: count || 0 });
    } catch (error) {
      console.error("Error getting DB cart count:", error);
      return res.json({ count: 0 });
    }
  }

  // --- Logic for Guest Users ---
  // The total count is the sum of quantities of all items in the cart
  const guestCart = req.session.cart || []; // Ensure we have an array
  const totalItems = guestCart.reduce((sum, item) => sum + (item.quantity || 0), 0);
  res.json({ count: totalItems });
});

/**
 * POST /api/cart/merge - Merges a guest cart into a logged-in user's DB cart.
 */
app.post('/api/cart/merge', async (req, res) => {
  const localCart = req.body.cart;

  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'User must be logged in to merge carts.' });
  }
  if (!Array.isArray(localCart)) {
    return res.status(400).json({ error: 'Invalid cart format.' });
  }

  const userId = req.user.id;
  if (localCart.length === 0) {
    return res.status(200).json({ message: 'No local cart to merge.' });
  }

  // Create a promise for each item to be inserted/updated in the database
  const mergePromises = localCart.map(item => {
    const [productId, size] = item.id.split('-');
    const sql = `
      INSERT INTO cart_items (user_id, product_id, size, quantity, price)
      VALUES (?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)
    `;
    return db.query(sql, [userId, productId, size, item.quantity, item.price]);
  });

  try {
    await Promise.all(mergePromises);
    res.status(200).json({ success: true, message: 'Cart merged successfully.' });
  } catch (error) {
    console.error('Error merging cart into DB:', error);
    res.status(500).json({ error: 'Could not merge cart.' });
  }
});

// --- M-Pesa Routes ---
app.use('/api/mpesa', mpesaRoutes);

// --- Favourites API Routes ---
app.get('/api/favourites', ensureAuthenticated, async (req, res) => {
  try {
    const [favourites] = await db.query(
      `SELECT p.* FROM product p JOIN favourites f ON p.id = f.product_id WHERE f.user_id = ?`,
      [req.user.id]
    );
    res.json(favourites);
  } catch (error) {
    console.error('Error fetching favourites:', error);
    res.status(500).json({ error: 'Could not retrieve favourites.' });
  }
});

/**
 * POST /api/favourites - Adds a product to the user's favourites.
 */
app.post('/api/favourites', ensureAuthenticated, async (req, res) => {
  const { productId } = req.body;
  if (!productId) {
    return res.status(400).json({ error: 'Product ID is required.' });
  }

  try {
    await db.query('INSERT INTO favourites (user_id, product_id) VALUES (?, ?)', [req.user.id, productId]);
    res.status(201).json({ success: true, message: 'Product added to favourites.' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      // It's already a favourite, which is not an error for the user.
      return res.status(200).json({ success: true, message: 'Product is already in favourites.' });
    }
    console.error('Error adding to favourites:', error);
    res.status(500).json({ error: 'Could not add product to favourites.' });
  }
});

/**
 * POST /api/favourites/merge - Merges an array of product IDs into the user's favourites.
 */
app.post('/api/favourites/merge', ensureAuthenticated, async (req, res) => {
  const { productIds } = req.body;

  if (!Array.isArray(productIds) || productIds.length === 0) {
    return res.status(400).json({ error: 'An array of product IDs is required.' });
  }

  try {
    // Prepare values for a bulk insert, e.g., [[userId, productId1], [userId, productId2]]
    const values = productIds.map(id => [req.user.id, id]);

    // Use 'INSERT IGNORE' to prevent errors for duplicate entries.
    // It will simply skip inserting rows that would cause a duplicate key error (user_id, product_id).
    await db.query('INSERT IGNORE INTO favourites (user_id, product_id) VALUES ?', [values]);

    res.status(200).json({ success: true, message: 'Local favourites merged successfully.' });
  } catch (error) {
    console.error('Error merging favourites:', error);
    res.status(500).json({ error: 'Could not merge favourites.' });
  }
});

/**
 * DELETE /api/favourites/:productId - Removes a product from the user's favourites.
 */
app.delete('/api/favourites/:productId', ensureAuthenticated, async (req, res) => {
  const { productId } = req.params;
  if (!productId) {
    return res.status(400).json({ error: 'Product ID is required.' });
  }

  try {
    await db.query('DELETE FROM favourites WHERE user_id = ? AND product_id = ?', [req.user.id, productId]);
    res.status(200).json({ success: true, message: 'Product removed from favourites.' });
  } catch (error) {
    console.error('Error removing from favourites:', error);
    res.status(500).json({ error: 'Could not remove product from favourites.' });
  }
});

/**
 * Merges the guest cart from the session with the user's database cart upon login.
 * @param {object} session - The user's session object.
 * @param {number} userId - The ID of the user.
 */
async function mergeCartsOnLogin(session, userId) {
  const guestCart = session.cart;
  if (!guestCart || guestCart.length === 0) {
    return; 
  }

  console.log(`Merging ${guestCart.length} guest cart items for user ${userId}.`);

  const mergePromises = guestCart.map(item => {
    const [productId, size] = item.id.split('-');
    const sql = `
      INSERT INTO cart_items (user_id, product_id, size, quantity, price)
      VALUES (?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)
    `;
    return db.query(sql, [userId, productId, size, item.quantity, item.price]);
  });

  await Promise.all(mergePromises);
  // After merging, the guest cart in the session is no longer needed.
  session.cart = [];
}


// --- Google Auth Routes ---
app.get('/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// GET /auth/google/callback - The route Google redirects to after the user authenticates.
app.get(
  '/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/login.html` }),
  async (req, res) => {
    try {
      const user = req.user;
      const name = user.name || 'User';
      const isNewUser = user.isNewUser || false;

      // Merge guest cart if needed
      await mergeCartsOnLogin(req.session, user.id);
      console.log(`Cart merged for Google user ${user.id}`);

      // Redirect to the correct frontend callback page path
      res.redirect(`${FRONTEND_URL}/Frontend-babyshoe/auth-callback.html?name=${encodeURIComponent(name)}&isNewUser=${isNewUser}`);
    } catch (err) {
      console.error("Google login cart merge failed:", err);
      res.redirect(`${FRONTEND_URL}/login.html`);
    }
  }
);


// --- Logout Route ---
// POST /api/logout - Logs the user out.
app.post('/api/logout', (req, res, next) => {
  req.logout(function(err) { // Passport's logout function.
    if (err) { 
      return next(err); // Pass errors to the error handler
    }
    req.session.destroy((err) => {
      if (err) console.error("Error destroying session:", err); // Log if session destruction fails
      res.clearCookie('connect.sid'); // Tell the browser to clear the session cookie
      res.json({ success: true, message: "You have been logged out." });
    });
  });
});


// --- Check Authentication Status Route ---
app.get('/api/auth/status', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      isLoggedIn: true,
      user: { email: req.user.email, name: req.user.name }
    });
  } else {
    res.json({ isLoggedIn: false });
  }
});

/**
 * Normalizes a Kenyan phone number to the MSISDN format (254...).
 * Handles formats like 07..., 7..., +254...
 * @param {string} phone - The phone number to normalize.
 * @returns {string|null} The normalized phone number or null if the format is invalid.
 */
function normalizePhone(phone) {
  if (!phone || typeof phone !== 'string') return null;

  let msisdn = phone.trim().replace(/\s+/g, ''); // Remove spaces

  if (msisdn.startsWith('+')) {
    msisdn = msisdn.substring(1); // Remove +
  }
  if (msisdn.startsWith('07')) {
    msisdn = '254' + msisdn.substring(1); // Replace 07 with 2547
  }
  if (msisdn.startsWith('7')) {
    // Handle cases where it's just 7... without the 0
    msisdn = '254' + msisdn;
  }

  return /^2547\d{8}$/.test(msisdn) ? msisdn : null;
}

// --- Server Startup ---
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
