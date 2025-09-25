// --- Module Imports ---
const express = require('express');
const mysql = require('mysql2/promise'); 
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const axios = require('axios'); // For making HTTP requests to Safaricom API

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

// --- Express App Initialization ---
const app = express();
const PORT = 3000;

// --- Environment Setup ---
const isProduction = process.env.NODE_ENV === 'production';
const FRONTEND_URL = isProduction ? process.env.FRONTEND_URL_PROD : process.env.FRONTEND_URL_DEV;
const GOOGLE_CALLBACK_URL = isProduction ? process.env.GOOGLE_CALLBACK_URL_PROD : process.env.GOOGLE_CALLBACK_URL_DEV;

// --- Middleware Setup ---
// CORS (Cross-Origin Resource Sharing) middleware to allow requests from the frontend

const allowedOrigins = [
  FRONTEND_URL, // This uses the URL from your .env file (e.g., http://127.0.0.1:5501)
  'http://localhost:5501', // Also allow the localhost variant for flexibility
  
  process.env.FRONTEND_URL_PROD // This is for your future production deployment
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // allow Postman / curl
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Not allowed by CORS: " + origin));
  },
  credentials: true
}));





app.use(bodyParser.json()); // Middleware to parse incoming request bodies in JSON format

// --- Session Setup ---
// In production, ensure you're running behind a proxy (like Nginx) that handles HTTPS.
// 'trust proxy' allows Express to trust the X-Forwarded-Proto header.
if (isProduction) {
  app.set('trust proxy', 1); // trust first proxy
}
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false, // More secure default, saves session only when modified
  cookie: { 
    secure: isProduction, // Use secure cookies in production (requires HTTPS)
    httpOnly: true, // Prevents client-side JS from accessing the cookie
    sameSite: isProduction ? 'none' : 'lax', // 'none' for cross-domain requests in prod, 'lax' for dev
    maxAge: 24 * 60 * 60 * 1000 // e.g., 24 hours
  }
}));

// --- Passport Setup ---
app.use(passport.initialize());
app.use(passport.session());
// --- Database Connection Pool ---
const db = mysql.createPool({ 
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});


// --- Passport Google Strategy ---
// This configures how Passport authenticates users with their Google accounts.
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    // This is the URL Google will redirect to after the user grants permission.
    callbackURL: GOOGLE_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    // This function is called after the user successfully authenticates with Google.
    // We need to find or create a user in our database.
    const { id, displayName, emails, photos } = profile;
    const email = emails[0].value;
    const profilePicture = photos[0].value;

    try {
      // Check if a user already exists with this Google ID or email address.
      const [rows] = await db.query('SELECT * FROM users WHERE google_id = ? OR email = ?', [id, email]);

      if (rows.length > 0) {
        // User exists, log them in.
        const user = rows[0];
        user.isNewUser = false; // Mark as an existing user
        // If they signed up with email first, link their Google ID to their existing account.
        if (!user.google_id) {
          await db.query('UPDATE users SET google_id = ? WHERE id = ?', [id, user.id]);
        }

        return done(null, user); // Passport proceeds with the user object
      } else {
        // New user, create a new account for them in the database.
        const newUser = {
          google_id: id,
          email,
          name: displayName,
          profile_picture: profilePicture
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
      return done(err, null); // An error occurred, pass it to Passport
    }
  }
));

// --- Passport Serialization/Deserialization ---
// Determines what user data should be stored in the session. Here, we only store the user's ID.
passport.serializeUser((user, done) => done(null, user.id));

// Retrieves the full user object from the database based on the ID stored in the session.
passport.deserializeUser(async (id, done) => {
  try {
    const [[user]] = await db.query('SELECT * FROM users WHERE id = ?', [id]); // Find user by ID
    done(null, user); // Provide the full user object to Passport
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
  // This function encapsulates the logic for sending an email using Nodemailer.
  try {
    let transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: parseInt(process.env.MAIL_PORT, 10),
      secure: process.env.MAIL_SECURE === 'true',
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
      tls: {
        // Do not fail on invalid certs
        rejectUnauthorized: false
      },
    });

    // --- Debugging Step: Verify transporter configuration ---
    // This will check if the host, port, and auth credentials are correct.
    // If it fails, it will throw an error immediately.
    try {
      await transporter.verify();
    } catch (verifyErr) {
      console.error('Mailer configuration error:', verifyErr);
      throw verifyErr; // Stop the process if mailer config is bad
    }

    await transporter.sendMail({
      from: '"Fashionable Baby Shoes" <noreply@fashionablebabyshoes.com>',
      to,
      subject,
      html,
    });
    console.log(`Email sent successfully to ${to}`);
  } catch (err) {
    // Re-throw the error so the calling function knows something went wrong.
    console.error(`Failed to send email to ${to}. Subject: "${subject}". Error:`, err);
    throw err;
  }
}

// --- API Routes ---

// Test route
app.get('/', (req, res) => {
  res.send('Backend is running');
});

// GET /api/products - Fetches all products from the database.
app.get('/api/products', async (req, res) => {
  try {
    // Join products with their available sizes from the new product_size table
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

// GET /api/products/:id - Fetches a single product by its unique ID.
app.get('/api/products/:id', async (req, res) => {
  try {
    const productId = req.params.id;
    // Fetch the product and aggregate its available sizes
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

  // --- Backend Validation ---
  if (!email || !password || !name) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }
  // Validate email format
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  // Validate password length
  if (password.length < 6) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    // Hash the password before storing it for security. 10 is the salt round count.
    const hashedPassword = await bcrypt.hash(password, 10);
    // Insert the new user into the database.
    const [result] = await db.query('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword]);
    
    // Send a welcome email to the new user
    const subject = 'Welcome to Fashionable Baby Shoes!';
    const html = `<h1>Welcome, ${name || 'friend'}!</h1><p>Thank you for signing up. We're excited to have you with us. Happy shopping!</p>`;
    sendEmail(email, subject, html).catch(console.error); // Send email but don't wait for it to complete

    res.status(201).json({ success: true, userId: result.insertId });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// POST /api/login - Handles user login with email and password.
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

    // Use passport's req.login() to establish a session.
    // This calls passport.serializeUser() and saves the user ID to the session.
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
      // To prevent "email enumeration" attacks, we send a success response even if the user doesn't exist.
      // This way, an attacker can't figure out which emails are registered.
      return res.json({ success: true, message: 'If a user with that email exists, a reset link has been sent.' });
    }

    const token = crypto.randomBytes(32).toString('hex'); // Generate a secure, random token.
    const expires = Date.now() + 3600000; // Token expires in 1 hour (3600000 ms).

    // Store the token and its expiration date in the database for the user.
    await db.query('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?', [token, expires, user.id]);

    const resetUrl = `${FRONTEND_URL}/Frontend-babyshoe/reset-password.html?token=${token}`;
    const subject = 'Password Reset Request';
    const html = `<p>You requested a password reset. Click the link below to reset your password:</p><a href="${resetUrl}">${resetUrl}</a><p>This link will expire in one hour.</p>`;

    // Send email in the background without waiting for it to complete
    // By using 'await', we ensure that if sendEmail fails,
    // the error is caught by this try/catch block.
    await sendEmail(user.email, subject, html);
    res.json({ success: true, message: 'If a user with that email exists, a reset link has been sent.' });

  } catch (err) {
    // This will now catch errors from both the database query and sendEmail.
    // It returns a detailed error to the frontend for easier debugging.
    // IMPORTANT: For production, you might want to revert to a more generic error message.
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
    // 2. Create a unique ID for the cart item (product + size).
    const cartItemId = `${product.id}-${size}`;
    const existingItem = req.session.cart.find(item => item.id === cartItemId);

    if (existingItem) {
      // If item already exists, just update its quantity.
      existingItem.quantity += parseInt(quantity, 10);
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


// --- Favourites API Routes ---

/**
 * GET /api/favourites - Fetches all favourite items for the logged-in user.
 */
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
    return; // Nothing to merge
  }

  console.log(`Merging ${guestCart.length} guest cart items for user ${userId}.`);

  const mergePromises = guestCart.map(item => {
    const [productId, size] = item.id.split('-');
    const sql = `
      INSERT INTO cart_items (user_id, product_id, size, quantity, price)
      VALUES (?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity)
    `;
    // Ensure all values are valid before querying
    return db.query(sql, [userId, productId, size, item.quantity, item.price]);
  });

  await Promise.all(mergePromises);
  // After merging, the guest cart in the session is no longer needed.
  session.cart = [];
}


// --- Google Auth Routes ---

// GET /auth/google - The route the user visits to start the Google login process.
// Passport redirects them to Google's authentication screen.
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// GET /auth/google/callback - The route Google redirects to after the user authenticates.
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: `${FRONTEND_URL}/login.html` }), // If Google auth fails, redirect to login page.
  (req, res) => {
    // Successful authentication. The user is now logged in (req.user exists).
    // Merge guest cart with user account if necessary.
    mergeCartsOnLogin(req.session, req.user.id)
      .then(() => console.log(`Cart merged for Google user ${req.user.id}`))
      .catch(err => console.error("Google login cart merge failed:", err));

    const { name, isNewUser } = req.user;
    res.redirect(`${FRONTEND_URL}/Frontend-babyshoe/auth-callback.html?name=${encodeURIComponent(name)}&isNewUser=${isNewUser}`);

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
// GET /api/auth/status - A route for the frontend to check if the user is currently logged in.
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

// --- M-Pesa API Routes ---

/**
 * Middleware to get M-Pesa access token.
 * This function requests an access token from the Safaricom API and attaches it to the request object.
 */
const getMpesaAccessToken = async (req, res, next) => {
  const consumerKey = process.env.MPESA_CONSUMER_KEY;
  const consumerSecret = process.env.MPESA_CONSUMER_SECRET;
  const url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials';
  const auth = 'Basic ' + Buffer.from(consumerKey + ':' + consumerSecret).toString('base64');

  try {
    const response = await axios.get(url, { headers: { Authorization: auth } });
    req.mpesa_access_token = response.data.access_token;
    next();
  } catch (err) {
    console.error('Failed to get M-Pesa access token:', err.response ? err.response.data : err.message);
    res.status(500).json({ error: 'Could not get M-Pesa access token' });
  }
};

/**
 * POST /api/stk-push - Initiates an M-Pesa STK Push request.
 */
app.post('/api/stk-push', getMpesaAccessToken, async (req, res) => {
  const { phone: rawPhone, cart, shippingDetails } = req.body; // We will ignore the 'amount' from the body
  const token = req.mpesa_access_token;
  const phone = normalizePhone(rawPhone);

  // Validate the required fields from the request body
  if (!phone || !cart || !Array.isArray(cart) || cart.length === 0) {
    return res.status(400).json({ error: 'A valid phone number (e.g., 07... or 254...) and cart details are required.' });
  }

  let serverCalculatedSubtotal = 0;
  try {
    // --- SERVER-SIDE AMOUNT CALCULATION ---
    // This is a critical security step. Never trust the amount from the client.
    for (const item of cart) {
      // Fetch the product price from the database to prevent price tampering.
      const [[product]] = await db.query('SELECT price FROM product WHERE id = ?', [item.productId]);
      if (!product) {
        return res.status(400).json({ error: `Product with ID ${item.productId} not found.` });
      }
      serverCalculatedSubtotal += product.price * item.quantity;
    }
  } catch (dbError) {
    console.error("Database error during amount calculation:", dbError);
    return res.status(500).json({ error: 'Could not verify product prices.' });
  }

  const shippingCost = 500; // Define shipping cost on the server
  const serverCalculatedTotal = serverCalculatedSubtotal + shippingCost;

  const url = 'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest';
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey = process.env.MPESA_PASSKEY;
  const timestamp = new Date().toISOString().replace(/[^0-9]/g, '').slice(0, -3);
  const password = Buffer.from(shortcode + passkey + timestamp).toString('base64');

  const payload = {
    BusinessShortCode: shortcode,
    Password: password,
    Timestamp: timestamp,
    TransactionType: 'CustomerPayBillOnline',
    Amount: serverCalculatedTotal, // CRITICAL: Use the server-calculated total
    PartyA: phone,
    PartyB: shortcode,
    PhoneNumber: phone,
    CallBackURL: process.env.MPESA_CALLBACK_URL,
    AccountReference: 'FashionableBabyShoes',
    TransactionDesc: 'Payment for shoes'
  };

  try {
    // --- Step 1: Initiate the STK Push with Safaricom ---
    const response = await axios.post(url, payload, {
      headers: { Authorization: `Bearer ${token}` }
    });

    const checkoutRequestID = response.data.CheckoutRequestID;

    // --- Step 2: Save the pending order to your database ---
    // This is crucial. We save the order with a 'pending' status.
    // The M-Pesa callback will later update this order to 'paid' or 'failed'.
    const orderData = {
      user_id: req.user ? req.user.id : null, // Safely get user_id if logged in, otherwise null for guest
      status: 'pending',
      amount: serverCalculatedTotal, // Save the correct amount to the order
      mpesa_checkout_id: checkoutRequestID,
      shipping_details: JSON.stringify(shippingDetails), // Store shipping info
      items: JSON.stringify(cart) // Store the items in the order
    };

    // You will need an 'orders' table for this to work.
    await db.query('INSERT INTO orders SET ?', orderData);
    console.log(`✅ Order pending, saved with CheckoutRequestID: ${checkoutRequestID}`);

    res.status(200).json(response.data);
  } catch (err) {
    console.error('STK Push Error:', err.response ? err.response.data : err.message);
    res.status(500).json({ error: 'Failed to initiate M-Pesa payment.', details: err.response ? err.response.data : null });
  }
});

/**
 * POST /api/mpesa-callback - Receives the payment confirmation from Safaricom.
 */
app.post('/api/mpesa-callback', (req, res) => {
  console.log('--- M-Pesa Callback Received ---');
  console.log(JSON.stringify(req.body, null, 2));
  
  // Safely access nested properties
  const callbackData = req.body && req.body.Body && req.body.Body.stkCallback;

  if (!callbackData) {
    console.error('Invalid M-Pesa callback format received.');
    return res.status(200).json({ ResultCode: 1, ResultDesc: 'Failed' }); // Acknowledge but note error
  }

  const resultCode = callbackData.ResultCode;

  if (resultCode === 0) {
    // Payment was successful
    const checkoutRequestID = callbackData.CheckoutRequestID;
    console.log(`✅ Payment successful! Updating order with CheckoutRequestID: ${checkoutRequestID}`);
    // Here you would typically:
    // 1. Find the order: `UPDATE orders SET status = 'paid' WHERE mpesa_checkout_id = ?`
    // 2. Verify the amount paid from `callbackData.CallbackMetadata`.
    // 3. Clear the user's cart.
    // 4. Send a confirmation email to the user.
  } else {
    // Payment failed or was cancelled
    console.error(`❌ Payment failed. ResultCode: ${resultCode}, Reason: ${callbackData.ResultDesc}`);
  }

  // Acknowledge receipt of the callback to Safaricom
  res.status(200).json({ ResultCode: 0, ResultDesc: 'Accepted' });
});


// --- Server Startup ---
// First, test the database connection. If successful, start the Express server.
db.getConnection()
  .then(connection => {
    console.log('Connected to MySQL');
    connection.release();
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  }).catch(err => {
    console.error('Failed to connect to database.', err);
    process.exit(1);
  });
