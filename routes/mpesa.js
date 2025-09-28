const express = require("express");
const axios = require("axios");
const router = express.Router();
const { db } = require('../db');
const logger = require('../logger'); //logger

// 1️⃣ Get OAuth token
async function getToken() {
  const consumerKey = process.env.MPESA_CONSUMER_KEY;
  const consumerSecret = process.env.MPESA_CONSUMER_SECRET;
  
  const baseUrl = process.env.MPESA_ENV === "production"
    ? "https://api.safaricom.co.ke"
    : "https://sandbox.safaricom.co.ke";

  const url = `${baseUrl}/oauth/v1/generate?grant_type=client_credentials`;
  const auth = 'Basic ' + Buffer.from(consumerKey + ':' + consumerSecret).toString('base64');

  const resp = await axios.get(url, { headers: { Authorization: auth } });
  return resp.data.access_token;
}

// Helper → generate timestamp
function getTimestamp() {
  const pad = (n) => (n < 10 ? "0" + n : n);
  const date = new Date();
  return (
    date.getFullYear().toString() +
    pad(date.getMonth() + 1) +
    pad(date.getDate()) +
    pad(date.getHours()) +
    pad(date.getMinutes()) +
    pad(date.getSeconds())
  );
}

/**
 * Normalizes a phone number to the MSISDN format (254...).
 * @param {string} phone - The phone number to normalize.
 * @returns {string|null} The normalized phone number or null if invalid.
 */
function normalizePhone(phone) {
  if (!phone || typeof phone !== 'string') return null;
  
  let msisdn = phone.trim();
  if (msisdn.startsWith('+')) {
    msisdn = msisdn.substring(1);
  }
  if (msisdn.startsWith('07')) {
    msisdn = '254' + msisdn.substring(1);
  }
  if (msisdn.startsWith('7')) {
    msisdn = '254' + msisdn;
  }

  // Final check for the correct format
  if (/^2547\d{8}$/.test(msisdn)) {
    return msisdn;
  }
  return null;
}

// Middleware for request-level logging
router.use((req, res, next) => {
  logger.info(`Request to M-Pesa route: ${req.method} ${req.originalUrl}`, { body: req.body });
  next();
});

// 2️⃣ STK Push endpoint (now at /api/mpesa/stk-push)
router.post("/stk-push", async (req, res) => {
  try {
    const mpesaEnv = process.env.MPESA_ENV || 'sandbox';
    const { phone, cart, shippingDetails } = req.body;

    // --- 1. Input Validation ---
    const msisdn = normalizePhone(phone);
    if (!msisdn) {
      return res.status(400).json({ error: 'Invalid phone number format. Please use 2547...' });
    }
    if (!cart || !Array.isArray(cart) || cart.length === 0) {
      return res.status(400).json({ error: 'Cart details are missing or invalid.' });
    }
    if (!shippingDetails || typeof shippingDetails !== 'object' || !shippingDetails.name) {
      return res.status(400).json({ error: 'Valid shipping details are required.' });
    }

    // --- 2. Server-side amount calculation ---
    let subtotal = 0;
    for (const item of cart) {
      const [[product]] = await db.query('SELECT price FROM product WHERE id = ?', [item.productId]);
      if (!product) {
        return res.status(400).json({ error: `Product with ID ${item.productId} not found.` });
      }
      subtotal += product.price * item.quantity;
    }

    const shipping = 500; 
    const amount = subtotal + shipping;
    // ❗ M-Pesa Sandbox is most reliable with an amount of 1.
    const mpesaAmount = mpesaEnv === 'sandbox' ? 1 : amount;

    const token = await getToken();
    const shortcode = process.env.MPESA_SHORTCODE;
    const passkey = process.env.MPESA_PASSKEY;
    const callbackURL = process.env.MPESA_CALLBACK_URL ? process.env.MPESA_CALLBACK_URL.trim() : null;

    console.log("✅ Shortcode being used:", shortcode);
    console.log("✅ Environment:", process.env.MPESA_ENV);
    console.log("✅ Callback URL:", callbackURL);

    // --- 3. Environment Variable Validation ---
    if (!shortcode || !passkey || !callbackURL) {
      logger.error('❌ M-Pesa environment variables are missing. Check MPESA_SHORTCODE, MPESA_PASSKEY, MPESA_CALLBACK_URL.');
      // Do not expose internal configuration details to the client.
      return res.status(500).json({ error: 'Payment gateway is not configured correctly.' });
    }

    // --- 4. Create Pending Order in DB *BEFORE* calling M-Pesa ---
    // This prevents the race condition where the callback arrives before the order is saved.
    let orderId;
    try {
      const orderData = {
        user_id: req.user ? req.user.id : null,
        status: 'pending_mpesa_auth', // A temporary status
        amount: amount, // The real order amount
        shipping_details: JSON.stringify(shippingDetails),
        items: JSON.stringify(cart)
      };
      const [result] = await db.query('INSERT INTO orders SET ?', orderData);
      orderId = result.insertId;
      logger.info(`📝 Order created with temporary status, ID: ${orderId}`);
    } catch (dbError) {
      logger.error('❌ DB Error: Failed to create initial pending order.', { error: dbError.message });
      return res.status(500).json({
        error: "Failed to create order before payment.",
        details: "Could not save order to the database."
      });
    }
    // --- End of order creation ---


    const timestamp = getTimestamp();

    // Generate password = base64(shortcode + passkey + timestamp)
    const password = Buffer.from(shortcode + passkey + timestamp).toString("base64");

    const stkPushUrl = mpesaEnv === "production"
      ? "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
      : "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest";


    const stkResp = await axios.post(
      stkPushUrl,
      {
        BusinessShortCode: shortcode,
        Password: password,
        Timestamp: timestamp,
        TransactionType: 'CustomerPayBillOnline',
        Amount: mpesaAmount, // Use the sandbox-friendly amount
        PartyA: msisdn,      
        PartyB: shortcode,    // paybill
        PhoneNumber: msisdn,   
        CallBackURL: callbackURL, // Use the trimmed URL
        AccountReference: process.env.MPESA_ACCOUNT_NUMBER || 'FashionableBabyShoes',
        TransactionDesc: `Order payment by ${shippingDetails?.name || "Customer"}`
      },
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    );

    // --- 5. Update Order with M-Pesa CheckoutRequestID ---
    const checkoutRequestID = stkResp.data.CheckoutRequestID;
    await db.query(
      'UPDATE orders SET status = ?, mpesa_checkout_id = ? WHERE id = ?',
      ['pending', checkoutRequestID, orderId]
    );
    logger.info(`✅ Order ${orderId} updated to pending with CheckoutRequestID: ${checkoutRequestID}`, { orderId, checkoutRequestID });

    res.json(stkResp.data);

  } catch (err) {
    // This block now catches errors from both the M-Pesa API call and the DB operations.
    const errorContext = {
      phone: req.body?.phone,
      errorMessage: err.message,
      details: err.response?.data || null
    };

    logger.error("❌ STK Push error", errorContext);

    // If the order was created but the M-Pesa call failed, mark the order as failed.
    // This requires `orderId` to be declared outside the try block.
    // We can't do that easily here, but it's a good improvement for later.
    // For now, the order will remain in 'pending_mpesa_auth' status, which is informative.

    res.status(err.response?.status || 500).json({
      error: "Failed to initiate M-Pesa payment",
      details: err.response?.data?.errorMessage || "An internal error occurred."
    });
  }
});

module.exports = router;
