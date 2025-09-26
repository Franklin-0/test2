const express = require("express");
const axios = require("axios");
const router = express.Router();
const db = require('../db');
const logger = require('../logger'); //logger

// 1️⃣ Get OAuth token
async function getToken() {
  const consumerKey = process.env.MPESA_CONSUMER_KEY;
  const consumerSecret = process.env.MPESA_CONSUMER_SECRET;
  const url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials";
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

// 2️⃣ STK Push endpoint
router.post("/stk-push", async (req, res) => {
  try {
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
      const [[product]] = await db.query('SELECT price FROM products WHERE id = ?', [item.productId]);
      if (!product) {
        return res.status(400).json({ error: `Product with ID ${item.productId} not found.` });
      }
      subtotal += product.price * item.quantity;
    }

    const shipping = 500; 
    const amount = subtotal + shipping;
    // We'll also need the real total to save in the database for the pending order.
    const realOrderAmount = subtotal + shipping;
    // --- End of server-side amount calculation ---

    const token = await getToken();
    const timestamp = getTimestamp();
    const shortcode = process.env.MPESA_SHORTCODE;
    const passkey = process.env.MPESA_PASSKEY;
    const callbackURL = process.env.MPESA_CALLBACK_URL;

    // Generate password = base64(shortcode + passkey + timestamp)
    const password = Buffer.from(shortcode + passkey + timestamp).toString("base64");

    const stkResp = await axios.post(
      "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
      {
        BusinessShortCode: shortcode,
        Password: password,
        Timestamp: timestamp,
        TransactionType: 'CustomerPayBillOnline',
        Amount: amount,
        PartyA: msisdn,      
        PartyB: shortcode,    // paybill
        PhoneNumber: msisdn,   
        CallBackURL: callbackURL,
        AccountReference: process.env.MPESA_ACCOUNT_NUMBER || 'FashionableBabyShoes',
        TransactionDesc: `Order payment by ${shippingDetails?.name || "Customer"}`
      },
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    );

    const checkoutRequestID = stkResp.data.CheckoutRequestID;
    const orderData = {
      user_id: req.user ? req.user.id : null, 
      status: 'pending',
      amount: realOrderAmount, 
      mpesa_checkout_id: checkoutRequestID,
      shipping_details: JSON.stringify(shippingDetails), 
      items: JSON.stringify(cart) 
    };

    await db.query('INSERT INTO orders SET ?', orderData);
    logger.info(`✅ Order pending, saved with CheckoutRequestID: ${checkoutRequestID}`, { checkoutRequestID });
    res.json(stkResp.data);

  } catch (err) {
    const errorContext = {
      phone: req.body.phone,
      errorMessage: err.message,
      details: err.response?.data || null
    };
    logger.error("❌ STK Push error", errorContext);
    res.status(err.response?.status || 500).json({
      error: "Failed to initiate M-Pesa payment",
      details: err.response?.data?.errorMessage || "An internal error occurred."
    });
  }
});

/**
 * Middleware to secure the callback endpoint by checking the source IP.
 * In production, you would get these IPs from Safaricom's official documentation.
 */

const safaricomIpCheck = (req, res, next) => {
  const allowedIps = [
    '196.201.214.200', '196.201.214.206', '196.201.213.114', '196.201.212.127', 
    '196.201.212.138', '196.201.212.129', '196.201.212.136', '196.201.213.44', 
    '196.201.213.50', '196.201.214.208'
    // Add any other IPs provided by Safaricom. For sandbox, you might need to allow your ngrok IP.
  ];
  let requestIp = req.ip || req.connection.remoteAddress;

  // Handle IPv6-mapped IPv4 addresses (e.g., ::ffff:196.201.214.200)
  if (requestIp && requestIp.startsWith('::ffff:')) {
    requestIp = requestIp.substring(7);
  }

  // For production, you should enforce this check.
  if (process.env.NODE_ENV === 'production' && !allowedIps.includes(requestIp)) {
    logger.warn(`🚫 Denied callback request from untrusted IP: ${requestIp}`);
    return res.status(403).json({ error: 'Forbidden' });
  }

  next();
};

// 3️⃣ Callback route → Safaricom sends payment result here
router.post("/stk-callback", safaricomIpCheck, async (req, res) => {
  logger.info("📩 M-Pesa Callback Received", { body: req.body });
  
  const callbackData = req.body?.Body?.stkCallback;

  if (!callbackData) {
    logger.error('Invalid M-Pesa callback format received.', { body: req.body });
    // Acknowledge receipt to Safaricom even on error to prevent retries.
    return res.status(200).json({ ResultCode: 1, ResultDesc: 'Failed' });
  }

  const checkoutRequestID = callbackData.CheckoutRequestID;
  const resultCode = callbackData.ResultCode;

  // --- Handle failed or cancelled payments ---
  if (resultCode !== 0) {
    logger.error(`❌ Payment failed for ${checkoutRequestID}.`, { checkoutRequestID, resultCode, reason: callbackData.ResultDesc });
    // Store the failure reason for better analytics/support.
    const failureReason = callbackData.ResultDesc || 'Payment failed or was cancelled by user.';
    // Update the order status to 'failed'
    await db.query(
      'UPDATE orders SET status = ?, failure_reason = ? WHERE mpesa_checkout_id = ?', 
      ['failed', failureReason, checkoutRequestID]);
    return res.status(200).json({ ResultCode: 0, ResultDesc: 'Accepted' });
  }

  // --- Handle successful payments ---
  logger.info(`🎉 Payment successful for ${checkoutRequestID}`, { checkoutRequestID });
  const metadata = callbackData.CallbackMetadata.Item;
  const parsedMeta = {};
  metadata.forEach(item => {
    // Use optional chaining in case Value is missing
    parsedMeta[item.Name] = item.Value;
  });

  const mpesaReceipt = parsedMeta.MpesaReceiptNumber;
  const amountPaid = parsedMeta.Amount;

  // --- Use a database transaction to ensure data integrity ---
  let connection;
  try {
    // 1. Get a connection from the pool
    connection = await db.getConnection();
    // 2. Start a transaction
    await connection.beginTransaction();

    // 3. Find the order to verify amount and get user_id
    const [[order]] = await connection.query(
      'SELECT * FROM orders WHERE mpesa_checkout_id = ? AND status = ?',
      [checkoutRequestID, 'pending']
    );

    if (!order) {
      // This can happen if the callback is delayed or sent twice.
      // It's not an error, but we should log it and not proceed.
      logger.warn(`⚠️ Order with CheckoutID ${checkoutRequestID} was not in 'pending' state or not found. No action taken.`, { checkoutRequestID });
      await connection.commit(); // Commit the empty transaction
      return res.status(200).json({ ResultCode: 0, ResultDesc: "Accepted" });
    }

    // Optional but recommended: Verify the amount paid matches the order amount
    if (parseInt(amountPaid, 10) < order.amount) {
        logger.error(`❌ Payment amount mismatch for order ${order.id}.`, { orderId: order.id, checkoutRequestID, expected: order.amount, paid: amountPaid });
        await connection.query('UPDATE orders SET status = ? WHERE id = ?', ['payment_mismatch', order.id]);
        await connection.commit();
        return res.status(200).json({ ResultCode: 0, ResultDesc: "Accepted" });
    }

    // 4. Update the order status to 'paid'
    await connection.query(
      'UPDATE orders SET status = ?, mpesa_receipt = ?, amount_paid = ? WHERE mpesa_checkout_id = ? AND status = ?',
      ['paid', mpesaReceipt, amountPaid, checkoutRequestID, 'pending']
    );
    logger.info(`✅ Order ${order.id} updated to 'paid'.`, { orderId: order.id, checkoutRequestID, receipt: mpesaReceipt });

    // 5. If the order was placed by a logged-in user, clear their cart
    if (order.user_id) {
      await connection.query('DELETE FROM carts WHERE user_id = ?', [order.user_id]);
      logger.info(`🛒 Cart cleared for user ${order.user_id}.`, { userId: order.user_id, orderId: order.id });
    }

    // 6. Commit the transaction
    await connection.commit();
    // TODO: Send a confirmation email here, after the transaction is successful.
  } catch (dbError) {
    const errorContext = {
      checkoutRequestID,
      error: dbError.message,
      stack: dbError.stack
    };
    logger.error('DATABASE TRANSACTION ERROR during M-Pesa callback processing:', errorContext);
    // If an error occurred, roll back the transaction
    if (connection) await connection.rollback();
  } finally {
    // 7. Always release the connection back to the pool
    if (connection) connection.release();
  }

  // Always respond 200 OK
  res.status(200).json({ ResultCode: 0, ResultDesc: "Accepted" });
});

module.exports = router;
