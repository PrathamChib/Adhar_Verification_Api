require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.set("trust proxy", true);

const PORT = Number(process.env.PORT) || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN || process.env.TELEGRAM_BOT_TOKEN;
const CHAT_ID = process.env.CHAT_ID || process.env.TELEGRAM_CHAT_ID;

const OTP_EXPIRY_MS = 2 * 60 * 1000;
const MAX_ATTEMPTS = 3;
const SESSION_CLEANUP_INTERVAL_MS = 30 * 1000;

// Stores Aadhaar -> OTP session
const otpSessions = new Map();
// Stores client key (IP) -> Aadhaar for verification flow
const clientToAadhaar = new Map();

function isValidAadhaar(aadhaar) {
  return typeof aadhaar === "string" && /^\d{12}$/.test(aadhaar);
}

function isValidOtp(otp) {
  return typeof otp === "string" && /^\d{6}$/.test(otp);
}

function generateSixDigitOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function removeSession(aadhaar) {
  otpSessions.delete(aadhaar);
  for (const [clientKey, mappedAadhaar] of clientToAadhaar.entries()) {
    if (mappedAadhaar === aadhaar) {
      clientToAadhaar.delete(clientKey);
    }
  }
}

function isExpired(session) {
  return Date.now() > session.expiresAt;
}

function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [aadhaar, session] of otpSessions.entries()) {
    if (now > session.expiresAt) {
      removeSession(aadhaar);
    }
  }
}

setInterval(cleanupExpiredSessions, SESSION_CLEANUP_INTERVAL_MS).unref();

async function sendOtpViaTelegram(otp) {
  if (!BOT_TOKEN || !CHAT_ID) {
    throw new Error("Missing BOT_TOKEN or CHAT_ID environment variables");
  }

  const telegramUrl = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
  const message = `Your OTP for Aadhaar verification is: ${otp}`;

  await axios.post(
    telegramUrl,
    {
      chat_id: CHAT_ID,
      text: message
    },
    {
      timeout: 5000
    }
  );
}

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

function getClientKey(req) {
  // `req.ip` is proxy-aware when trust proxy is enabled (recommended on Render).
  return req.ip || req.socket.remoteAddress || "unknown-client";
}

function getActiveSessionForResend(req, aadhaarFromBody) {
  const clientKey = getClientKey(req);
  const aadhaar = aadhaarFromBody || clientToAadhaar.get(clientKey);

  if (!aadhaar) {
    return { error: "OTP_SESSION_NOT_FOUND" };
  }

  if (!isValidAadhaar(aadhaar)) {
    return { error: "INVALID_AADHAAR" };
  }

  const session = otpSessions.get(aadhaar);
  if (!session) {
    return { error: "OTP_SESSION_NOT_FOUND" };
  }

  if (isExpired(session)) {
    removeSession(aadhaar);
    return { error: "OTP_EXPIRED" };
  }

  return { aadhaar, session, clientKey };
}

app.post("/send-otp", async (req, res) => {
  try {
    const { aadhaar } = req.query || {};
    const clientKey = getClientKey(req);

    if (!isValidAadhaar(aadhaar)) {
      return res.status(400).json({ error: "INVALID_AADHAAR" });
    }

    const existingSession = otpSessions.get(aadhaar);
    if (existingSession && !isExpired(existingSession)) {
      return res.status(429).json({ error: "OTP_ALREADY_SENT" });
    }

    const otp = generateSixDigitOtp();
    const createdAt = Date.now();
    const session = {
      aadhaar,
      otp,
      createdAt,
      expiresAt: createdAt + OTP_EXPIRY_MS,
      attemptsLeft: MAX_ATTEMPTS
    };

    try {
      await sendOtpViaTelegram(otp);
    } catch (error) {
      return res.status(502).json({ error: "TELEGRAM_SEND_FAILED" });
    }

    otpSessions.set(aadhaar, session);
    clientToAadhaar.set(clientKey, aadhaar);

    return res.status(200).json({
      status: "OTP_SENT",
      expires_in_seconds: OTP_EXPIRY_MS / 1000
    });
  } catch (error) {
    return res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
  }
});

app.post("/resend-otp", async (req, res) => {
  try {
    const { aadhaar } = req.query || {};
    const result = getActiveSessionForResend(req, aadhaar);

    if (result.error === "INVALID_AADHAAR") {
      return res.status(400).json({ error: "INVALID_AADHAAR" });
    }

    if (result.error === "OTP_SESSION_NOT_FOUND") {
      return res.status(404).json({ error: "OTP_SESSION_NOT_FOUND" });
    }

    if (result.error === "OTP_EXPIRED") {
      return res.status(410).json({ error: "OTP_EXPIRED" });
    }

    const { aadhaar: resolvedAadhaar, session, clientKey } = result;

    try {
      await sendOtpViaTelegram(session.otp);
    } catch (error) {
      return res.status(502).json({ error: "TELEGRAM_SEND_FAILED" });
    }

    clientToAadhaar.set(clientKey, resolvedAadhaar);

    return res.status(200).json({
      status: "OTP_RESENT",
      expires_in_seconds: Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000))
    });
  } catch (error) {
    return res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
  }
});

app.post("/verify-otp", (req, res) => {
  try {
    const { otp } = req.query || {};
    const clientKey = getClientKey(req);

    if (!isValidOtp(otp)) {
      return res.status(400).json({
        verified: false,
        error: "INVALID_OTP",
        attempts_left: MAX_ATTEMPTS
      });
    }

    const aadhaar = clientToAadhaar.get(clientKey);
    if (!aadhaar) {
      return res.status(404).json({
        verified: false,
        error: "OTP_SESSION_NOT_FOUND"
      });
    }

    const session = otpSessions.get(aadhaar);
    if (!session) {
      clientToAadhaar.delete(clientKey);
      return res.status(404).json({
        verified: false,
        error: "OTP_SESSION_NOT_FOUND"
      });
    }

    if (isExpired(session)) {
      removeSession(session.aadhaar);
      return res.status(410).json({
        verified: false,
        error: "OTP_EXPIRED"
      });
    }

    if (session.attemptsLeft <= 0) {
      removeSession(session.aadhaar);
      return res.status(429).json({
        verified: false,
        error: "MAX_ATTEMPTS_EXCEEDED"
      });
    }

    if (session.otp === otp) {
      removeSession(session.aadhaar);
      return res.status(200).json({ verified: true });
    }

    session.attemptsLeft -= 1;

    if (session.attemptsLeft <= 0) {
      removeSession(session.aadhaar);
      return res.status(429).json({
        verified: false,
        error: "MAX_ATTEMPTS_EXCEEDED"
      });
    }

    return res.status(401).json({
      verified: false,
      error: "INVALID_OTP",
      attempts_left: session.attemptsLeft
    });
  } catch (error) {
    return res.status(500).json({
      verified: false,
      error: "INTERNAL_SERVER_ERROR"
    });
  }
});

app.use((err, _req, res, _next) => {
  return res.status(500).json({
    error: "INTERNAL_SERVER_ERROR",
    message: err?.message || "Unexpected error"
  });
});

app.listen(PORT, () => {
  console.log(`OTP API running on port ${PORT}`);
});
