require("dotenv").config();

const express = require("express");
const twilio = require("twilio");
const crypto = require("crypto");

const app = express();
app.use(express.json());
app.set("trust proxy", true);

const PORT = process.env.PORT || 3000;
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

const OTP_EXPIRY_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 3;
const SESSION_CLEANUP_INTERVAL_MS = 30 * 1000;

// Stores Aadhaar -> OTP session
const otpSessions = new Map();
// Stores client key (IP) -> Aadhaar for verification flow
const clientToAadhaar = new Map();

const aadhaarPhoneMap = {
  "898400965625": "+917006483722",
  "676767676767": "+91788940413"
};

const aadhaarVidMap = {
  "898400965625": "1234567890123456",
  "676767676767": "9876543210987654"
};

function isValidAadhaar(aadhaar) {
  return typeof aadhaar === "string" && /^\d{12}$/.test(aadhaar);
}

function isValidOtp(otp) {
  return typeof otp === "string" && /^\d{6}$/.test(otp);
}

function generateSixDigitOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function generateIrreversibleAadhaarCode(aadhaar) {
  const secret = process.env.AADHAAR_HASH_SECRET || "uidai-mock-secret";
  return crypto
    .createHmac("sha256", secret)
    .update(aadhaar)
    .digest("hex")
    .substring(0, 32);
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

async function sendOtpViaTwilio(phoneNumber, otp) {
  try {
    await twilioClient.messages.create({
      body: `Your OTP for Aadhaar verification is: ${otp}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phoneNumber
    });
  } catch (error) {
    console.error("Twilio send failed:", error);
    throw new Error("TWILIO_SEND_FAILED");
  }
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

    const phoneNumber = aadhaarPhoneMap[aadhaar];
    if (!phoneNumber) {
      console.log(`Aadhaar mapping not found for: ${aadhaar}`);
      return res.status(404).json({ error: "AADHAAR_NOT_FOUND" });
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
      await sendOtpViaTwilio(phoneNumber, otp);
    } catch (error) {
      return res.status(502).json({ error: "TWILIO_SEND_FAILED" });
    }

    otpSessions.set(aadhaar, session);
    clientToAadhaar.set(clientKey, aadhaar);

    console.log(`OTP successfully sent for Aadhaar: ${aadhaar} to ${phoneNumber}`);

    return res.status(200).json({
      status: "OTP_SENT",
      expires_in_seconds: OTP_EXPIRY_MS / 1000
    });
  } catch (error) {
    console.error("Internal server error in /send-otp:", error);
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
    const phoneNumber = aadhaarPhoneMap[resolvedAadhaar];
    
    if (!phoneNumber) {
      return res.status(404).json({ error: "AADHAAR_NOT_FOUND" });
    }

    try {
      await sendOtpViaTwilio(phoneNumber, session.otp);
    } catch (error) {
      return res.status(502).json({ error: "TWILIO_SEND_FAILED" });
    }

    clientToAadhaar.set(clientKey, resolvedAadhaar);
    console.log(`OTP successfully resent for Aadhaar: ${resolvedAadhaar} to ${phoneNumber}`);

    return res.status(200).json({
      status: "OTP_RESENT",
      expires_in_seconds: Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000))
    });
  } catch (error) {
    console.error("Internal server error in /resend-otp:", error);
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

    if (session.otp === otp) {
      // Generate irreversible Aadhaar reference ID
      const aadhaarReferenceId = generateIrreversibleAadhaarCode(session.aadhaar);
      
      // Internally resolve VID if needed for future logic (not returned in response)
      const vid = aadhaarVidMap[session.aadhaar];

      // Remove session only AFTER successful verification response is prepared
      removeSession(session.aadhaar);
      console.log(`OTP verified successfully for Aadhaar: ${session.aadhaar}`);
      
      return res.status(200).json({
        verified: true,
        aadhaar_reference_id: aadhaarReferenceId
      });
    }

    session.attemptsLeft -= 1;

    if (session.attemptsLeft === 0) {
      removeSession(session.aadhaar);

      return res.status(401).json({
        verified: false,
        error: "INVALID_OTP",
        attempts_left: 0
      });
    }

    return res.status(401).json({
      verified: false,
      error: "INVALID_OTP",
      attempts_left: session.attemptsLeft
    });
  } catch (error) {
    console.error("Internal server error in /verify-otp:", error);
    return res.status(500).json({
      verified: false,
      error: "INTERNAL_SERVER_ERROR"
    });
  }
});

app.use((err, _req, res, _next) => {
  console.error("Unhandled exception:", err);
  return res.status(500).json({
    error: "INTERNAL_SERVER_ERROR",
    message: err?.message || "Unexpected error"
  });
});

app.listen(PORT, () => {
  console.log(`OTP API running on port ${PORT}`);
});
