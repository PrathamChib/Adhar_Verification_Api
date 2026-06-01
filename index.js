require("dotenv").config();

const express = require("express");
const twilio = require("twilio");
const crypto = require("crypto");
const aadhaarData = require("./aadhaar-data");

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

function isValidAadhaar(aadhaar) {
  return typeof aadhaar === "string" && /^\d{12}$/.test(aadhaar);
}

function isValidVid(vid) {
  return typeof vid === "string" && /^\d{16}$/.test(vid);
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

function maskAadhaar(aadhaar) {
  if (!aadhaar || aadhaar.length < 4) return aadhaar;
  return "XXXXXXXX" + aadhaar.slice(-4);
}

function maskMobile(mobile) {
  if (!mobile || mobile.length < 4) return mobile;
  return "XXXXXX" + mobile.slice(-4);
}

function maskName(name) {
  if (!name) return name;
  return name.split(" ").map(word => {
    if (word.length <= 2) return word;
    return word.substring(0, 2) + "*".repeat(word.length - 2);
  }).join(" ");
}

function calculateAge(dobString) {
  if (!dobString) return null;
  const parts = dobString.split("-");
  if (parts.length !== 3) return null;
  const day = parseInt(parts[0], 10);
  const month = parseInt(parts[1], 10) - 1;
  const year = parseInt(parts[2], 10);

  const dob = new Date(year, month, day);
  const today = new Date();

  let age = today.getFullYear() - dob.getFullYear();
  const monthDiff = today.getMonth() - dob.getMonth();
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < dob.getDate())) {
    age--;
  }
  return age;
}

function findRecordByAadhaar(aadhaar) {
  return aadhaarData.find(r => r.aadhaar === aadhaar);
}

function findRecordByVid(vid) {
  return aadhaarData.find(r => r.vid === vid);
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
      body: `Your OTP for KYC verification is: ${otp}`,
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
  return req.ip || req.socket.remoteAddress || "unknown-client";
}

async function processSendOtp(req, res, aadhaar, phoneNumber, identifierType, identifierValue) {
  const clientKey = getClientKey(req);

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

  console.log(`OTP successfully sent for ${identifierType}: ${identifierValue} to ${phoneNumber}`);

  return res.status(200).json({
    status: "OTP_SENT",
    expires_in_seconds: OTP_EXPIRY_MS / 1000
  });
}

app.post("/send-otp", async (req, res) => {
  try {
    const { aadhaar } = req.query || {};

    if (!isValidAadhaar(aadhaar)) {
      return res.status(400).json({ error: "INVALID_AADHAAR" });
    }

    const record = findRecordByAadhaar(aadhaar);
    if (!record) {
      console.log(`Aadhaar record not found for: ${aadhaar}`);
      return res.status(404).json({ error: "AADHAAR_NOT_FOUND" });
    }

    return await processSendOtp(req, res, aadhaar, record.mobile, "Aadhaar", aadhaar);
  } catch (error) {
    console.error("Internal server error in /send-otp:", error);
    return res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
  }
});

app.post("/send-otp-via-vid", async (req, res) => {
  try {
    const { vid } = req.query || {};

    if (!isValidVid(vid)) {
      return res.status(400).json({ error: "INVALID_VID" });
    }

    const record = findRecordByVid(vid);
    if (!record) {
      console.log(`VID record not found for: ${vid}`);
      return res.status(404).json({ error: "VID_NOT_FOUND" });
    }

    return await processSendOtp(req, res, record.aadhaar, record.mobile, "VID", vid);
  } catch (error) {
    console.error("Internal server error in /send-otp-via-vid:", error);
    return res.status(500).json({ error: "INTERNAL_SERVER_ERROR" });
  }
});

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
    const record = findRecordByAadhaar(resolvedAadhaar);

    if (!record) {
      return res.status(404).json({ error: "AADHAAR_NOT_FOUND" });
    }
    const phoneNumber = record.mobile;

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
      const aadhaarReferenceId = generateIrreversibleAadhaarCode(session.aadhaar);
      const record = findRecordByAadhaar(session.aadhaar);

      removeSession(session.aadhaar);
      console.log(`OTP verified successfully for Aadhaar: ${session.aadhaar}`);

      const nameParts = record.details.name.trim().split(/\s+/);
      const firstName = nameParts[0] || "";
      const lastName = nameParts.slice(1).join(" ") || "";
      const age = calculateAge(record.details.dob);
      const currentDate = new Date().toISOString().split("T")[0];

      return res.status(200).json({
        verified: true,
        aadhaar_reference_id: aadhaarReferenceId,
        kyc_details: {
          name: maskName(record.details.name),
          first_name: firstName,
          last_name: lastName,
          aadhaar_number: maskAadhaar(record.aadhaar),
          mobile: maskMobile(record.mobile),
          gender: record.details.gender,
          dob: record.details.dob,
          age: age,
          date: currentDate,
          address: record.details.address
        }
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
