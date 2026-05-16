# Aadhaar OTP Verification API (Twilio)

Production-ready Node.js + Express backend that sends OTP via Twilio SMS and verifies OTP with expiry, attempt limits, UIDAI-style irreversible reference IDs, and masked KYC data. Supports both Aadhaar-based and VID-based KYC flows.

## Features

- **Aadhaar KYC**: `POST /send-otp?aadhaar=...` with Aadhaar validation (12 digits).
- **VID KYC**: `POST /send-otp-via-vid?vid=...` with VID validation (16 digits).
- **Resend OTP**: `POST /resend-otp?aadhaar=...` to resend active OTP without generating a new one.
- **Verify OTP**: `POST /verify-otp?otp=...` verifies OTP and returns masked user KYC details.
- Internal-only VID and dynamic data mapping via `aadhaar-data.js`.
- Returns UIDAI-style irreversible Aadhaar reference ID on successful verification.
- Sensitive KYC data (Name, Aadhaar, Mobile) is masked in the response.
- OTP expires in 5 minutes.
- Maximum 3 verification attempts.
- One active OTP per Aadhaar (anti-spam behavior).
- Expired session cleanup in memory.
- Robust error handling with clear error codes.
- Deployable on Render.

## Tech Stack

- Node.js
- Express.js
- Twilio SDK (SMS API calls)
- Crypto (Built-in for HMAC hashing)
- dotenv (environment variables)

## Project Structure

- `index.js` - API implementation and OTP session logic
- `aadhaar-data.js` - Mock database containing structured Aadhaar, VID, and user records
- `package.json` - dependencies and scripts
- `.env.example` - environment variables template
- `README.md` - setup, testing, deployment instructions

## Environment Variables

Create `.env` from `.env.example` (or manually create it):

```bash
cp .env.example .env
```

Set:

- `TWILIO_ACCOUNT_SID` - Twilio Account SID
- `TWILIO_AUTH_TOKEN` - Twilio Auth Token
- `TWILIO_PHONE_NUMBER` - Twilio Phone Number (with country code, e.g., +1234567890)
- `AADHAAR_HASH_SECRET` - Secret key used to generate irreversible Aadhaar Reference IDs (e.g., `uidai-mock-secret-2026`)
- `PORT` - server port (Render automatically provides this at runtime)

Example:

```env
TWILIO_ACCOUNT_SID=your_twilio_sid_here
TWILIO_AUTH_TOKEN=your_twilio_auth_token_here
TWILIO_PHONE_NUMBER=+1234567890
AADHAAR_HASH_SECRET=your_super_secret_hash_key
PORT=3000
```

## Run Locally

```bash
npm install
npm run dev
```

Production start:

```bash
npm start
```

Health check:

```bash
curl http://localhost:3000/health
```

## API Contract

*Note: All endpoints currently expect parameters to be passed in the URL Query String.*

### 1) Send OTP (Aadhaar Method)

**Endpoint**: `POST /send-otp?aadhaar=123456789012`  

**Success (200)**:

```json
{
  "status": "OTP_SENT",
  "expires_in_seconds": 300
}
```

### 2) Send OTP (VID Method)

**Endpoint**: `POST /send-otp-via-vid?vid=1234567890123456`  

**Success (200)**:

```json
{
  "status": "OTP_SENT",
  "expires_in_seconds": 300
}
```

**Errors (for both send-otp methods)**:

- `400`: `{"error": "INVALID_AADHAAR"}` or `{"error": "INVALID_VID"}`
- `404`: `{"error": "AADHAAR_NOT_FOUND"}` or `{"error": "VID_NOT_FOUND"}`
- `429`: `{"error": "OTP_ALREADY_SENT"}`
- `502`: `{"error": "TWILIO_SEND_FAILED"}`

### 3) Resend OTP

**Endpoint**: `POST /resend-otp?aadhaar=123456789012`  
*(Note: aadhaar query param is optional if current client IP flow mapping is active)*

**Success (200)**:

```json
{
  "status": "OTP_RESENT",
  "expires_in_seconds": 295
}
```

### 4) Verify OTP

**Endpoint**: `POST /verify-otp?otp=123456`  

**Success (200)**:

```json
{
  "verified": true,
  "aadhaar_reference_id": "89b5a0346a084ad3e20dfbe5171dfbb9",
  "kyc_details": {
    "name": "Pr***** Ch**",
    "aadhaar_number": "XXXXXXXX5625",
    "mobile": "XXXXXX3722",
    "gender": "Male",
    "dob": "25-08-2004",
    "address": "Bangalore, Karnataka"
  }
}
```

**Invalid OTP (401)**:

```json
{
  "verified": false,
  "error": "INVALID_OTP",
  "attempts_left": 2
}
```

**Expired/Not Found**:

- `410`: `{"error": "OTP_EXPIRED"}`
- `404`: `{"error": "OTP_SESSION_NOT_FOUND"}`

## cURL Examples

### Send OTP (Aadhaar)

```bash
curl -X POST "http://localhost:3000/send-otp?aadhaar=898400965625"
```

### Send OTP (VID)

```bash
curl -X POST "http://localhost:3000/send-otp-via-vid?vid=1234567890123456"
```

### Verify OTP

```bash
curl -X POST "http://localhost:3000/verify-otp?otp=123456"
```

## Twilio Setup Notes

- Create an account on [Twilio](https://www.twilio.com/).
- Get your `Account SID` and `Auth Token` from the Twilio console.
- Provision a Twilio Phone Number to send SMS.
- Ensure your Twilio account is upgraded or the recipient numbers are verified in Twilio if using a trial account.

## Render Deployment

1. Push this project to GitHub.
2. In Render, click **New +** -> **Web Service**.
3. Connect your repo.
4. Use:
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node index.js` (or `npm start` if defined in package.json)
5. Add environment variables in Render dashboard.
6. Deploy.

## Security and Production Notes

- Do not commit `.env` to source control.
- OTP sessions and the Aadhaar-VID mapping are currently in-memory and reset when the server restarts.
- Verification links request flow by client IP so `verify-otp` can work without Aadhaar in the verify payload.
- For horizontally scaled production, move sessions to Redis or a database.
- Keep all secrets (`TWILIO_AUTH_TOKEN`, `AADHAAR_HASH_SECRET`, etc.) only in environment variables.
