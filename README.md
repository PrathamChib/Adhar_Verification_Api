# Aadhaar OTP Verification API (Telegram)

Production-ready Node.js + Express backend that sends OTP via Telegram Bot API and verifies OTP with expiry and attempt limits.

## Features

- `POST /send-otp` with Aadhaar validation (12 digits).
- `POST /resend-otp` to resend active OTP without generating a new one.
- `POST /verify-otp` using OTP only (Aadhaar is mapped internally).
- OTP expires in 2 minutes.
- Maximum 3 verification attempts.
- One active OTP per Aadhaar (anti-spam behavior).
- Expired session cleanup in memory.
- Robust error handling with clear error codes.
- Deployable on Render.

## Tech Stack

- Node.js
- Express.js
- Axios (Telegram API calls)
- dotenv (environment variables)

## Project Structure

- `server.js` - API implementation and OTP session logic
- `package.json` - dependencies and scripts
- `.env.example` - environment variables template
- `README.md` - setup, testing, deployment instructions

## Environment Variables

Create `.env` from `.env.example`:

```bash
cp .env.example .env
```

Set:

- `BOT_TOKEN` (or `TELEGRAM_BOT_TOKEN`) - Telegram bot token
- `CHAT_ID` (or `TELEGRAM_CHAT_ID`) - Telegram chat ID where OTP messages will be delivered
- `PORT` - server port (Render automatically provides this at runtime)

Example:

```env
BOT_TOKEN=your_telegram_bot_token_here
CHAT_ID=your_telegram_chat_id_here
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

### 1) Send OTP

**Endpoint**: `POST /send-otp`  
**Body**:

```json
{
  "aadhaar": "123456789012"
}
```

**Success (200)**:

```json
{
  "status": "OTP_SENT",
  "expires_in_seconds": 120
}
```

**Errors**:

- `400`:

```json
{
  "error": "INVALID_AADHAAR"
}
```

- `429`:

```json
{
  "error": "OTP_ALREADY_SENT"
}
```

- `502`:

```json
{
  "error": "TELEGRAM_SEND_FAILED"
}
```

### 2) Resend OTP

**Endpoint**: `POST /resend-otp`  
**Body** (optional Aadhaar; if omitted, current client flow mapping is used):

```json
{
  "aadhaar": "123456789012"
}
```

**Success (200)**:

```json
{
  "status": "OTP_RESENT",
  "expires_in_seconds": 95
}
```

**Errors**:

- `400`:

```json
{
  "error": "INVALID_AADHAAR"
}
```

- `404`:

```json
{
  "error": "OTP_SESSION_NOT_FOUND"
}
```

- `410`:

```json
{
  "error": "OTP_EXPIRED"
}
```

- `502`:

```json
{
  "error": "TELEGRAM_SEND_FAILED"
}
```

### 3) Verify OTP

**Endpoint**: `POST /verify-otp`  
**Body**:

```json
{
  "otp": "123456"
}
```

**Success (200)**:

```json
{
  "verified": true
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

**Max attempts exceeded (429)**:

```json
{
  "verified": false,
  "error": "MAX_ATTEMPTS_EXCEEDED"
}
```

**Expired OTP (410)**:

```json
{
  "verified": false,
  "error": "OTP_EXPIRED"
}
```

**Session not found (404)**:

```json
{
  "verified": false,
  "error": "OTP_SESSION_NOT_FOUND"
}
```

## cURL Examples

### Send OTP

```bash
curl -X POST http://localhost:3000/send-otp \
  -H "Content-Type: application/json" \
  -d '{"aadhaar":"123456789012"}'
```

### Verify OTP

```bash
curl -X POST http://localhost:3000/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"otp":"123456"}'
```

### Resend OTP

```bash
curl -X POST http://localhost:3000/resend-otp \
  -H "Content-Type: application/json" \
  -d '{"aadhaar":"123456789012"}'
```

## Telegram Setup Notes

- Create a bot via [@BotFather](https://t.me/BotFather) and copy bot token.
- Get your numeric chat ID and set `CHAT_ID`.
- Ensure your bot can send messages to that chat.

## Render Deployment

1. Push this project to GitHub.
2. In Render, click **New +** -> **Web Service**.
3. Connect your repo.
4. Use:
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
5. Add environment variables in Render dashboard:
   - `BOT_TOKEN`
   - `CHAT_ID`
   - `PORT` (optional on Render; Render usually injects this automatically)
6. Deploy.

Recommended health endpoint for monitoring: `GET /health`.

## Security and Production Notes

- Do not commit `.env` to source control.
- OTP sessions are currently in-memory and reset when server restarts.
- Verification links request flow by client IP so `verify-otp` can work without Aadhaar in the verify payload.
- For horizontally scaled production, move sessions to Redis or a database.
- Keep `BOT_TOKEN` and `CHAT_ID` only in environment variables.
