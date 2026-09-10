const fs = require('fs');
const crypto = require('crypto');

const keysString = process.env.ENCRYPTION_KEYS || '';
const secretUrl = process.env.SECRET_URL || '';
const pushoverUser = process.env.PUSHOVER_USER_KEY || '';
const pushoverToken = process.env.PUSHOVER_TOKEN || '';
const stateFile = './state.json';

// Load state
let state = { last_reset: new Date().toISOString() };
if (fs.existsSync(stateFile)) {
  state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
}

const lastReset = new Date(state.last_reset);
const now = new Date();
const diffMs = now - lastReset;
const diffDays = diffMs / (1000 * 60 * 60 * 24);

// Determine payload: If >= 7 days elapsed, reveal secret URL
const payload = diffDays >= 7 ? secretUrl : "TIMER_RUNNING";

// Helper function to send Pushover notifications from Node.js
async function sendPushoverNotification(message) {
  if (!pushoverUser || !pushoverToken) return;
  try {
    await fetch('https://api.pushover.net/1/messages.json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: pushoverToken,
        user: pushoverUser,
        message: message
      })
    });
  } catch (err) {
    console.error('Failed to send Pushover notification:', err);
  }
}

// Daily check: Log to Pushover if reset age is between 1 and 31 days
(async () => {
  if (diffDays > 1 && diffDays < 31) {
    const remainingDays = Math.max(0, Math.ceil(7 - diffDays));
    await sendPushoverNotification(`Days to deadman timeout: ${remainingDays}`);
  }
})();

// AES-256-GCM Encryption Helper
// AES-256-GCM Encryption Helper
function encrypt(text, rawKeyString) {
  const cleanKey = rawKeyString.trim();
  let keyBuffer;

  // If the key is a 64-character hex string, parse it as hex
  if (/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
    keyBuffer = Buffer.from(cleanKey, 'hex');
  } else {
    // If it's a plain text passphrase, hash it with SHA-256 to guarantee a 32-byte key
    keyBuffer = crypto.createHash('sha256').update(cleanKey).digest();
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  
  return {
    iv: iv.toString('hex'),
    content: encrypted,
    tag: tag
  };
}

// Clean and filter comma-separated keys from environment variable
const keys = keysString
  .split(',')
  .map(k => k.trim())
  .filter(Boolean);

if (keys.length === 0) {
  throw new Error("ENCRYPTION_KEYS secret is empty or missing.");
}

const encryptedPayloads = keys.map(key => encrypt(payload, key));
const keys = keysString.split(',').filter(Boolean);
const encryptedPayloads = keys.map(key => encrypt(payload, key));

const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Deadman Switch Status</title>
  <style>
    body { font-family: sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
    .box { border: 1px solid #ccc; padding: 20px; border-radius: 8px; }
    input[type="text"] { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
    button { padding: 10px 20px; cursor: pointer; }
    #result { margin-top: 20px; font-weight: bold; }
  </style>
</head>
<body>
  <div class="box">
    <h2>Deadman Switch Access</h2>
    <label for="keyInput">Enter Private Encryption Key (Hex):</label>
    <input type="text" id="keyInput" placeholder="e.g. 4f8a..."/>
    <button onclick="handleDecrypt()">Submit</button>
    <div id="result"></div>
  </div>

  <script>
    const PAYLOADS = ${JSON.stringify(encryptedPayloads)};
    const LAST_RESET_ISO = "${lastReset.toISOString()}";
    const PUSHOVER_USER = "${pushoverUser}";
    const PUSHOVER_TOKEN = "${pushoverToken}";

    async function hexToBytes(hex) {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
      }
      return bytes;
    }

    // AES-GCM Decryption (relies purely on tag verification without manual pepper checks)
    async function decryptMessage(payload, keyHex) {
      try {
        const keyBytes = await hexToBytes(keyHex);
        const cryptoKey = await window.crypto.subcrypto.importKey(
          "raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]
        );
        const iv = await hexToBytes(payload.iv);
        const tag = await hexToBytes(payload.tag);
        const content = await hexToBytes(payload.content);
        
        const cipherText = new Uint8Array(content.length + tag.length);
        cipherText.set(content);
        cipherText.set(tag, content.length);

        const decrypted = await window.crypto.subcrypto.decrypt(
          { name: "AES-GCM", iv: iv, tagLength: 128 },
          cryptoKey,
          cipherText
        );
        return new TextDecoder().decode(decrypted);
      } catch (e) {
        return null; // Automatic failure if key or tag does not match
      }
    }

    async function logToPushover(logResult) {
      if (!PUSHOVER_USER || !PUSHOVER_TOKEN) return;
      try {
        const params = new URLSearchParams({
          token: PUSHOVER_TOKEN,
          user: PUSHOVER_USER,
          message: \`Deadman Switch Access Attempt\\nResult: \${logResult}\\nTimestamp: \${new Date().toISOString()}\`
        });
        await fetch('https://api.pushover.net/1/messages.json', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: params
        });
      } catch (e) {
        console.error('Logging failed:', e);
      }
    }

    async function handleDecrypt() {
      const keyInput = document.getElementById("keyInput").value.trim();
      const resultDiv = document.getElementById("result");
      resultDiv.innerHTML = "Processing...";

      let decryptedMessage = null;
      for (const p of PAYLOADS) {
        const msg = await decryptMessage(p, keyInput);
        if (msg !== null) {
          decryptedMessage = msg;
          break;
        }
      }

      let logPayload = "Decryption key is not valid";

      if (!decryptedMessage) {
        resultDiv.innerText = "Decryption key is not valid";
      } else if (decryptedMessage === "TIMER_RUNNING") {
        logPayload = "TIMER_RUNNING";
        const lastResetDate = new Date(LAST_RESET_ISO);
        const expiryDate = new Date(lastResetDate.getTime() + (7 * 24 * 60 * 60 * 1000));
        const diff = expiryDate - new Date();

        if (diff <= 0) {
          resultDiv.innerHTML = "Timer pending daily refresh.";
        } else {
          const days = Math.floor(diff / (1000 * 60 * 60 * 24));
          const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
          const mins = Math.floor((diff / 1000 / 60) % 60);

          const dateStr = lastResetDate.toISOString().replace('T', ' ').substring(0, 16);
          resultDiv.innerHTML = \`Last reset on \${dateStr}.<br>Time remaining: \${days} days \${hours} hours \${mins} minutes\`;
        }
      } else {
        // Redact actual SECRET_URL in log payload
        logPayload = "SUCCESS (SECRET_URL REDACTED)";
        resultDiv.innerHTML = \`You can now <a href="\${decryptedMessage}">download the required files</a>.\`;
      }

      // Log submission result to Pushover
      logToPushover(logPayload);
    }
  </script>
</body>
</html>`;

fs.writeFileSync('./index.html', htmlContent);
