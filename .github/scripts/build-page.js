const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Capture build time at execution
const buildTimeIso = new Date().toISOString();

// Static salt for key derivation (PBKDF2 requirement)
const SALT_STRING = "deadman-switch-pbkdf2-salt";
const PBKDF2_ITERATIONS = 600000;

// 1. Read key inputs from environment variables
const rawKeys = process.env.ENCRYPTION_KEYS || '';
const secretUrl = process.env.SECRET_URL || '';
const pushoverUser = process.env.PUSHOVER_USER_KEY || '';
const pushoverToken = process.env.PUSHOVER_TOKEN || '';

// 2. Read timestamp from process.env
const rawTimestamp = process.env.LAST_RESET_TIMESTAMP || '';

if (!rawKeys) {
  console.error('Error: ENCRYPTION_KEYS environment variable is not set.');
  process.exit(1);
}

if (!secretUrl) {
  console.error('Error: SECRET_URL environment variable is not set.');
  process.exit(1);
}

// 3. Fallback and sanitize timestamp string
let lastReset;
if (rawTimestamp) {
  const cleanIsoString = rawTimestamp.trim().replace(' ', 'T');
  lastReset = new Date(cleanIsoString);
} else {
  console.warn('Warning: LAST_RESET_TIMESTAMP not provided. Falling back to current time.');
  lastReset = new Date();
}

// Compute diff in days
const now = new Date();
const diffMs = now.getTime() - lastReset.getTime();
const diffDays = diffMs / (1000 * 60 * 60 * 24);

console.log('diffDays:', diffDays);

// Helper function to send Pushover notifications from Node build process
async function sendPushoverNotification(message) {
  if (!pushoverUser || !pushoverToken) return;
  try {
    const params = new URLSearchParams({
      token: pushoverToken,
      user: pushoverUser,
      sound: 'none',
      message: message
    });
    await fetch('https://api.pushover.net/1/messages.json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params
    });
  } catch (e) {
    console.error('Pushover notification failed:', e);
  }
}

// Daily check: Log to Pushover if reset age is between 1 and 31 days
(async () => {
  if (diffDays > 1 && diffDays < 31) {
    const remainingDays = Math.max(0, Math.ceil(7 - diffDays));
    await sendPushoverNotification(`Days to deadman timeout: ${remainingDays}`);
  }
})();

// Key derivation helper using PBKDF2-HMAC-SHA256 (600,000 iterations)
function getKeyBuffer(rawKeyString) {
  const cleanKey = rawKeyString.trim().replace(/^["']|["']$/g, '');
  if (/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
    return Buffer.from(cleanKey, 'hex');
  }
  // Derives a 32-byte (256-bit) key using PBKDF2 with 600,000 iterations
  return crypto.pbkdf2Sync(
    cleanKey,
    SALT_STRING,
    PBKDF2_ITERATIONS,
    32,
    'sha256'
  );
}

// Parse comma-separated keys
const keys = rawKeys.split(',').map(k => k.trim()).filter(k => k.length > 0);
const cryptoKeys = keys.map(getKeyBuffer);

// AES-256-GCM Encryption helper
function encrypt(text, keyBuffer) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyBuffer, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    content: encrypted.toString('hex')
  };
}

// Generate encrypted payloads
const encryptedPayloads = [];

if (diffDays >= 7) {
  // Switch expired: encrypt actual secret
  cryptoKeys.forEach(keyBuf => {
    encryptedPayloads.push(encrypt(secretUrl, keyBuf));
  });
} else {
  // Switch active: encrypt dummy payload
  cryptoKeys.forEach(keyBuf => {
    encryptedPayloads.push(encrypt("TIMER_RUNNING", keyBuf));
  });
}

// Front-end HTML layout
const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bob's Deadman Switch</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f4f9; }
    .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 400px; width: 100%; text-align: center; }
    input { width: 100%; padding: 0.5rem; margin: 1rem 0; box-sizing: border-box; }
    button { width: 100%; padding: 0.75rem; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
    button:hover { background-color: #0056b3; }
    #result { margin-top: 1rem; word-break: break-all; text-align: left; }
    .build-time { margin-top: 1.5rem; font-size: 0.75rem; color: #6c757d; text-align: center; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Bob's Deadman Switch</h2>
    <input type="password" id="keyInput" placeholder="Enter Decryption Key" />
    <button id="submitBtn" onclick="handleDecrypt()">Decrypt</button>
    <div id="result"></div>
    <div class="build-time">Page built on: <span id="buildTimeSpan"></span></div>
  </div>

  <script>
    const PAYLOADS = ${JSON.stringify(encryptedPayloads)};
    const LAST_RESET_ISO = "${lastReset.toISOString()}";
    const BUILD_TIME_ISO = "${buildTimeIso}";
    const PUSHOVER_USER = "${pushoverUser}";
    const PUSHOVER_TOKEN = "${pushoverToken}";

    const SALT_STRING = "${SALT_STRING}";
    const PBKDF2_ITERATIONS = ${PBKDF2_ITERATIONS};

    // Render formatted build time
    document.getElementById("buildTimeSpan").innerText = new Date(BUILD_TIME_ISO).toISOString().replace('T', ' ').substring(0, 16) + ' UTC';

    function hexToBytes(hex) {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
      }
      return bytes;
    }

    async function deriveCryptoKey(inputKey) {
      const cleanKey = inputKey.trim().replace(/^["']|["']$/g, '');
      let keyBytes;

      if (/^[0-9a-fA-F]{64}$/.test(cleanKey)) {
        keyBytes = hexToBytes(cleanKey);
      } else {
        const encoder = new TextEncoder();
        const passphraseBytes = encoder.encode(cleanKey);
        const saltBytes = encoder.encode(SALT_STRING);

        const baseKey = await window.crypto.subtle.importKey(
          "raw", passphraseBytes, { name: "PBKDF2" }, false, ["deriveBits"]
        );

        const derivedBits = await window.crypto.subtle.deriveBits(
          {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
          },
          baseKey,
          256
        );
        keyBytes = new Uint8Array(derivedBits);
      }

      return await window.crypto.subtle.importKey(
        "raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]
      );
    }

    async function decryptMessage(payload, cryptoKey) {
      try {
        const iv = hexToBytes(payload.iv);
        const tag = hexToBytes(payload.tag);
        const content = hexToBytes(payload.content);
        
        const cipherText = new Uint8Array(content.length + tag.length);
        cipherText.set(content);
        cipherText.set(tag, content.length);

        const decrypted = await window.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv, tagLength: 128 },
          cryptoKey,
          cipherText
        );
        return new TextDecoder().decode(decrypted);
      } catch (e) {
        return null;
      }
    }

    async function logToPushover(logResult) {
      if (!PUSHOVER_USER || !PUSHOVER_TOKEN) return;
      try {
        const params = new URLSearchParams({
          token: PUSHOVER_TOKEN,
          user: PUSHOVER_USER,
          sound: 'none',
          message: \`Deadman Switch Access Attempt\\n\${logResult}\`
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
      const keyInputEl = document.getElementById("keyInput");
      const submitBtnEl = document.getElementById("submitBtn");
      const rawKeyInput = keyInputEl.value;
      const keyInput = rawKeyInput.trim();
      const resultDiv = document.getElementById("result");
      resultDiv.innerHTML = "Processing...";

      const keyPrefix = keyInput.length > 0 ? keyInput.substring(0, 5) : "EMPTY";

      if (!keyInput) {
        resultDiv.innerText = "Decryption key is not valid";
        logToPushover(\`Key Prefix: \${keyPrefix}\\nResult: Decryption key is not valid\`);
        return;
      }

      let decryptedMessage = null;
      try {
        const cryptoKey = await deriveCryptoKey(keyInput);
        for (const p of PAYLOADS) {
          const msg = await decryptMessage(p, cryptoKey);
          if (msg !== null) {
            decryptedMessage = msg;
            break;
          }
        }
      } catch (err) {
        decryptedMessage = null;
      }

      let logMessage = "";

      if (!decryptedMessage) {
        resultDiv.innerText = "Decryption key is not valid";
        logMessage = \`Key Prefix: \${keyPrefix}\\nResult: Decryption key is not valid\`;
      } else if (decryptedMessage === "TIMER_RUNNING") {
        keyInputEl.style.display = 'none';
        submitBtnEl.style.display = 'none';

        const lastResetDate = new Date(LAST_RESET_ISO);
        const buildTimeDate = new Date(BUILD_TIME_ISO);
        const userNow = new Date();

        const targetRevealTime = new Date(lastResetDate.getTime() + (7 * 24 * 60 * 60 * 1000) + (buildTimeDate.getTime() + (24 * 60 * 60 * 1000) - userNow.getTime()));
        const diff = targetRevealTime - userNow;

        if (diff <= 0) {
          resultDiv.innerHTML = "Timer pending daily refresh.<br><br>Try again then.";
          logMessage = \`Key Prefix: \${keyPrefix}\\nResult: TIMER_RUNNING\\nTime remaining: Timer pending daily refresh\`;
        } else {
          const days = Math.floor(diff / (1000 * 60 * 60 * 24));
          const hours = Math.floor((diff / (1000 * 60 * 60)) % 24);
          const mins = Math.floor((diff / 1000 / 60) % 60);

          const timeRemainingStr = \`\${days} days \${hours} hours \${mins} minutes\`;
          const dateStr = lastResetDate.toISOString().replace('T', ' ').substring(0, 16);
          
          resultDiv.innerHTML = \`Last reset on \${dateStr} UTC.<br>Time remaining: \${timeRemainingStr}<br><br>Try again then.\`;
          logMessage = \`Key Prefix: \${keyPrefix}\\nResult: TIMER_RUNNING\\nTime remaining: \${timeRemainingStr}\`;
        }
      } else {
        logMessage = \`Key Prefix: \${keyPrefix}\\nResult: SUCCESS (SECRET_URL REDACTED)\`;
        resultDiv.innerHTML = \`You can now <a href="\${decryptedMessage}">download the required files</a>.\`;
      }

      logToPushover(logMessage);
    }
  </script>
</body>
</html>`;

fs.writeFileSync(path.join(__dirname, '../../index.html'), htmlContent);
console.log('Successfully generated index.html');
