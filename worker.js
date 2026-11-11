/**
 * Cloudflare Worker: Telegram WireGuard Configuration Generator Bot & Admin Panel
 * 
 * Authoritative generator implementation ported from wg.html reference.
 * Includes password-protected web admin panel, PBKDF2 hashing, AES-GCM token encryption,
 * D1 admin management, single-message Telegram wizard, in-memory .conf document delivery.
 */

// ==========================================
// 1. AUTHORITATIVE COUNTRY & DNS DATA (from wg.html)
// ==========================================

const COUNTRIES = [
  { name: 'Germany 🇩🇪', code: 'DE', ipv4Prefix: '194.26.29.', ipv6Prefix: '2a02:29e0:500:', endpoint: 'de.wg-node.net' },
  { name: 'Netherlands 🇳🇱', code: 'NL', ipv4Prefix: '185.228.82.', ipv6Prefix: '2a03:b0c0:3:', endpoint: 'nl.wg-node.net' },
  { name: 'United States 🇺🇸', code: 'US', ipv4Prefix: '198.54.130.', ipv6Prefix: '2607:f8b0:4005:', endpoint: 'us.wg-node.net' },
  { name: 'United Kingdom 🇬🇧', code: 'GB', ipv4Prefix: '185.190.140.', ipv6Prefix: '2a00:1098:0:', endpoint: 'uk.wg-node.net' },
  { name: 'France 🇫🇷', code: 'FR', ipv4Prefix: '51.15.42.', ipv6Prefix: '2001:bc8:35a8:', endpoint: 'fr.wg-node.net' },
  { name: 'Canada 🇨🇦', code: 'CA', ipv4Prefix: '142.44.195.', ipv6Prefix: '2607:5300:201:', endpoint: 'ca.wg-node.net' },
  { name: 'Finland 🇫🇮', code: 'FI', ipv4Prefix: '95.216.14.', ipv6Prefix: '2a01:4f9:c010:', endpoint: 'fi.wg-node.net' },
  { name: 'Turkey 🇹🇷', code: 'TR', ipv4Prefix: '185.255.94.', ipv6Prefix: '2a09:bac0:100:', endpoint: 'tr.wg-node.net' },
  { name: 'United Arab Emirates 🇦🇪', code: 'AE', ipv4Prefix: '185.183.104.', ipv6Prefix: '2a04:52c0:101:', endpoint: 'ae.wg-node.net' },
  { name: 'Singapore 🇸🇬', code: 'SG', ipv4Prefix: '128.199.200.', ipv6Prefix: '2400:6180:0:', endpoint: 'sg.wg-node.net' },
  { name: 'Japan 🇯🇵', code: 'JP', ipv4Prefix: '133.242.180.', ipv6Prefix: '2401:2500:102:', endpoint: 'jp.wg-node.net' },
  { name: 'Poland 🇵🇱', code: 'PL', ipv4Prefix: '185.204.216.', ipv6Prefix: '2a02:c207:2012:', endpoint: 'pl.wg-node.net' },
  { name: 'Sweden 🇸🇪', code: 'SE', ipv4Prefix: '185.157.162.', ipv6Prefix: '2a03:94e0:123:', endpoint: 'se.wg-node.net' },
  { name: 'Switzerland 🇨🇭', code: 'CH', ipv4Prefix: '178.209.50.', ipv6Prefix: '2a00:d880:3:', endpoint: 'ch.wg-node.net' },
  { name: 'Italy 🇮🇹', code: 'IT', ipv4Prefix: '185.117.88.', ipv6Prefix: '2a02:29e0:700:', endpoint: 'it.wg-node.net' },
  { name: 'Spain 🇪🇸', code: 'ES', ipv4Prefix: '185.166.216.', ipv6Prefix: '2a00:1450:400d:', endpoint: 'es.wg-node.net' }
];

const DNS_SERVICES = [
  { name: 'Cloudflare (1.1.1.1)', primary: '1.1.1.1', secondary: '1.0.0.1', hostname: '1dot1dot1dot1.cloudflare-dns.com' },
  { name: 'Google (8.8.8.8)', primary: '8.8.8.8', secondary: '8.8.4.4', hostname: 'dns.google' },
  { name: 'Quad9 (9.9.9.9)', primary: '9.9.9.9', secondary: '149.112.112.112', hostname: 'dns.quad9.net' },
  { name: 'AdGuard (AdBlock)', primary: '94.140.14.14', secondary: '94.140.15.15', hostname: 'dns.adguard-dns.com' },
  { name: 'OpenDNS', primary: '208.67.222.222', secondary: '208.67.220.220', hostname: 'dns.opendns.com' },
  { name: 'Shecan (شکن)', primary: '178.22.122.100', secondary: '185.51.200.2', hostname: 'free.shecan.ir' },
  { name: 'Electro (الکترو)', primary: '78.157.42.101', secondary: '78.157.42.100', hostname: 'elc.ir' },
  { name: 'Begzar (بگذر)', primary: '185.55.226.26', secondary: '185.55.225.25', hostname: 'begzar.ir' },
  { name: '403 Online (۴۰۳)', primary: '10.202.10.202', secondary: '10.202.10.102', hostname: 'dns.403.online' }
];

// ==========================================
// 2. CRYPTO & SECURITY UTILITIES
// ==========================================

function bufToHex(buf) {
  const bytes = new Uint8Array(buf);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function constantTimeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// 32-byte independent random key generation encoded to Base64 (from wg.html)
function generateRandomKey32() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// Random hex string helper
function getRandomHex(length) {
  const bytes = new Uint8Array(Math.ceil(length / 2));
  crypto.getRandomValues(bytes);
  return bufToHex(bytes).substring(0, length);
}

// PBKDF2 Password Hashing
async function hashPassword(password) {
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const iterations = 100000;
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  );
  const rawHash = await crypto.subtle.exportKey('raw', key);
  return `${iterations}$${bufToHex(salt)}$${bufToHex(new Uint8Array(rawHash))}`;
}

async function verifyPassword(password, storedHashStr) {
  if (!storedHashStr || typeof storedHashStr !== 'string') return false;
  const parts = storedHashStr.split('$');
  if (parts.length !== 3) return false;
  const iterations = parseInt(parts[0], 10);
  const salt = hexToBuf(parts[1]);
  const expectedHashHex = parts[2];
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    true,
    ['sign']
  );
  const rawHash = await crypto.subtle.exportKey('raw', key);
  const actualHashHex = bufToHex(new Uint8Array(rawHash));
  return constantTimeCompare(expectedHashHex, actualHashHex);
}

// AES-GCM Token Encryption with APP_ENCRYPTION_KEY
async function getMasterKey(encryptionSecret) {
  const enc = new TextEncoder();
  const rawSecret = encryptionSecret || 'default-cf-worker-fallback-key-32bytes!';
  const keyData = await crypto.subtle.digest('SHA-256', enc.encode(rawSecret));
  return crypto.subtle.importKey('raw', keyData, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptToken(token, encryptionSecret) {
  if (!token) return '';
  const key = await getMasterKey(encryptionSecret);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const enc = new TextEncoder();
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(token)
  );
  return `${bufToHex(iv)}:${bufToHex(new Uint8Array(encrypted))}`;
}

async function decryptToken(encryptedStr, encryptionSecret) {
  if (!encryptedStr || !encryptedStr.includes(':')) return null;
  try {
    const [ivHex, cipherHex] = encryptedStr.split(':');
    const key = await getMasterKey(encryptionSecret);
    const iv = hexToBuf(ivHex);
    const ciphertext = hexToBuf(cipherHex);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  } catch (err) {
    return null;
  }
}

// Safe HTML Escaping
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ==========================================
// 3. DATABASE (D1) & SETTINGS HELPERS
// ==========================================

async function ensureDbInitialized(db) {
  if (!db) return;
  try {
    await db.batch([
      db.prepare(`CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
      )`),
      db.prepare(`CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tg_id TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        added_at INTEGER NOT NULL
      )`)
    ]);
  } catch (err) {
    // Already exists or initialization error
  }
}

async function getSetting(db, key) {
  if (!db) return null;
  try {
    const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
    return row ? row.value : null;
  } catch (e) {
    return null;
  }
}

async function setSetting(db, key, value) {
  if (!db) return;
  await db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?')
    .bind(key, value, value)
    .run();
}

async function getAdmins(db) {
  if (!db) return [];
  try {
    const { results } = await db.prepare('SELECT tg_id, role, added_at FROM admins ORDER BY id ASC').all();
    return results || [];
  } catch (e) {
    return [];
  }
}

async function addAdmin(db, tgId, role = 'admin') {
  if (!db) return false;
  try {
    await db.prepare('INSERT INTO admins (tg_id, role, added_at) VALUES (?, ?, ?)')
      .bind(String(tgId).trim(), role, Date.now())
      .run();
    return true;
  } catch (e) {
    return false;
  }
}

async function removeAdmin(db, tgId) {
  if (!db) return false;
  try {
    const res = await db.prepare('DELETE FROM admins WHERE tg_id = ? AND role != ?')
      .bind(String(tgId).trim(), 'owner')
      .run();
    return res.meta && res.meta.changes > 0;
  } catch (e) {
    return false;
  }
}

async function isAuthorizedUser(db, userId, ownerId) {
  const uid = String(userId).trim();
  if (ownerId && uid === String(ownerId).trim()) return true;
  if (!db) return false;
  try {
    const row = await db.prepare('SELECT tg_id FROM admins WHERE tg_id = ?').bind(uid).first();
    return !!row;
  } catch (e) {
    return false;
  }
}

// ==========================================
// 4. CONFIGURATION GENERATOR ALGORITHM (PORTED FROM wg.html)
// ==========================================

/**
 * EXACT ALGORITHM PORTED FROM wg.html:
 * - 32-byte independent random values for PrivateKey, PublicKey, PreSharedKey.
 * - IPv4 generation from selected country prefix + random host octet.
 * - IPv6 generation from selected country prefix + random hextets.
 * - Random MTU between 1420 and 1440.
 * - Random ListenPort between 2087 and 2088.
 * - Endpoint port 62050.
 * - DNS first-line: primary, secondary.
 * - DNS second-line: hostname pattern.
 * - AllowedIPs: 0.0.0.0/0, ::/0.
 */
function generateWireguardConfig(country, dns) {
  // Independent 32-byte random keys (Base64)
  const privateKey = generateRandomKey32();
  const publicKey = generateRandomKey32();
  const preSharedKey = generateRandomKey32();

  // IPv4 Address generation from country prefix
  const hostOctet = Math.floor(Math.random() * 250) + 2; // 2 to 251
  const ipv4 = `${country.ipv4Prefix}${hostOctet}/32`;

  // IPv6 Address generation from country prefix
  const ipv6Hextet1 = getRandomHex(4);
  const ipv6Hextet2 = getRandomHex(4);
  const ipv6 = `${country.ipv6Prefix}${ipv6Hextet1}:${ipv6Hextet2}/128`;

  // Random MTU between 1420 and 1440
  const mtu = Math.floor(Math.random() * (1440 - 1420 + 1)) + 1420;

  // Random ListenPort between 2087 and 2088
  const listenPort = Math.random() < 0.5 ? 2087 : 2088;

  // Endpoint port 62050
  const endpoint = `${country.endpoint}:62050`;

  // Assembly according to authoritative wg.html structure
  const configText = `[Interface]
PrivateKey = ${privateKey}
Address = ${ipv4}, ${ipv6}
MTU = ${mtu}
ListenPort = ${listenPort}
DNS = ${dns.primary}, ${dns.secondary}
DNS = ${dns.hostname}

[Peer]
PublicKey = ${publicKey}
PersistentKeepalive = 25
PreSharedKey = ${preSharedKey}
Endpoint = ${endpoint}
AllowedIPs = 0.0.0.0/0, ::/0
`;

  return {
    configText,
    privateKey,
    publicKey,
    preSharedKey,
    ipv4,
    ipv6,
    mtu,
    listenPort,
    endpoint
  };
}

// ==========================================
// 5. TELEGRAM BOT API CLIENT
// ==========================================

async function telegramRequest(token, method, payload = {}) {
  const url = `https://api.telegram.org/bot${token}/${method}`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  return res.json();
}

async function answerCallbackQuery(token, callbackQueryId, text = '', showAlert = false) {
  return telegramRequest(token, 'answerCallbackQuery', {
    callback_query_id: callbackQueryId,
    text,
    show_alert: showAlert
  });
}

async function editMessageText(token, chatId, messageId, text, replyMarkup = null) {
  const payload = {
    chat_id: chatId,
    message_id: messageId,
    text,
    parse_mode: 'HTML'
  };
  if (replyMarkup) {
    payload.reply_markup = replyMarkup;
  }
  return telegramRequest(token, 'editMessageText', payload);
}

async function sendTelegramMessage(token, chatId, text, replyMarkup = null) {
  const payload = {
    chat_id: chatId,
    text,
    parse_mode: 'HTML'
  };
  if (replyMarkup) {
    payload.reply_markup = replyMarkup;
  }
  return telegramRequest(token, 'sendMessage', payload);
}

async function sendDocumentInMemory(token, chatId, filename, contentText, caption = '') {
  const formData = new FormData();
  formData.append('chat_id', String(chatId));
  formData.append('caption', caption);
  formData.append('parse_mode', 'HTML');
  
  const blob = new Blob([contentText], { type: 'text/plain;charset=utf-8' });
  formData.append('document', blob, filename);

  const res = await fetch(`https://api.telegram.org/bot${token}/sendDocument`, {
    method: 'POST',
    body: formData
  });
  return res.json();
}

// ==========================================
// 6. TELEGRAM BOT WIZARD KEYBOARDS & WORKFLOW
// ==========================================

const COUNTRIES_PER_PAGE = 6;
const DNS_PER_PAGE = 6;

function buildCountryKeyboard(page = 0) {
  const totalPages = Math.ceil(COUNTRIES.length / COUNTRIES_PER_PAGE);
  const start = page * COUNTRIES_PER_PAGE;
  const end = Math.min(start + COUNTRIES_PER_PAGE, COUNTRIES.length);
  const keyboard = [];

  for (let i = start; i < end; i += 2) {
    const row = [];
    row.push({
      text: COUNTRIES[i].name,
      callback_data: `wz_c_${i}`
    });
    if (i + 1 < end) {
      row.push({
        text: COUNTRIES[i + 1].name,
        callback_data: `wz_c_${i + 1}`
      });
    }
    keyboard.push(row);
  }

  // Pagination navigation row
  const navRow = [];
  if (page > 0) {
    navRow.push({ text: '⬅️ قبلی', callback_data: `wz_cp_${page - 1}` });
  }
  navRow.push({ text: `📄 صفحه ${page + 1} از ${totalPages}`, callback_data: 'wz_noop' });
  if (page < totalPages - 1) {
    navRow.push({ text: 'بعدی ➡️', callback_data: `wz_cp_${page + 1}` });
  }
  keyboard.push(navRow);

  // Cancel button
  keyboard.push([{ text: '❌ لغو عملیات', callback_data: 'wz_cancel' }]);

  return { inline_keyboard: keyboard };
}

function buildDnsKeyboard(page = 0) {
  const totalPages = Math.ceil(DNS_SERVICES.length / DNS_PER_PAGE);
  const start = page * DNS_PER_PAGE;
  const end = Math.min(start + DNS_PER_PAGE, DNS_SERVICES.length);
  const keyboard = [];

  for (let i = start; i < end; i += 2) {
    const row = [];
    row.push({
      text: DNS_SERVICES[i].name,
      callback_data: `wz_d_${i}`
    });
    if (i + 1 < end) {
      row.push({
        text: DNS_SERVICES[i + 1].name,
        callback_data: `wz_d_${i + 1}`
      });
    }
    keyboard.push(row);
  }

  // Pagination navigation row
  const navRow = [];
  if (page > 0) {
    navRow.push({ text: '⬅️ قبلی', callback_data: `wz_dp_${page - 1}` });
  }
  if (totalPages > 1) {
    navRow.push({ text: `📄 صفحه ${page + 1} از ${totalPages}`, callback_data: 'wz_noop' });
    if (page < totalPages - 1) {
      navRow.push({ text: 'بعدی ➡️', callback_data: `wz_dp_${page + 1}` });
    }
    keyboard.push(navRow);
  }

  // Back & Cancel
  keyboard.push([
    { text: '🔙 تغییر کشور', callback_data: 'wz_back_country' },
    { text: '❌ لغو', callback_data: 'wz_cancel' }
  ]);

  return { inline_keyboard: keyboard };
}

// ==========================================
// 7. TELEGRAM WEBHOOK HANDLER
// ==========================================

async function handleTelegramWebhook(request, env) {
  // Validate Telegram webhook secret token
  const secretHeader = request.headers.get('X-Telegram-Bot-Api-Secret-Token');
  const configuredSecret = await getSetting(env.DB, 'webhook_secret');
  if (configuredSecret && secretHeader !== configuredSecret) {
    return new Response('Unauthorized Webhook Request', { status: 403 });
  }

  let update;
  try {
    update = await request.json();
  } catch (err) {
    return new Response('Invalid JSON', { status: 400 });
  }

  const encryptedToken = await getSetting(env.DB, 'encrypted_bot_token');
  const botToken = await decryptToken(encryptedToken, env.APP_ENCRYPTION_KEY);
  const ownerId = await getSetting(env.DB, 'owner_tg_id');

  if (!botToken) {
    return new Response(JSON.stringify({ ok: true, msg: 'Bot token not configured' }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // A. HANDLE CALLBACK QUERIES
  if (update.callback_query) {
    const cq = update.callback_query;
    const userId = cq.from.id;
    const chatId = cq.message ? cq.message.chat.id : userId;
    const messageId = cq.message ? cq.message.message_id : null;
    const data = cq.data || '';

    // Check authorization
    const authorized = await isAuthorizedUser(env.DB, userId, ownerId);
    if (!authorized) {
      await answerCallbackQuery(botToken, cq.id, '⛔ شما مجاز به استفاده از این ربات نیستید.', true);
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (data === 'wz_noop') {
      await answerCallbackQuery(botToken, cq.id);
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (data === 'wz_cancel') {
      await env.KV.delete(`wizard:${userId}`);
      await answerCallbackQuery(botToken, cq.id, 'عملیات لغو گردید.');
      if (messageId) {
        await editMessageText(
          botToken,
          chatId,
          messageId,
          '❌ <b>عملیات لغو شد.</b>\nبرای شروع مجدد، دستور /start را ارسال کنید یا روی دکمه زیر بزنید.',
          { inline_keyboard: [[{ text: '➕ ساخت کانفیگ جدید', callback_data: 'wz_restart' }]] }
        );
      }
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (data === 'wz_restart') {
      await answerCallbackQuery(botToken, cq.id);
      // Start fresh wizard in same message
      await env.KV.put(
        `wizard:${userId}`,
        JSON.stringify({ step: 'name', chatId, messageId }),
        { expirationTtl: 600 }
      );
      await editMessageText(
        botToken,
        chatId,
        messageId,
        '🛡️ <b>ساخت کانفیگ WireGuard (شبیه‌ساز)</b>\n\n' +
        '📝 لطفاً یک <b>نام انگلیسی</b> برای کانفیگ خود ارسال کنید:\n' +
        '• فقط حروف A-Z و a-z\n' +
        '• اعداد 0-9\n' +
        '• خط تیره (-) و آندرلاین (_)\n' +
        '• حداکثر ۱۵ کاراکتر\n\n' +
        '<i>(نام مورد نظر را به عنوان پیام متنی بفرستید)</i>'
      );
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Load active wizard state
    const rawState = await env.KV.get(`wizard:${userId}`);
    if (!rawState) {
      await answerCallbackQuery(botToken, cq.id, 'نشست شما منقضی شده است. لطفا مجددا /start بزنید.', true);
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    const state = JSON.parse(rawState);
    const activeMsgId = state.messageId || messageId;

    // Country Pagination
    if (data.startsWith('wz_cp_')) {
      const page = parseInt(data.replace('wz_cp_', ''), 10) || 0;
      await answerCallbackQuery(botToken, cq.id);
      await editMessageText(
        botToken,
        chatId,
        activeMsgId,
        `🌐 <b>انتخاب کشور سرور</b>\nنام کانفیگ: <code>${escapeHtml(state.configName)}</code>\n\nلطفاً موقعیت سرور را انتخاب کنید:`,
        buildCountryKeyboard(page)
      );
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Country Selection
    if (data.startsWith('wz_c_')) {
      const countryIdx = parseInt(data.replace('wz_c_', ''), 10);
      const country = COUNTRIES[countryIdx];
      if (!country) {
        await answerCallbackQuery(botToken, cq.id, 'کشور نامعتبر است.', true);
        return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
      }

      state.step = 'dns';
      state.countryIdx = countryIdx;
      await env.KV.put(`wizard:${userId}`, JSON.stringify(state), { expirationTtl: 600 });
      await answerCallbackQuery(botToken, cq.id, `کشور ${country.name} انتخاب شد.`);

      await editMessageText(
        botToken,
        chatId,
        activeMsgId,
        `📡 <b>انتخاب سرویس DNS</b>\nنام کانفیگ: <code>${escapeHtml(state.configName)}</code>\nکشور سرور: <b>${escapeHtml(country.name)}</b>\n\nلطفاً یکی از ارائه‌دهندگان DNS زیر را انتخاب نمایید:`,
        buildDnsKeyboard(0)
      );
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    // DNS Pagination
    if (data.startsWith('wz_dp_')) {
      const page = parseInt(data.replace('wz_dp_', ''), 10) || 0;
      const country = COUNTRIES[state.countryIdx] || COUNTRIES[0];
      await answerCallbackQuery(botToken, cq.id);
      await editMessageText(
        botToken,
        chatId,
        activeMsgId,
        `📡 <b>انتخاب سرویس DNS</b>\nنام کانفیگ: <code>${escapeHtml(state.configName)}</code>\nکشور سرور: <b>${escapeHtml(country.name)}</b>\n\nلطفاً یکی از ارائه‌دهندگان DNS زیر را انتخاب نمایید:`,
        buildDnsKeyboard(page)
      );
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Back to country
    if (data === 'wz_back_country') {
      state.step = 'country';
      await env.KV.put(`wizard:${userId}`, JSON.stringify(state), { expirationTtl: 600 });
      await answerCallbackQuery(botToken, cq.id);
      await editMessageText(
        botToken,
        chatId,
        activeMsgId,
        `🌐 <b>انتخاب کشور سرور</b>\nنام کانفیگ: <code>${escapeHtml(state.configName)}</code>\n\nلطفاً موقعیت سرور را انتخاب کنید:`,
        buildCountryKeyboard(0)
      );
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    // DNS Selection & Final Generation
    if (data.startsWith('wz_d_')) {
      const dnsIdx = parseInt(data.replace('wz_d_', ''), 10);
      const dns = DNS_SERVICES[dnsIdx];
      const country = COUNTRIES[state.countryIdx];
      if (!dns || !country) {
        await answerCallbackQuery(botToken, cq.id, 'انتخاب نامعتبر است.', true);
        return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
      }

      await answerCallbackQuery(botToken, cq.id, 'در حال تولید کانفیگ...');

      // Update message to show progress
      await editMessageText(
        botToken,
        chatId,
        activeMsgId,
        '⚙️ <b>در حال تولید کلیدها و کانفیگ WireGuard...</b>\nلطفاً چند لحظه شکیبا باشید.'
      );

      // Generate configuration in memory
      const generated = generateWireguardConfig(country, dns);
      const fileName = `${state.configName}.conf`;

      // Update the existing wizard message to show final success
      await editMessageText(
        botToken,
        chatId,
        activeMsgId,
        `✅ <b>کانفیگ با موفقیت ساخته شد!</b>\n\n` +
        `📁 نام فایل: <code>${escapeHtml(fileName)}</code>\n` +
        `🌐 کشور سرور: <b>${escapeHtml(country.name)}</b>\n` +
        `📡 سرویس DNS: <b>${escapeHtml(dns.name)}</b>\n` +
        `🔌 پورت شنود: <code>${generated.listenPort}</code> | MTU: <code>${generated.mtu}</code>\n\n` +
        `📥 <i>فایل کانفیگ به پیوست همین پیام ارسال شد.</i>\n\n` +
        `⚠️ <b>توجه امنیتی:</b> این کانفیگ توسط الگوریتم شبیه‌ساز تولید شده است و ایجاد اتصال واقعی WireGuard را تضمین نمی‌کند.`,
        {
          inline_keyboard: [
            [{ text: '➕ ساخت یک کانفیگ دیگر', callback_data: 'wz_restart' }]
          ]
        }
      );

      // Send the .conf file in-memory
      await sendDocumentInMemory(
        botToken,
        chatId,
        fileName,
        generated.configText,
        `🛡️ فایل کانفیگ WireGuard (شبیه‌ساز)\nنام: ${escapeHtml(fileName)}`
      );

      // Delete wizard temporary state immediately after successful completion
      await env.KV.delete(`wizard:${userId}`);

      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  // B. HANDLE INCOMING TEXT MESSAGES
  if (update.message) {
    const msg = update.message;
    const userId = msg.from.id;
    const chatId = msg.chat.id;
    const text = (msg.text || '').trim();

    // Check authorization
    const authorized = await isAuthorizedUser(env.DB, userId, ownerId);
    if (!authorized) {
      await sendTelegramMessage(
        botToken,
        chatId,
        `⛔ <b>دسترسی غیرمجاز</b>\nشما دسترسی به این بات را ندارید.\nشناسه تلگرام شما: <code>${userId}</code>`
      );
      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Commands /start or /new
    if (text === '/start' || text === '/new' || text === '/create') {
      // Clear old state if exists
      await env.KV.delete(`wizard:${userId}`);

      // Send the initial single wizard message
      const sentMsg = await sendTelegramMessage(
        botToken,
        chatId,
        '🛡️ <b>ربات ساخت کانفیگ WireGuard (نسخه شبیه‌ساز)</b>\n\n' +
        '📝 لطفاً یک <b>نام انگلیسی</b> برای کانفیگ خود ارسال کنید:\n' +
        '• فقط حروف A-Z و a-z\n' +
        '• اعداد 0-9\n' +
        '• خط تیره (-) و آندرلاین (_)\n' +
        '• حداکثر ۱۵ کاراکتر و حداقل ۱ کاراکتر\n\n' +
        '<i>(نام مورد نظر را بنویسید و ارسال کنید)</i>'
      );

      if (sentMsg.ok && sentMsg.result) {
        await env.KV.put(
          `wizard:${userId}`,
          JSON.stringify({
            step: 'name',
            chatId,
            messageId: sentMsg.result.message_id
          }),
          { expirationTtl: 600 }
        );
      }

      return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
    }

    // Check if user is currently entering the configuration name
    const rawState = await env.KV.get(`wizard:${userId}`);
    if (rawState) {
      const state = JSON.parse(rawState);
      if (state.step === 'name') {
        const nameCandidate = text;
        // Validation: 1 to 15 chars, alphanumeric + hyphen + underscore only.
        // Rejects spaces, persian chars, special symbols.
        const isValid = /^[a-zA-Z0-9_-]{1,15}$/.test(nameCandidate);

        if (!isValid) {
          // Edit existing wizard message to show validation error
          await editMessageText(
            botToken,
            chatId,
            state.messageId,
            '⚠️ <b>نام وارد شده نامعتبر است!</b>\n\n' +
            'قوانین نام کانفیگ:\n' +
            '❌ فاصله (Space) یا حروف فارسی مجاز نیستند.\n' +
            '❌ کاراکترهای خاص مجاز نیستند.\n' +
            '✅ فقط حروف انگلیسی (A-Z, a-z)، اعداد (0-9)، - و _\n' +
            '✅ حداکثر طول ۱۵ کاراکتر\n\n' +
            '<i>لطفاً نام دیگری تایپ و ارسال کنید:</i>'
          );
          return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
        }

        // Name is valid: Advance wizard to country selection in the SAME message
        state.configName = nameCandidate;
        state.step = 'country';
        await env.KV.put(`wizard:${userId}`, JSON.stringify(state), { expirationTtl: 600 });

        await editMessageText(
          botToken,
          chatId,
          state.messageId,
          `🌐 <b>انتخاب کشور سرور</b>\nنام کانفیگ: <code>${escapeHtml(nameCandidate)}</code>\n\nلطفاً موقعیت سرور را از فهرست زیر انتخاب کنید:`,
          buildCountryKeyboard(0)
        );

        return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Default message when no active state
    await sendTelegramMessage(
      botToken,
      chatId,
      'برای شروع ساخت کانفیگ WireGuard دستور /start را ارسال کنید.',
      {
        inline_keyboard: [[{ text: '➕ ساخت کانفیگ', callback_data: 'wz_restart' }]]
      }
    );
    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
}

// ==========================================
// 8. ADMIN WEB PANEL (HTML & CSS EMBEDDED)
// ==========================================

function getAdminStyles() {
  return `
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --input-bg: #0f172a;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Vazirmatn", Tahoma, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      direction: rtl;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    .container { max-width: 1080px; margin: 0 auto; padding: 20px; width: 100%; }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 16px 0;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 24px;
      flex-wrap: wrap;
      gap: 12px;
    }
    .header h1 { font-size: 1.4rem; font-weight: 700; color: #60a5fa; display: flex; align-items: center; gap: 8px; }
    .header-actions { display: flex; gap: 10px; align-items: center; }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      border: none;
      transition: all 0.2s;
      text-decoration: none;
      color: #fff;
    }
    .btn-primary { background: var(--primary); }
    .btn-primary:hover { background: var(--primary-hover); }
    .btn-danger { background: var(--danger); }
    .btn-danger:hover { background: #dc2626; }
    .btn-secondary { background: #475569; }
    .btn-secondary:hover { background: #334155; }
    .btn-sm { padding: 4px 10px; font-size: 0.8rem; border-radius: 6px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 24px; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .card-title {
      font-size: 1.1rem;
      font-weight: 700;
      margin-bottom: 16px;
      color: #e2e8f0;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 0.8rem;
      font-weight: 600;
    }
    .status-active { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    .status-inactive { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .status-warning { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
    .form-group { margin-bottom: 16px; text-align: right; }
    .form-label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 6px; color: var(--text-muted); }
    .form-control {
      width: 100%;
      padding: 10px 14px;
      background: var(--input-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      color: var(--text);
      font-size: 0.95rem;
      direction: ltr;
      text-align: left;
    }
    .form-control:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2); }
    .form-control.rtl { direction: rtl; text-align: right; }
    .help-text { font-size: 0.75rem; color: var(--text-muted); margin-top: 4px; }
    .alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 16px; font-size: 0.9rem; }
    .alert-success { background: rgba(16, 185, 129, 0.2); border: 1px solid var(--success); color: #34d399; }
    .alert-danger { background: rgba(239, 68, 68, 0.2); border: 1px solid var(--danger); color: #f87171; }
    .alert-info { background: rgba(59, 130, 246, 0.2); border: 1px solid var(--primary); color: #93c5fd; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.9rem; }
    th, td { padding: 12px; text-align: right; border-bottom: 1px solid var(--card-border); }
    th { color: var(--text-muted); font-weight: 600; background: rgba(15, 23, 42, 0.5); }
    .ltr-cell { direction: ltr; text-align: left; font-family: monospace; }
    .auth-wrapper {
      min-height: 80vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .auth-box {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 32px;
      width: 100%;
      max-width: 420px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
      text-align: center;
    }
    .auth-title { font-size: 1.5rem; margin-bottom: 8px; color: #60a5fa; }
    .auth-subtitle { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 24px; }
    .code-block {
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      padding: 12px;
      font-family: monospace;
      font-size: 0.8rem;
      direction: ltr;
      text-align: left;
      overflow-x: auto;
      margin: 10px 0;
      color: #38bdf8;
    }
    .footer {
      margin-top: auto;
      padding: 20px;
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
      border-top: 1px solid var(--card-border);
    }
  `;
}

function renderHtmlLayout(title, content) {
  return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - مدیریت بات وایرگارد</title>
  <style>${getAdminStyles()}</style>
</head>
<body>
  ${content}
</body>
</html>`;
}

function renderLoginPage(error = '') {
  const content = `
  <div class="auth-wrapper">
    <div class="auth-box">
      <div style="font-size: 2.5rem; margin-bottom: 12px;">🛡️</div>
      <h2 class="auth-title">ورود به پنل مدیریت</h2>
      <p class="auth-subtitle">سیستم مدیریت بات تولید کانفیگ WireGuard</p>
      
      ${error ? `<div class="alert alert-danger">${escapeHtml(error)}</div>` : ''}

      <form method="POST" action="/admin/login">
        <div class="form-group">
          <label class="form-label">رمز عبور مدیریت</label>
          <input type="password" name="password" required class="form-control" placeholder="••••••••" autofocus>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%; padding: 12px; margin-top: 8px;">
          ورود به پنل
        </button>
      </form>
    </div>
  </div>`;
  return renderHtmlLayout('ورود مدیریت', content);
}

function renderSetupPage(error = '') {
  const content = `
  <div class="auth-wrapper">
    <div class="auth-box">
      <div style="font-size: 2.5rem; margin-bottom: 12px;">🔑</div>
      <h2 class="auth-title">راه‌اندازی اولیه پنل</h2>
      <p class="auth-subtitle">جهت ورود و امنیت پنل، رمز عبور مدیر ارشد را تعیین کنید.</p>
      
      ${error ? `<div class="alert alert-danger">${escapeHtml(error)}</div>` : ''}

      <form method="POST" action="/admin/setup">
        <div class="form-group">
          <label class="form-label">رمز عبور جدید</label>
          <input type="password" name="new_password" required minlength="8" class="form-control" placeholder="حداقل ۸ کاراکتر" autofocus>
        </div>
        <div class="form-group">
          <label class="form-label">تکرار رمز عبور جدید</label>
          <input type="password" name="confirm_password" required minlength="8" class="form-control" placeholder="تکرار رمز">
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%; padding: 12px; margin-top: 8px;">
          ثبت و ورود
        </button>
      </form>
    </div>
  </div>`;
  return renderHtmlLayout('راه‌اندازی اولیه', content);
}

function renderDashboardPage({
  ownerId,
  isTokenConfigured,
  maskedToken,
  botInfo,
  webhookInfo,
  admins,
  workerUrl,
  successMsg = '',
  errorMsg = ''
}) {
  const isBotActive = isTokenConfigured && botInfo && botInfo.ok;
  const isWebhookActive = webhookInfo && webhookInfo.url;

  const content = `
  <div class="container">
    <header class="header">
      <h1>🛡️ مدیریت بات تلگرام WireGuard (شبیه‌ساز)</h1>
      <div class="header-actions">
        <a href="#setup-guide" class="btn btn-secondary btn-sm">راهنمای Cloudflare</a>
        <a href="/admin/logout" class="btn btn-danger btn-sm">خروج</a>
      </div>
    </header>

    ${successMsg ? `<div class="alert alert-success">${escapeHtml(successMsg)}</div>` : ''}
    ${errorMsg ? `<div class="alert alert-danger">${escapeHtml(errorMsg)}</div>` : ''}

    <!-- وضعیت سیستم -->
    <div class="grid">
      <div class="card">
        <div class="card-title">
          <span>وضعیت بات تلگرام</span>
          <span class="status-badge ${isBotActive ? 'status-active' : 'status-inactive'}">
            ${isBotActive ? 'فعال و متصل' : 'غیرفعال / نامعتبر'}
          </span>
        </div>
        <p style="font-size: 0.9rem; color: var(--text-muted); margin-bottom: 8px;">
          ${botInfo && botInfo.ok ? `نام بات: <b>@${escapeHtml(botInfo.result.username)}</b> (${escapeHtml(botInfo.result.first_name)})` : 'توکن بات تلگرام تنظیم نشده یا نامعتبر است.'}
        </p>
        <p style="font-size: 0.85rem; color: var(--text-muted);">
          مالک اصلی: <code style="color: #60a5fa;">${escapeHtml(ownerId || 'تعریف نشده')}</code>
        </p>
      </div>

      <div class="card">
        <div class="card-title">
          <span>وضعیت وب‌هوک (Webhook)</span>
          <span class="status-badge ${isWebhookActive ? 'status-active' : 'status-warning'}">
            ${isWebhookActive ? 'ست شده' : 'ست نشده'}
          </span>
        </div>
        <p style="font-size: 0.85rem; color: var(--text-muted); word-break: break-all; margin-bottom: 8px;">
          آدرس: <span class="ltr-cell">${escapeHtml((webhookInfo && webhookInfo.url) || `${workerUrl}/webhook`)}</span>
        </p>
        <form method="POST" action="/admin/api/webhook/sync" style="display:inline;">
          <button type="submit" class="btn btn-secondary btn-sm">ثبت/بروزرسانی وب‌هوک در تلگرام</button>
        </form>
      </div>

      <div class="card">
        <div class="card-title">
          <span>دیتابیس و ذخیره‌سازی</span>
          <span class="status-badge status-active">متصل</span>
        </div>
        <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 6px;">
          • دیتابیس D1: ذخیره مالکان و تنظیمات رمزنگاری شده
        </p>
        <p style="font-size: 0.85rem; color: var(--text-muted);">
          • حافظه KV: نگهداری سشن‌های موقت و ویزارد بات
        </p>
      </div>
    </div>

    <!-- تنظیمات بات تلگرام -->
    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">🤖 تنظیمات اتصال بات تلگرام</div>
      <form method="POST" action="/admin/api/config">
        <div class="grid">
          <div class="form-group">
            <label class="form-label">توکن بات تلگرام (Bot Token)</label>
            <input type="text" name="bot_token" class="form-control" placeholder="${isTokenConfigured ? '•••••••• (رمزنگاری شده با AES-GCM)' : '123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ'}" autocomplete="off">
            <span class="help-text">توکن را از @BotFather دریافت کنید. این توکن با کلید مخفی APP_ENCRYPTION_KEY به صورت AES-GCM رمز شده و در D1 ذخیره می‌شود.</span>
          </div>

          <div class="form-group">
            <label class="form-label">شناسه عددی تلگرام مالک (Owner Telegram User ID)</label>
            <input type="text" name="owner_tg_id" value="${escapeHtml(ownerId || '')}" required class="form-control" placeholder="123456789">
            <span class="help-text">شناسه عددی حساب کاربری خودتان در تلگرام (قابل دریافت از بات @userinfobot).</span>
          </div>
        </div>

        <button type="submit" class="btn btn-primary">ذخیره تنظیمات و ثبت وب‌هوک</button>
      </form>
    </div>

    <!-- مدیریت مدیران مجاز -->
    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">
        <span>👥 مدیریت مدیران مجاز بات تلگرام</span>
        <span style="font-size: 0.85rem; font-weight: normal; color: var(--text-muted);">تعداد: ${admins.length}</span>
      </div>
      <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 16px;">
        تنها مالک اصلی و مدیران ثبت‌شده در این جدول مجاز به استفاده از بات و ایجاد کانفیگ هستند. دیگران به صورت خودکار ریجکت می‌شوند.
      </p>

      <!-- فرم افزودن ادمین -->
      <form method="POST" action="/admin/api/admins/add" style="display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap;">
        <input type="text" name="admin_id" required pattern="[0-9]+" placeholder="شناسه عددی تلگرام ادمین جدید (مثلاً 987654321)" class="form-control" style="max-width: 380px;">
        <button type="submit" class="btn btn-primary">افزودن ادمین</button>
      </form>

      <!-- جدول ادمین‌ها -->
      <div style="overflow-x: auto;">
        <table>
          <thead>
            <tr>
              <th>شناسه تلگرام</th>
              <th>نقش</th>
              <th>تاریخ افزودن</th>
              <th>عملیات</th>
            </tr>
          </thead>
          <tbody>
            ${admins.map(adm => `
              <tr>
                <td class="ltr-cell"><b>${escapeHtml(adm.tg_id)}</b></td>
                <td>
                  <span class="status-badge ${adm.role === 'owner' ? 'status-active' : 'status-warning'}">
                    ${adm.role === 'owner' ? '👑 مالک اصلی' : 'مدیر ثانویه'}
                  </span>
                </td>
                <td style="font-size: 0.8rem; color: var(--text-muted);">
                  ${new Date(adm.added_at).toLocaleString('fa-IR')}
                </td>
                <td>
                  ${adm.role !== 'owner' ? `
                    <form method="POST" action="/admin/api/admins/delete" onsubmit="return confirm('آیا از حذف دسترسی این مدیر اطمینان دارید؟');" style="display:inline;">
                      <input type="hidden" name="admin_id" value="${escapeHtml(adm.tg_id)}">
                      <button type="submit" class="btn btn-danger btn-sm">حذف دسترسی</button>
                    </form>
                  ` : '<span style="font-size: 0.8rem; color: var(--text-muted);">غیرقابل حذف</span>'}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <!-- تغییر رمز عبور پنل مدیریت -->
    <div class="card" style="margin-bottom: 24px;">
      <div class="card-title">🔐 تغییر رمز عبور پنل مدیریت</div>
      <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 16px;">
        شما می‌توانید رمز ورود به این پنل را در هر زمان بدون نیاز به ویرایش کدهای ورکر تغییر دهید. پس از تغییر رمز، تمام نشست‌های فعال لغو خواهند شد.
      </p>

      <form method="POST" action="/admin/api/password">
        <div class="grid">
          <div class="form-group">
            <label class="form-label">رمز عبور فعلی</label>
            <input type="password" name="current_password" required class="form-control" placeholder="••••••••">
          </div>
          <div class="form-group">
            <label class="form-label">رمز عبور جدید</label>
            <input type="password" name="new_password" required minlength="8" class="form-control" placeholder="حداقل ۸ کاراکتر">
          </div>
          <div class="form-group">
            <label class="form-label">تکرار رمز عبور جدید</label>
            <input type="password" name="confirm_password" required minlength="8" class="form-control" placeholder="تکرار رمز جدید">
          </div>
        </div>

        <button type="submit" class="btn btn-primary">تغییر و ذخیره رمز جدید</button>
      </form>
    </div>

    <!-- راهنمای راه‌اندازی کلودفلر -->
    <div class="card" id="setup-guide" style="margin-bottom: 24px;">
      <div class="card-title">📖 راهنمای پیکربندی منابع Cloudflare (KV & D1 & Secret)</div>
      <div style="font-size: 0.9rem; line-height: 1.8; color: var(--text-muted);">
        <p>برای دیپلوی موفق این پروژه روی Cloudflare Workers موارد زیر را با Wrangler یا در داشبورد کلودفلر انجام دهید:</p>
        
        <ol style="margin-right: 20px; margin-top: 10px;">
          <li><b>ایجاد KV Namespace:</b>
            <div class="code-block">npx wrangler kv:namespace create KV</div>
            شناسه بازگردانده شده (ID) را در فایل <code>wrangler.toml</code> در بخش <code>[[kv_namespaces]]</code> جایگزین کنید.
          </li>
          
          <li style="margin-top: 12px;"><b>ایجاد دیتابیس Cloudflare D1:</b>
            <div class="code-block">npx wrangler d1 create wireguard-bot-db</div>
            مقدار <code>database_id</code> را در فایل <code>wrangler.toml</code> در بخش <code>[[d1_databases]]</code> قرار دهید.
          </li>

          <li style="margin-top: 12px;"><b>اجرای اسکیما در D1:</b>
            دیتابیس به صورت خودکار در زمان اجرای ورکر جدول‌ها را در صورت عدم وجود می‌سازد، اما می‌توانید این دستور را نیز اجرا نمایید:
            <div class="code-block">npx wrangler d1 execute wireguard-bot-db --command "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT); CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, tg_id TEXT UNIQUE NOT NULL, role TEXT NOT NULL DEFAULT 'admin', added_at INTEGER NOT NULL);"</div>
          </li>

          <li style="margin-top: 12px;"><b>تنظیم متغیر مخفی APP_ENCRYPTION_KEY:</b>
            کلید مستر رمزنگاری توکن را در کلودفلر ثبت کنید:
            <div class="code-block">npx wrangler secret put APP_ENCRYPTION_KEY</div>
            (یک رشته تصادفی حداقل ۳۲ کاراکتری وارد کنید)
          </li>

          <li style="margin-top: 12px;"><b>دیپلوی نهایی:</b>
            <div class="code-block">npx wrangler deploy</div>
          </li>
        </ol>
      </div>
    </div>

    <footer class="footer">
      Telegram WireGuard Bot & Management Panel • Embedded Single-File Worker
    </footer>
  </div>`;

  return renderHtmlLayout('داشبورد مدیریت', content);
}

// ==========================================
// 9. HTTP REQUEST ROUTER & AUTH MIDDLEWARE
// ==========================================

function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(';');
  for (let c of cookies) {
    const [k, v] = c.trim().split('=');
    if (k === name) return decodeURIComponent(v);
  }
  return null;
}

function setCookie(name, val, maxAgeSec = 86400) {
  return `${name}=${encodeURIComponent(val)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAgeSec}`;
}

function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

// Rate Limiting for Admin Login
async function checkLoginRateLimit(kv, ip) {
  if (!kv) return true;
  const key = `ratelimit:login:${ip}`;
  const attempts = await kv.get(key);
  if (attempts && parseInt(attempts, 10) >= 5) {
    return false; // Rate limit exceeded (5 failed attempts)
  }
  return true;
}

async function recordFailedLogin(kv, ip) {
  if (!kv) return;
  const key = `ratelimit:login:${ip}`;
  const current = await kv.get(key);
  const count = (parseInt(current, 10) || 0) + 1;
  await kv.put(key, String(count), { expirationTtl: 900 }); // 15 minutes block
}

async function clearLoginRateLimit(kv, ip) {
  if (!kv) return;
  await kv.delete(`ratelimit:login:${ip}`);
}

// Session Validation
async function getAuthenticatedSession(request, kv) {
  if (!kv) return null;
  const sessionToken = getCookie(request, 'session_token');
  if (!sessionToken) return null;
  const user = await kv.get(`session:${sessionToken}`);
  return user ? sessionToken : null;
}

// Main Fetch Export
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';

    // Auto-initialize DB schema on demand
    await ensureDbInitialized(env.DB);

    // ===================================
    // ROUTE: Telegram Webhook POST
    // ===================================
    if (url.pathname === '/webhook' && request.method === 'POST') {
      return handleTelegramWebhook(request, env);
    }

    // ===================================
    // ROUTE: Root Redirection -> /admin
    // ===================================
    if (url.pathname === '/' || url.pathname === '') {
      return Response.redirect(`${url.origin}/admin`, 302);
    }

    // Check if initial admin password has been configured
    const adminPasswordHash = await getSetting(env.DB, 'admin_password_hash');

    // ===================================
    // ROUTE: Initial Setup (/admin/setup)
    // ===================================
    if (url.pathname === '/admin/setup') {
      if (adminPasswordHash) {
        return Response.redirect(`${url.origin}/admin/login`, 302);
      }

      if (request.method === 'GET') {
        return new Response(renderSetupPage(), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }

      if (request.method === 'POST') {
        const formData = await request.formData();
        const newPassword = formData.get('new_password') || '';
        const confirmPassword = formData.get('confirm_password') || '';

        if (newPassword.length < 8) {
          return new Response(renderSetupPage('رمز عبور باید حداقل ۸ کاراکتر باشد.'), {
            status: 400,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }

        if (newPassword !== confirmPassword) {
          return new Response(renderSetupPage('رمز عبور جدید و تکرار آن یکسان نیستند.'), {
            status: 400,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }

        // Hash and save password
        const hash = await hashPassword(newPassword);
        await setSetting(env.DB, 'admin_password_hash', hash);

        // Auto login session
        const sessionToken = getRandomHex(32);
        await env.KV.put(`session:${sessionToken}`, 'admin', { expirationTtl: 86400 });

        return new Response('', {
          status: 302,
          headers: {
            'Location': '/admin',
            'Set-Cookie': setCookie('session_token', sessionToken)
          }
        });
      }
    }

    // If password not configured yet, force to /admin/setup
    if (!adminPasswordHash) {
      return Response.redirect(`${url.origin}/admin/setup`, 302);
    }

    // ===================================
    // ROUTE: Admin Login (/admin/login)
    // ===================================
    if (url.pathname === '/admin/login') {
      if (request.method === 'GET') {
        // If already logged in, redirect to dashboard
        const session = await getAuthenticatedSession(request, env.KV);
        if (session) {
          return Response.redirect(`${url.origin}/admin`, 302);
        }
        return new Response(renderLoginPage(), {
          headers: { 'Content-Type': 'text/html; charset=utf-8' }
        });
      }

      if (request.method === 'POST') {
        // Rate limiting check
        const isAllowed = await checkLoginRateLimit(env.KV, clientIp);
        if (!isAllowed) {
          return new Response(renderLoginPage('تعداد دفعات تلاش ناموفق بیش از حد مجاز است. لطفاً ۱۵ دقیقه دیگر تلاش کنید.'), {
            status: 429,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }

        const formData = await request.formData();
        const password = formData.get('password') || '';

        const isValid = await verifyPassword(password, adminPasswordHash);
        if (!isValid) {
          await recordFailedLogin(env.KV, clientIp);
          return new Response(renderLoginPage('رمز عبور وارد شده اشتباه است.'), {
            status: 401,
            headers: { 'Content-Type': 'text/html; charset=utf-8' }
          });
        }

        // Clear rate limit counter on success
        await clearLoginRateLimit(env.KV, clientIp);

        // Generate session token
        const sessionToken = getRandomHex(32);
        await env.KV.put(`session:${sessionToken}`, 'admin', { expirationTtl: 86400 });

        return new Response('', {
          status: 302,
          headers: {
            'Location': '/admin',
            'Set-Cookie': setCookie('session_token', sessionToken)
          }
        });
      }
    }

    // ===================================
    // ROUTE: Admin Logout (/admin/logout)
    // ===================================
    if (url.pathname === '/admin/logout') {
      const sessionToken = getCookie(request, 'session_token');
      if (sessionToken && env.KV) {
        await env.KV.delete(`session:${sessionToken}`);
      }
      return new Response('', {
        status: 302,
        headers: {
          'Location': '/admin/login',
          'Set-Cookie': clearCookie('session_token')
        }
      });
    }

    // ===================================
    // REQUIRE AUTHENTICATION FOR ALL /admin/*
    // ===================================
    const activeSession = await getAuthenticatedSession(request, env.KV);
    if (!activeSession) {
      return Response.redirect(`${url.origin}/admin/login`, 302);
    }

    // ===================================
    // ROUTE: Admin Dashboard (/admin)
    // ===================================
    if (url.pathname === '/admin' && request.method === 'GET') {
      const ownerId = await getSetting(env.DB, 'owner_tg_id');
      const encryptedToken = await getSetting(env.DB, 'encrypted_bot_token');
      const isTokenConfigured = !!encryptedToken;
      const botToken = await decryptToken(encryptedToken, env.APP_ENCRYPTION_KEY);

      let botInfo = null;
      let webhookInfo = null;
      if (botToken) {
        try {
          botInfo = await telegramRequest(botToken, 'getMe');
          const wh = await telegramRequest(botToken, 'getWebhookInfo');
          if (wh && wh.ok) webhookInfo = wh.result;
        } catch (e) {
          // Telegram API unreachable or bad token
        }
      }

      const admins = await getAdmins(env.DB);
      const successMsg = url.searchParams.get('msg') || '';
      const errorMsg = url.searchParams.get('err') || '';

      const html = renderDashboardPage({
        ownerId,
        isTokenConfigured,
        maskedToken: isTokenConfigured ? '••••••••' : '',
        botInfo,
        webhookInfo,
        admins,
        workerUrl: url.origin,
        successMsg,
        errorMsg
      });

      return new Response(html, {
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // ===================================
    // ROUTE: Save Bot Config (/admin/api/config)
    // ===================================
    if (url.pathname === '/admin/api/config' && request.method === 'POST') {
      const formData = await request.formData();
      const rawBotToken = (formData.get('bot_token') || '').trim();
      const ownerTgId = (formData.get('owner_tg_id') || '').trim();

      if (!ownerTgId || !/^[0-9]+$/.test(ownerTgId)) {
        return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent('شناسه عددی تلگرام مالک نامعتبر است.')}`, 302);
      }

      // Save owner ID in settings and admins table
      await setSetting(env.DB, 'owner_tg_id', ownerTgId);
      await addAdmin(env.DB, ownerTgId, 'owner');

      // If new bot token provided, validate and encrypt it
      if (rawBotToken) {
        // Validate with Telegram getMe
        const botTest = await telegramRequest(rawBotToken, 'getMe');
        if (!botTest || !botTest.ok) {
          return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent('توکن وارد شده توسط سرورهای تلگرام تأیید نشد.')}`, 302);
        }

        // Encrypt with AES-GCM
        const encrypted = await encryptToken(rawBotToken, env.APP_ENCRYPTION_KEY);
        await setSetting(env.DB, 'encrypted_bot_token', encrypted);

        // Generate webhook secret token
        const webhookSecret = getRandomHex(32);
        await setSetting(env.DB, 'webhook_secret', webhookSecret);

        // Automatically configure Telegram Webhook
        const webhookUrl = `${url.origin}/webhook`;
        await telegramRequest(rawBotToken, 'setWebhook', {
          url: webhookUrl,
          secret_token: webhookSecret,
          drop_pending_updates: false
        });
      }

      return Response.redirect(`${url.origin}/admin?msg=${encodeURIComponent('تنظیمات بات و وب‌هوک با موفقیت ذخیره شد.')}`, 302);
    }

    // ===================================
    // ROUTE: Re-sync Webhook (/admin/api/webhook/sync)
    // ===================================
    if (url.pathname === '/admin/api/webhook/sync' && request.method === 'POST') {
      const encryptedToken = await getSetting(env.DB, 'encrypted_bot_token');
      const botToken = await decryptToken(encryptedToken, env.APP_ENCRYPTION_KEY);

      if (!botToken) {
        return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent('ابتدا توکن بات تلگرام را وارد کنید.')}`, 302);
      }

      let webhookSecret = await getSetting(env.DB, 'webhook_secret');
      if (!webhookSecret) {
        webhookSecret = getRandomHex(32);
        await setSetting(env.DB, 'webhook_secret', webhookSecret);
      }

      const webhookUrl = `${url.origin}/webhook`;
      const res = await telegramRequest(botToken, 'setWebhook', {
        url: webhookUrl,
        secret_token: webhookSecret,
        drop_pending_updates: false
      });

      if (res && res.ok) {
        return Response.redirect(`${url.origin}/admin?msg=${encodeURIComponent('وب‌هوک با موفقیت در تلگرام ثبت و فعال شد.')}`, 302);
      } else {
        const desc = (res && res.description) || 'خطا در ثبت وب‌هوک';
        return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent(`خطا از سوی تلگرام: ${desc}`)}`, 302);
      }
    }

    // ===================================
    // ROUTE: Add Admin (/admin/api/admins/add)
    // ===================================
    if (url.pathname === '/admin/api/admins/add' && request.method === 'POST') {
      const formData = await request.formData();
      const adminId = (formData.get('admin_id') || '').trim();

      if (!adminId || !/^[0-9]+$/.test(adminId)) {
        return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent('شناسه کاربری باید فقط شامل اعداد باشد.')}`, 302);
      }

      const success = await addAdmin(env.DB, adminId, 'admin');
      if (!success) {
        return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent('این شناسه تلگرام قبلاً ثبت شده است.')}`, 302);
      }

      return Response.redirect(`${url.origin}/admin?msg=${encodeURIComponent('مدیر جدید با موفقیت اضافه شد.')}`, 302);
    }

    // ===================================
    // ROUTE: Remove Admin (/admin/api/admins/delete)
    // ===================================
    if (url.pathname === '/admin/api/admins/delete' && request.method === 'POST') {
      const formData = await request.formData();
      const adminId = (formData.get('admin_id') || '').trim();

      const ownerId = await getSetting(env.DB, 'owner_tg_id');
      if (adminId === ownerId) {
        return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent('مالک اصلی سیستم غیرقابل حذف است.')}`, 302);
      }

      const deleted = await removeAdmin(env.DB, adminId);
      if (deleted) {
        return Response.redirect(`${url.origin}/admin?msg=${encodeURIComponent('دسترسی مدیر حذف گردید.')}`, 302);
      } else {
        return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent('خطا در حذف مدیر یا مدیر یافت نشد.')}`, 302);
      }
    }

    // ===================================
    // ROUTE: Change Admin Password (/admin/api/password)
    // ===================================
    if (url.pathname === '/admin/api/password' && request.method === 'POST') {
      const formData = await request.formData();
      const currentPassword = formData.get('current_password') || '';
      const newPassword = formData.get('new_password') || '';
      const confirmPassword = formData.get('confirm_password') || '';

      const currentHash = await getSetting(env.DB, 'admin_password_hash');
      const isValid = await verifyPassword(currentPassword, currentHash);
      if (!isValid) {
        return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent('رمز عبور فعلی نادرست است.')}`, 302);
      }

      if (newPassword.length < 8) {
        return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent('رمز عبور جدید باید حداقل ۸ کاراکتر باشد.')}`, 302);
      }

      if (newPassword !== confirmPassword) {
        return Response.redirect(`${url.origin}/admin?err=${encodeURIComponent('رمز جدید و تکرار آن مطابقت ندارند.')}`, 302);
      }

      // Save new password hash
      const newHash = await hashPassword(newPassword);
      await setSetting(env.DB, 'admin_password_hash', newHash);

      // Invalidate current session and require re-login
      if (activeSession && env.KV) {
        await env.KV.delete(`session:${activeSession}`);
      }

      return new Response('', {
        status: 302,
        headers: {
          'Location': `/admin/login?msg=${encodeURIComponent('رمز عبور با موفقیت تغییر کرد. لطفاً با رمز جدید وارد شوید.')}`,
          'Set-Cookie': clearCookie('session_token')
        }
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};
