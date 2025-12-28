
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users', 'users.json');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const REWARDS_FILE = path.join(DATA_DIR, 'rewards.json');
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
const ADMIN_USERNAME = '9micedev';
const ADMIN_USERNAME_SAFE = ADMIN_USERNAME.toLowerCase();
const ALLOWED_HOSTS = new Set(
  (process.env.ALLOWED_HOSTS || 'localhost:3000,127.0.0.1:3000')
    .split(',')
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean)
);
const uploadBuckets = new Map(); // userId -> { count, reset }
const registerBuckets = new Map(); // ip -> { count, reset }
const suspiciousBuckets = new Map(); // userId -> { count, reset }
const TOTP_STEP = 30;
const TOTP_DIGITS = 6;
const CAPTCHA_WINDOW_MS = 5 * 60 * 1000;
const HUMAN_BYPASS_PATHS = ['/api/human-challenge', '/api/human-verify', '/human', '/health', '/login', '/register'];
const BADGE_OPTIONS = [
  'Owner',
  'Premium',
  'Verified',
  'Developer',
  'Designer',
  'VIP',
  'Staff',
  'Helper',
  'Booster',
  'Server Booster',
  'Million',
  'The Million',
  'Domain Legend',
  'Christmas 2024',
  'Christmas 2025',
  'Easter 2025',
  'Bug Hunter',
  'Image Host',
  'Gifter',
  'Donor',
  'Hone.gg',
  'Winner',
  'Second Place',
  'Third Place',
  'Crown',
  'OG'
];
const SPARKLE_COLORS = [
  'black',
  'blue',
  'green',
  'pink',
  'red',
  'white',
  'yellow'
];
const MAX_LINK_IMAGE_MB = 5;

function canonicalBadgeName(name) {
  if (!name) return null;
  const normalized = String(name).trim();
  const match = BADGE_OPTIONS.find((b) => b.toLowerCase() === normalized.toLowerCase());
  return match || null;
}

function filterBadges(list) {
  const seen = new Set();
  const badges = Array.isArray(list) ? list : [];
  const result = [];
  badges.forEach((badge) => {
    const canonical = canonicalBadgeName(badge);
    if (canonical && !seen.has(canonical)) {
      seen.add(canonical);
      result.push(canonical);
    }
  });
  return result;
}

function isAdminUser(user) {
  return String(user?.username || '').toLowerCase() === ADMIN_USERNAME_SAFE;
}

function normalizeUser(user) {
  if (!user) return null;
  const normalized = { ...user };
  normalized.username = String(normalized.username || '').toLowerCase();
  normalized.role = isAdminUser(normalized) ? 'admin' : 'user';
  normalized.premium = Boolean(normalized.premium);
  normalized.premiumUntil = normalized.premiumUntil && !isNaN(Date.parse(normalized.premiumUntil))
    ? new Date(normalized.premiumUntil).toISOString()
    : null;
  normalized.badges = filterBadges(normalized.badges);
  normalized.banned = Boolean(normalized.banned);
  normalized.frozen = Boolean(normalized.frozen);
  normalized.cursorFile = typeof normalized.cursorFile === 'string' ? normalized.cursorFile : '';
  normalized.badgeSlots = Number.isFinite(normalized.badgeSlots) ? Math.max(0, Number(normalized.badgeSlots)) : 0;
  normalized.allowOneLetter = Boolean(normalized.allowOneLetter);
  normalized.sessions = Array.isArray(normalized.sessions) ? normalized.sessions : [];
  if (!normalized.createdAt) normalized.createdAt = new Date().toISOString();
  return normalized;
}

function isPremiumActive(user) {
  const until = user?.premiumUntil ? new Date(user.premiumUntil).getTime() : 0;
  return Boolean(user?.premium) || (until && until > Date.now());
}

function ensureStorage() {
  fs.mkdirSync(path.dirname(USERS_FILE), { recursive: true });
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, '[]', 'utf8');
  }
  if (!fs.existsSync(STATE_FILE)) {
    fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
    fs.writeFileSync(STATE_FILE, JSON.stringify({ emergencyMode: false, message: 'Emergency maintenance mode enabled' }, null, 2));
  }
  if (!fs.existsSync(REWARDS_FILE)) {
    fs.mkdirSync(path.dirname(REWARDS_FILE), { recursive: true });
    fs.writeFileSync(REWARDS_FILE, '[]', 'utf8');
  }
}

function readUsers() {
  ensureStorage();
  try {
    const raw = fs.readFileSync(USERS_FILE, 'utf8');
    const parsed = JSON.parse(raw || '[]');
    let dirty = false;
    const normalized = (Array.isArray(parsed) ? parsed : []).map((u) => {
      const norm = normalizeUser(u);
      if (JSON.stringify(norm) !== JSON.stringify(u)) dirty = true;
      return norm;
    });
    if (dirty) {
      writeUsers(normalized);
    }
    return normalized;
  } catch (err) {
    console.error('Failed to read users.json', err);
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function readState() {
  ensureStorage();
  try {
    const raw = fs.readFileSync(STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    return {
      emergencyMode: Boolean(parsed.emergencyMode),
      message: parsed.message || 'Emergency maintenance mode enabled'
    };
  } catch (err) {
    console.warn('Failed to read state, using defaults', err.message);
    return { emergencyMode: false, message: 'Emergency maintenance mode enabled' };
  }
}

function writeState(next) {
  fs.writeFileSync(STATE_FILE, JSON.stringify(next, null, 2));
}

function accountAgeDays(user) {
  const created = user?.createdAt ? new Date(user.createdAt).getTime() : 0;
  if (!created || isNaN(created)) return 0;
  return (Date.now() - created) / (1000 * 60 * 60 * 24);
}

// --- TOTP helpers ---
function randomBytes(len = 20) {
  return require('crypto').randomBytes(len);
}
function toBase32(buf) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  let output = '';
  for (const b of buf) {
    bits += b.toString(2).padStart(8, '0');
    while (bits.length >= 5) {
      const chunk = bits.slice(0, 5);
      bits = bits.slice(5);
      output += alphabet[parseInt(chunk, 2)];
    }
  }
  if (bits.length) {
    output += alphabet[parseInt(bits.padEnd(5, '0'), 2)];
  }
  return output;
}
function base32ToBuffer(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of str.replace(/=+$/g, '')) {
    const val = alphabet.indexOf(ch.toUpperCase());
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}
function generateTotpSecret() {
  return toBase32(randomBytes(20));
}
function totp(secret, step = TOTP_STEP, digits = TOTP_DIGITS, offset = 0) {
  const crypto = require('crypto');
  const key = base32ToBuffer(secret);
  const counter = Math.floor(Date.now() / 1000 / step) + offset;
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offsetBits = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offsetBits] & 0x7f) << 24) |
    ((hmac[offsetBits + 1] & 0xff) << 16) |
    ((hmac[offsetBits + 2] & 0xff) << 8) |
    (hmac[offsetBits + 3] & 0xff);
  return String(code % 10 ** digits).padStart(digits, '0');
}
function verifyTotp(secret, token) {
  const clean = String(token || '').replace(/\s+/g, '');
  if (!clean || clean.length !== TOTP_DIGITS) return false;
  for (let drift = -1; drift <= 1; drift++) {
    if (totp(secret, TOTP_STEP, TOTP_DIGITS, drift) === clean) return true;
  }
  return false;
}

// --- TOTP helpers ---

function readRewards() {
  ensureStorage();
  try {
    const raw = fs.readFileSync(REWARDS_FILE, 'utf8');
    const parsed = JSON.parse(raw || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.warn('Failed to read rewards', err.message);
    return [];
  }
}

function writeRewards(rewards) {
  fs.writeFileSync(REWARDS_FILE, JSON.stringify(rewards, null, 2));
}

function recordSession(user, sid, req) {
  if (!user || !sid) return user;
  user.sessions = Array.isArray(user.sessions) ? user.sessions : [];
  const nowIso = new Date().toISOString();
  const ua = req.get('user-agent') || 'unknown';
  const ip = clientIp(req);
  const idx = user.sessions.findIndex((s) => s.id === sid);
  const entry = { id: sid, ua, ip, createdAt: nowIso, lastActive: nowIso };
  if (idx >= 0) {
    user.sessions[idx] = { ...user.sessions[idx], ua, ip, lastActive: nowIso };
  } else {
    user.sessions.push(entry);
  }
  return user;
}

function touchSession(user, sid, req) {
  if (!user || !sid || !Array.isArray(user.sessions)) return false;
  const idx = user.sessions.findIndex((s) => s.id === sid);
  if (idx === -1) return false;
  user.sessions[idx].lastActive = new Date().toISOString();
  user.sessions[idx].ua = req.get('user-agent') || user.sessions[idx].ua;
  user.sessions[idx].ip = clientIp(req) || user.sessions[idx].ip;
  return true;
}

function sanitizeUser(user) {
  const normalized = normalizeUser(user);
  if (!normalized) return null;
  const clone = { ...normalized };
  delete clone.password;
  delete clone.sessions;
  delete clone.createdIp;
  delete clone.createdUa;
  if (clone.twofa) {
    clone.twofaEnabled = Boolean(clone.twofa.enabled);
    delete clone.twofa;
  }
  clone.role = isAdminUser(normalized) ? 'admin' : 'user';
  clone.premium = isPremiumActive(normalized);
  return clone;
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return String(forwarded).split(',')[0].trim();
  }
  return req.ip;
}

function isSuspiciousRequest(req) {
  const ua = String(req.headers['user-agent'] || '').toLowerCase();
  const acceptLang = req.headers['accept-language'];
  if (!ua || ua.length < 12) return true;
  if (/bot|spider|crawler|curl|wget|scrapy|python-requests/.test(ua)) return true;
  if (!acceptLang || acceptLang.length < 2) return true;
  return false;
}

function shouldBypassHuman(pathname) {
  if (HUMAN_BYPASS_PATHS.some((p) => pathname.startsWith(p))) return true;
  if (pathname.startsWith('/css') || pathname.startsWith('/js') || pathname.startsWith('/images') || pathname.startsWith('/uploads')) return true;
  return false;
}

function issueCaptcha(session) {
  const id = uuidv4();
  session.captcha = {
    id,
    expires: Date.now() + CAPTCHA_WINDOW_MS
  };
  session.captchaVerified = false;
  return { id, prompt: 'Tap verify to continue' };
}

function validateCaptcha(session, token) {
  if (session.captchaVerified) return true;
  const record = session?.captcha;
  if (!record || !token || record.id !== token) return false;
  if (record.expires < Date.now()) return false;
  session.captchaVerified = true;
  delete session.captcha;
  return true;
}

function findUserIndex(users, username) {
  const target = String(username || '').toLowerCase();
  return users.findIndex((u) => u.username === target);
}

function deleteUploadFile(filePath) {
  if (!filePath || typeof filePath !== 'string') return;
  const cleaned = filePath.replace(/\\/g, '/');
  const normalized = path.posix.normalize(cleaned);
  if (!normalized.startsWith('/uploads/')) return;
  const absolute = path.join(__dirname, 'public', normalized);
  try {
    if (fs.existsSync(absolute)) {
      fs.unlinkSync(absolute);
    }
  } catch (err) {
    console.warn('Failed to delete old upload', absolute, err.message);
  }
}

function checkUploadQuota(userId, isPremium) {
  const now = Date.now();
  const windowMs = 10 * 60 * 1000; // 10 minutes
  const maxCount = isPremium ? 100 : 30;
  const bucket = uploadBuckets.get(userId) || { count: 0, reset: now + windowMs };
  if (now > bucket.reset) {
    bucket.count = 0;
    bucket.reset = now + windowMs;
  }
  if (bucket.count >= maxCount) {
    const retryAfter = Math.max(1, Math.ceil((bucket.reset - now) / 1000));
    return { ok: false, retryAfter };
  }
  bucket.count += 1;
  uploadBuckets.set(userId, bucket);
  return { ok: true };
}

function checkSuspicious(userId) {
  const now = Date.now();
  const windowMs = 10 * 60 * 1000; // 10 minutes
  const maxCount = 200; // per 10 min per user
  const bucket = suspiciousBuckets.get(userId) || { count: 0, reset: now + windowMs };
  if (now > bucket.reset) {
    bucket.count = 0;
    bucket.reset = now + windowMs;
  }
  bucket.count += 1;
  suspiciousBuckets.set(userId, bucket);
  if (bucket.count > maxCount) {
    return { ok: false, retryAfter: Math.max(1, Math.ceil((bucket.reset - now) / 1000)) };
  }
  return { ok: true };
}

function checkRegisterQuota(ip) {
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hour
  const maxCount = 5;
  const bucket = registerBuckets.get(ip) || { count: 0, reset: now + windowMs };
  if (now > bucket.reset) {
    bucket.count = 0;
    bucket.reset = now + windowMs;
  }
  if (bucket.count >= maxCount) {
    const retryAfter = Math.max(1, Math.ceil((bucket.reset - now) / 1000));
    return { ok: false, retryAfter };
  }
  bucket.count += 1;
  registerBuckets.set(ip, bucket);
  return { ok: true };
}

function defaultProfile() {
  return {
    title: '',
    titleAnimation: 'none',
    titleAnimationSpeed: 300,
    overlay: 'none',
    enterAnimation: 'none',
    enterAnimationSpeed: 300,
    backgroundFile: '',
    backgroundOpacity: 100,
    backgroundBlur: 0,
    backgroundColor: '#000000',
    bannerFile: '',
    bannerOpacity: 100,
    bannerBlur: 0,
    themeColor: '#ffffff',
    primaryTextColor: '#ffffff',
    secondaryTextColor: '#aaaaaa',
    boxWidth: 440,
    boxOpacity: 50,
    boxRadius: 10,
    boxBlur: 0,
    boxTilt: true,
    boxColor: '#0c0e16',
    parallaxEnabled: false,
    parallaxIntensity: 10,
    parallaxInvert: false,
    showJoinDate: true,
    showUidTooltip: true,
    badgePosition: 'below',
    badgeBgColor: '#0c0e16',
    badgeTextColor: '#ffffff',
    badgeBgOpacity: 40,
    badgeIconColor: '#999999',
    badgeGlow: 12,
    badgeShape: 'rounded',
    badgeVisibility: [],
    decorationFile: '',
    textAnimation: 'none',
    linkLayout: 'stacked',
    layoutTemplate: 'default',
    nameAnimation: 'none',
    bioAnimation: 'none',
    joinAnimation: 'none',
    joinTextColor: '#ffffff',
    joinBgColor: '#0c0e16',
    joinOpacity: 100,
    viewsBgColor: '#0c0e16',
    viewsTextColor: '#ffffff',
    viewsOpacity: 60,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: '#78726D',
    borderOpacity: 20,
    shadowColor: '#303030',
    shadowOpacity: 0,
    avatarRadius: 50,
    avatarDecoration: 'none',
    cursor: 'system',
    cursorTrail: 'none',
    cursorFile: '',
    sparkles: 'none',
    revealBlur: 15,
    revealText: 'Click Enter',
    enterBgColor: 'rgba(0,0,0,0.8)',
    enterTextColor: '#ffffff',
    faviconFile: '',
    font: 'System',
    bio: '',
    location: '',
    avatarFile: '',
    music: [],
    seoTitle: '',
    seoDescription: ''
  };
}

ensureStorage();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.disable('x-powered-by');
app.disable('etag');
app.use(
  helmet({
    contentSecurityPolicy: false, // relaxed for inline styles/scripts already present
    crossOriginResourcePolicy: { policy: 'cross-origin' },
    referrerPolicy: { policy: 'same-origin' }
  })
);

// Block path traversal and direct access to code/config files
app.use((req, res, next) => {
  const p = req.path || '';
  if (p.includes('..')) {
    return res.status(400).json({ error: 'Invalid path' });
  }
  const sensitiveExt = /\.(env|json|md|lock|config|sql|sh|bat|cmd|log|db|db3|sqlite|yml|yaml|toml|map|bak|old|swp)$/i;
  if (sensitiveExt.test(p) && !p.startsWith('/api/')) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});

// Block common scraper/archiver user-agents
app.use((req, res, next) => {
  const ua = (req.get('user-agent') || '').toLowerCase();
  const blocked = [
    'curl',
    'wget',
    'httrack',
    'python-requests',
    'httpclient',
    'postmanruntime',
    'libwww',
    'scrapy',
    'okhttp',
    'httpurlconnection',
    'aiohttp',
    'go-http-client',
    'powershell',
    'java/'
  ];
  if (blocked.some((sig) => ua.includes(sig))) {
    return res.status(403).send('Automated scraping blocked');
  }
  // simplistic bot detection: no UA or UA length too short
  if (!ua || ua.length < 12) {
    return res.status(403).send('User-Agent required');
  }
  next();
});

// Do not allow HTML to be cached aggressively (makes mirroring harder)
app.use((req, res, next) => {
  const accept = req.headers.accept || '';
  if (accept.includes('text/html')) {
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
  }
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down' }
});

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many uploads, try later' }
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' }
});

app.use(['/api/login', '/api/register'], authLimiter);
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'bio-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 30
    }
  })
);

app.use(
  express.static(path.join(__dirname, 'public'), {
    dotfiles: 'deny',
    index: false,
    etag: false,
    cacheControl: true,
    maxAge: '1h'
  })
);

// Enforce same-origin API requests (helps against cross-site/fake origins)
function enforceOrigin(req, res, next) {
  const origin = req.headers.origin;
  if (!origin) return next();
  const host = (req.headers.host || '').toLowerCase();
  try {
    const parsed = new URL(origin);
    const originHost = parsed.host.toLowerCase();
    if (originHost === host || ALLOWED_HOSTS.has(originHost)) {
      return next();
    }
  } catch (err) {
    // malformed origin -> block
  }
  return res.status(403).json({ error: 'Forbidden origin' });
}

// Apply API-level protections
app.use('/api', apiLimiter, enforceOrigin);

// Additional hardening headers to reduce scraping/indexing
app.use((req, res, next) => {
  res.setHeader('X-Robots-Tag', 'noindex, noarchive, nosnippet, noimageindex');
  next();
});

// Lightweight anti-bot/VPN gate that forces a human verification page
app.use((req, res, next) => {
  if (req.session?.captchaVerified) return next();
  if (shouldBypassHuman(req.path)) return next();
  if (req.method === 'OPTIONS') return next();

  const suspicious = isSuspiciousRequest(req);
  if (!suspicious) return next();

  const redirect = `/human?r=${encodeURIComponent(req.originalUrl || '/')}`;
  if (req.path.startsWith('/api/')) {
    return res.status(403).json({ error: 'Human verification required', redirect });
  }
  return res.redirect(302, redirect);
});

app.use((req, res, next) => {
  const state = readState();
  req.appState = state;
  if (!state.emergencyMode) return next();

  const isAdminSession = req.session?.user && isAdminUser(req.session.user);
  const allowUnauthed = ['/login', '/api/login', '/api/human-challenge', '/api/human-verify', '/human'];
  const isAdminPath = req.path.startsWith('/admin') || req.path.startsWith('/api/admin');
  const isAllowedPath = allowUnauthed.some((p) => req.path.startsWith(p));

  if (isAdminSession || isAdminPath) {
    return next();
  }

  if (isAllowedPath) {
    return next();
  }

  const isApi = req.path.startsWith('/api/');
  const payload = { error: state.message || 'Emergency maintenance mode enabled' };
  if (isApi) {
    return res.status(503).json(payload);
  }
  res.status(503).send(state.message || 'Emergency maintenance mode enabled');
});

app.get('/api/human-challenge', (req, res) => {
  const challenge = issueCaptcha(req.session);
  res.json(challenge);
});

app.get('/human', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'human.html'));
});

app.get('/decoration.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'decoration.html'));
});

app.post('/api/human-verify', (req, res) => {
  const token = req.body?.captchaToken;
  if (!token) {
    return res.status(400).json({ error: 'Missing token' });
  }
  const ok = validateCaptcha(req.session, token);
  if (!ok) {
    issueCaptcha(req.session);
    return res.status(400).json({ error: 'Captcha failed' });
  }
  res.json({ success: true });
});

function requireAuth(req, res, next) {
  const sessionUser = req.session.user;
  if (!sessionUser) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const users = readUsers();
  const idx = users.findIndex((u) => u.id === sessionUser.id);
  if (idx === -1) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const normalized = normalizeUser(users[idx]);
  if (JSON.stringify(users[idx]) !== JSON.stringify(normalized)) {
    users[idx] = normalized;
    writeUsers(users);
  }
  const suspicious = checkSuspicious(normalized.id);
  if (!suspicious.ok) {
    return res.status(429).json({ error: 'Suspicious activity detected, slow down', retryAfter: suspicious.retryAfter });
  }
  touchSession(users[idx], req.sessionID, req);
  writeUsers(users);
  if (normalized.banned) {
    req.session.destroy(() => {});
    return res.status(403).json({ error: 'Account banned by admin' });
  }
  if (normalized.frozen) {
    req.session.destroy(() => {});
    return res.status(423).json({ error: 'Account is frozen by admin' });
  }
  req.user = normalized;
  req.users = users;
  req.session.user = { id: normalized.id, username: normalized.username, role: normalized.role, premium: isPremiumActive(normalized) };
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!isAdminUser(req.user)) {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const safeName = `${req.session.user?.username || 'file'}-${Date.now()}-${Math.round(Math.random() * 1e6)}${ext}`;
    cb(null, safeName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 21 * 1024 * 1024 }, // hard cap
  fileFilter: (req, file, cb) => {
    const allowed = ['image/', 'audio/', 'video/', 'font/', 'application/font', 'application/x-font', 'application/octet-stream'];
    const isAllowed = allowed.some((prefix) => file.mimetype.startsWith(prefix));
    if (!isAllowed) {
      return cb(new Error('Only image, audio, video or font uploads are allowed'));
    }
    const isFont =
      file.mimetype.startsWith('font/') ||
      file.mimetype.includes('font') ||
      ['.ttf', '.otf', '.woff', '.woff2'].some((ext) => (file.originalname || '').toLowerCase().endsWith(ext));
    if (isFont && !isPremiumActive(req.user)) {
      return cb(new Error('Custom fonts are premium-only'));
    }
    cb(null, true);
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'register.html'));
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  const users = readUsers();
  const idx = users.findIndex((u) => u.id === req.session.user.id);
  if (idx === -1) {
    return res.redirect('/login');
  }
  const current = normalizeUser(users[idx]);
  if (JSON.stringify(users[idx]) !== JSON.stringify(current)) {
    users[idx] = current;
    writeUsers(users);
  }
  if (!current || current.banned || current.frozen) {
    req.session.destroy(() => {});
    return res.redirect('/login');
  }
  req.session.user = { id: current.id, username: current.username, role: current.role, premium: isPremiumActive(current) };
  res.sendFile(path.join(__dirname, 'views', 'dashboard-advanced.html'));
});

app.get('/admin', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  const users = readUsers();
  const idx = users.findIndex((u) => u.id === req.session.user.id);
  if (idx === -1) {
    return res.redirect('/login');
  }
  const current = normalizeUser(users[idx]);
  if (JSON.stringify(users[idx]) !== JSON.stringify(current)) {
    users[idx] = current;
    writeUsers(users);
  }
  if (!current || current.banned || current.frozen) {
    req.session.destroy(() => {});
    return res.redirect('/login');
  }
  if (!isAdminUser(current)) {
    return res.status(403).send('Forbidden');
  }
  req.session.user = { id: current.id, username: current.username, role: current.role, premium: isPremiumActive(current) };
  res.sendFile(path.join(__dirname, 'views', 'admin.html'));
});

app.get('/u/:username', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'profile.html'));
});

app.post('/api/register', async (req, res) => {
  const { username, password, captchaToken } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  if (!validateCaptcha(req.session, captchaToken)) {
    issueCaptcha(req.session);
    return res.status(400).json({ error: 'Captcha failed' });
  }
  const regQuota = checkRegisterQuota(clientIp(req));
  if (!regQuota.ok) {
    return res.status(429).json({ error: 'Too many registrations from your IP, try later', retryAfter: regQuota.retryAfter });
  }

  const normalized = username.trim().toLowerCase();
  const minLength = 3;

  if (normalized.length < minLength || normalized.length > 20) {
    return res.status(400).json({ error: 'Username must be 3-20 chars' });
  }

  if (!/^[a-z0-9_]+$/i.test(normalized)) {
    return res.status(400).json({ error: 'Only letters, numbers and underscore are allowed' });
  }

  const users = readUsers();
  if (users.find((u) => u.username === normalized)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  const ip = clientIp(req);
  const ua = req.get('user-agent') || 'unknown';
  const deviceMatches = users.filter((u) => u.createdIp === ip && u.createdUa === ua);
  let premiumSession = false;
  if (req.session?.user) {
    const sessionUser = users.find((u) => u.id === req.session.user.id);
    premiumSession = isPremiumActive(sessionUser);
  }
  const deviceLimit = premiumSession ? 5 : 3;
  if (deviceMatches.length >= deviceLimit) {
    return res.status(429).json({ error: premiumSession ? 'Premium limit reached (5 accounts per device)' : 'Free limit reached (3 accounts per device)' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();
    const user = {
      id: uuidv4(),
      uid: (() => {
        const maxUid = users.reduce((acc, u) => Math.max(acc, Number(u.uid) || 0), 0);
        return maxUid + 1;
      })(),
      username: normalized,
      password: hash,
      role: isAdminUser({ username: normalized }) ? 'admin' : 'user',
      premium: false,
      premiumUntil: null,
      banned: false,
      frozen: false,
      views: 0,
      viewLog: [],
      badges: [],
      links: [],
      layout: 'card',
      widgets: {
        views: 'upperRight',
        audio: 'belowCard',
        location: 'default'
      },
      profile: defaultProfile(),
      alias: '',
      createdAt: now,
      createdIp: ip,
      createdUa: ua,
      sessions: []
    };

    users.push(user);
    writeUsers(users);
    delete req.session.captchaVerified;
    req.session.user = { id: user.id, username: user.username, role: user.role, premium: isPremiumActive(user) };
    recordSession(user, req.sessionID, req);
    writeUsers(users);
    res.json({ success: true, redirect: '/dashboard', user: sanitizeUser(user) });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password, captchaToken, token } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  if (!validateCaptcha(req.session, captchaToken)) {
    issueCaptcha(req.session);
    return res.status(400).json({ error: 'Captcha failed' });
  }

  const normalized = username.trim().toLowerCase();
  const users = readUsers();
  const user = users.find((u) => u.username === normalized);
  if (!user) {
    return res.status(400).json({ error: 'User not found' });
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  if (user.twofa?.enabled) {
    if (!token || !verifyTotp(user.twofa.secret, token)) {
      return res.status(401).json({ error: '2FA required', require2fa: true });
    }
  }

  if (user.banned) {
    return res.status(403).json({ error: 'Account banned by admin' });
  }
  if (user.frozen) {
    return res.status(423).json({ error: 'Account is frozen by admin' });
  }

  req.session.user = { id: user.id, username: user.username, role: user.role, premium: isPremiumActive(user) };
  recordSession(user, req.sessionID, req);
  writeUsers(users);
  delete req.session.captchaVerified;
  res.json({ success: true, redirect: '/dashboard', user: sanitizeUser(user) });
});

app.post('/api/logout', (req, res) => {
  const sid = req.sessionID;
  const users = readUsers();
  const idx = users.findIndex((u) => u.id === req.session.user?.id);
  if (idx !== -1) {
    users[idx].sessions = (users[idx].sessions || []).filter((s) => s.id !== sid);
    writeUsers(users);
  }
  req.session.destroy(() => res.json({ success: true }));
});

// 2FA setup
app.post('/api/2fa/setup', requireAuth, (req, res) => {
  const users = readUsers();
  const idx = users.findIndex((u) => u.id === req.session.user.id);
  if (idx === -1) return res.status(401).json({ error: 'Unauthorized' });
  const user = users[idx];
  if (user.twofa?.enabled) return res.status(400).json({ error: '2FA already enabled' });
  const secret = generateTotpSecret();
  req.session.twofaSetupSecret = secret;
  const issuer = encodeURIComponent('fakewanted.lol');
  const label = encodeURIComponent(user.username);
  const otpauth = `otpauth://totp/${issuer}:${label}?secret=${secret}&issuer=${issuer}`;
  res.json({ secret, otpauth });
});

app.post('/api/2fa/enable', requireAuth, (req, res) => {
  const token = req.body?.token;
  const secret = req.session.twofaSetupSecret;
  if (!secret) return res.status(400).json({ error: 'Start setup first' });
  if (!verifyTotp(secret, token)) return res.status(400).json({ error: 'Invalid code' });
  const users = readUsers();
  const idx = users.findIndex((u) => u.id === req.session.user.id);
  if (idx === -1) return res.status(401).json({ error: 'Unauthorized' });
  users[idx].twofa = { enabled: true, secret };
  writeUsers(users);
  delete req.session.twofaSetupSecret;
  res.json({ success: true, user: sanitizeUser(users[idx]) });
});

app.post('/api/2fa/disable', requireAuth, (req, res) => {
  const token = req.body?.token;
  const users = readUsers();
  const idx = users.findIndex((u) => u.id === req.session.user.id);
  if (idx === -1) return res.status(401).json({ error: 'Unauthorized' });
  const user = users[idx];
  if (!user.twofa?.enabled) return res.json({ success: true, user: sanitizeUser(user) });
  if (!verifyTotp(user.twofa.secret, token)) return res.status(400).json({ error: 'Invalid code' });
  delete users[idx].twofa;
  writeUsers(users);
  res.json({ success: true, user: sanitizeUser(users[idx]) });
});

// 2FA setup
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: sanitizeUser(req.user) });
});

app.get('/api/sessions', requireAuth, (req, res) => {
  const users = req.users || readUsers();
  const idx = users.findIndex((u) => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  const sessions = (users[idx].sessions || []).map((s) => ({
    id: s.id,
    ua: s.ua,
    ip: s.ip,
    createdAt: s.createdAt,
    lastActive: s.lastActive,
    current: s.id === req.sessionID
  }));
  res.json({ sessions });
});

app.delete('/api/sessions/:sid', requireAuth, (req, res) => {
  const sid = req.params.sid;
  if (!sid) return res.status(400).json({ error: 'Missing session id' });
  const ageDays = accountAgeDays(req.user);
  if (ageDays < 3) {
    return res.status(403).json({ error: 'Account must be at least 3 days old to remove sessions' });
  }
  const users = req.users || readUsers();
  const idx = users.findIndex((u) => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'User not found' });
  const before = users[idx].sessions || [];
  const exists = before.some((s) => s.id === sid);
  users[idx].sessions = before.filter((s) => s.id !== sid);
  writeUsers(users);
  req.sessionStore?.destroy?.(sid, () => {});
  if (sid === req.sessionID) {
    return req.session.destroy(() => res.json({ success: true, current: true }));
  }
  if (!exists) {
    return res.status(404).json({ error: 'Session not found' });
  }
  res.json({ success: true });
});

app.post('/api/rewards/redeem', requireAuth, (req, res) => {
  const codeRaw = String(req.body?.code || '').trim().toUpperCase();
  if (!codeRaw) {
    return res.status(400).json({ error: 'Code required' });
  }
  let rewards = readRewards();
  const idx = rewards.findIndex((r) => r.code === codeRaw);
  if (idx === -1) {
    return res.status(404).json({ error: 'Code not found' });
  }
  const reward = rewards[idx];
  if (reward.usesLeft !== undefined && reward.usesLeft <= 0) {
    return res.status(400).json({ error: 'Code already used up' });
  }
  if (reward.expiresAt && new Date(reward.expiresAt).getTime() < Date.now()) {
    return res.status(400).json({ error: 'Code expired' });
  }

  const users = readUsers();
  const userIdx = users.findIndex((u) => u.id === req.user.id);
  if (userIdx === -1) return res.status(404).json({ error: 'User not found' });
  const user = users[userIdx];

  // Apply premium days
  if (reward.premiumDays && Number(reward.premiumDays) > 0) {
    const days = Math.min(Number(reward.premiumDays), 3650);
    const now = new Date();
    const currentUntil = user.premiumUntil ? new Date(user.premiumUntil) : now;
    if (currentUntil < now) currentUntil.setTime(now.getTime());
    currentUntil.setDate(currentUntil.getDate() + days);
    user.premiumUntil = currentUntil.toISOString();
    user.premium = true;
  }

  // Apply badges
  if (Array.isArray(reward.badges)) {
    reward.badges.forEach((b) => {
      const canonical = canonicalBadgeName(b);
      if (canonical && !user.badges.includes(canonical)) {
        user.badges.push(canonical);
      }
    });
  }

  if (reward.customBadgeSlots && Number(reward.customBadgeSlots) > 0) {
    user.badgeSlots = Math.min(50, (user.badgeSlots || 0) + Number(reward.customBadgeSlots));
  }

  if (reward.allowOneLetter) {
    user.allowOneLetter = true;
  }

  users[userIdx] = normalizeUser(user);
  writeUsers(users);

  // Decrement uses
  if (reward.usesLeft !== undefined) {
    rewards[idx].usesLeft = Math.max(0, (rewards[idx].usesLeft || 0) - 1);
    writeRewards(rewards);
  }

  req.session.user = { id: user.id, username: user.username, role: user.role, premium: isPremiumActive(user) };
  res.json({ success: true, user: sanitizeUser(users[userIdx]), reward: rewards[idx] });
});

app.get('/api/profile/:username', (req, res) => {
  const users = readUsers();
  const username = req.params.username.toLowerCase();
  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(404).json({ error: 'Profile not found' });
  }
  if (!user.uid) {
    const maxUid = users.reduce((acc, u) => Math.max(acc, Number(u.uid) || 0), 0);
    user.uid = maxUid + 1;
    writeUsers(users);
  }

  const increment = req.query.increment !== 'false';
  if (increment) {
    const now = Date.now();
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip;
    const sessionKey = req.session.views || {};
    const lastView = sessionKey[user.id];
    const recent = Array.isArray(user.viewLog) ? user.viewLog.filter(v => now - new Date(v.at).getTime() < 10 * 60 * 1000) : [];
    const alreadyToday = recent.some(v => v.ip === ip);
    if (!alreadyToday && (!lastView || now - lastView > 60 * 1000)) {
      user.views = (user.views || 0) + 1;
      if (!Array.isArray(user.viewLog)) user.viewLog = [];
      user.viewLog.push({ at: new Date().toISOString(), ip });
      req.session.views = { ...sessionKey, [user.id]: now };
      writeUsers(users);
    }
  }

  res.json({ user: sanitizeUser(user) });
});

app.post('/api/profile/save', requireAuth, (req, res) => {
  if (req.user.frozen) {
    return res.status(423).json({ error: 'Account is frozen by admin' });
  }
  const body = req.body || {};
  const restricted = ['role', 'premium', 'premiumUntil', 'badges', 'banned', 'frozen', 'badgeSlots', 'allowOneLetter'];
  const attempted = restricted.filter(
    (key) =>
      Object.prototype.hasOwnProperty.call(body, key) ||
      Object.prototype.hasOwnProperty.call(body.profile || {}, key)
  );
  if (attempted.length) {
    return res.status(400).json({ error: `Restricted fields cannot be changed: ${attempted.join(', ')}` });
  }
  const users = req.users || readUsers();
  const idx = users.findIndex((u) => u.id === req.session.user.id);
  if (idx === -1) {
    return res.status(401).json({ error: 'User not found' });
  }

  const user = users[idx];
  const premiumActive = isPremiumActive(user);

  const oldUploads = {
    background: user.profile?.backgroundFile || '',
    banner: user.profile?.bannerFile || '',
    avatar: user.profile?.avatarFile || '',
    favicon: user.profile?.faviconFile || '',
    font: user.profile?.fontFile || '',
    cursor: user.profile?.cursorFile || ''
  };

  const incomingProfile = body.profile || {};
  const allowedProfile = { ...user.profile, ...incomingProfile };
  allowedProfile.music = Array.isArray(incomingProfile.music) ? incomingProfile.music.slice(0, 3) : user.profile.music || [];
  allowedProfile.bio = typeof incomingProfile.bio === 'string' ? incomingProfile.bio.slice(0, 500) : user.profile.bio;
  allowedProfile.location = typeof incomingProfile.location === 'string' ? incomingProfile.location.slice(0, 120) : user.profile.location;
  allowedProfile.title = typeof incomingProfile.title === 'string' ? incomingProfile.title.slice(0, 140) : user.profile.title;
  allowedProfile.revealText = typeof incomingProfile.revealText === 'string' ? incomingProfile.revealText.slice(0, 140) : user.profile.revealText;
  allowedProfile.parallaxEnabled = Boolean(incomingProfile.parallaxEnabled);
  const rawIntensity = Number(incomingProfile.parallaxIntensity);
  allowedProfile.parallaxIntensity = Number.isFinite(rawIntensity) ? Math.max(0, Math.min(20, rawIntensity)) : user.profile.parallaxIntensity || 0;
  allowedProfile.parallaxInvert = Boolean(incomingProfile.parallaxInvert);
  allowedProfile.boxColor = typeof incomingProfile.boxColor === 'string' ? incomingProfile.boxColor : user.profile.boxColor || '#0c0e16';
  const textAnimations = ['none', 'pulse', 'glow', 'wave', 'typewriter'];
  const layoutTemplates = ['default', 'modern', 'simplistic', 'portfolio', 'poster', 'compact', 'glow'];
  const linkLayouts = ['stacked', 'inline'];
  allowedProfile.textAnimation = textAnimations.includes(incomingProfile.textAnimation) ? incomingProfile.textAnimation : user.profile.textAnimation || 'none';
  allowedProfile.nameAnimation = textAnimations.includes(incomingProfile.nameAnimation) ? incomingProfile.nameAnimation : user.profile.nameAnimation || user.profile.textAnimation || 'none';
  allowedProfile.bioAnimation = textAnimations.includes(incomingProfile.bioAnimation) ? incomingProfile.bioAnimation : user.profile.bioAnimation || user.profile.textAnimation || 'none';
  allowedProfile.joinAnimation = textAnimations.includes(incomingProfile.joinAnimation) ? incomingProfile.joinAnimation : user.profile.joinAnimation || 'none';
  const requestedTemplate = layoutTemplates.includes(incomingProfile.layoutTemplate)
    ? incomingProfile.layoutTemplate
    : (user.profile.layoutTemplate || 'default');
  allowedProfile.layoutTemplate = premiumActive ? requestedTemplate : 'default';
  allowedProfile.joinTextColor = typeof incomingProfile.joinTextColor === 'string' ? incomingProfile.joinTextColor : user.profile.joinTextColor || '#ffffff';
  allowedProfile.joinBgColor = typeof incomingProfile.joinBgColor === 'string' ? incomingProfile.joinBgColor : user.profile.joinBgColor || '#0c0e16';
  const rawJoinOpacity = Number(incomingProfile.joinOpacity);
  allowedProfile.joinOpacity = Number.isFinite(rawJoinOpacity)
    ? Math.max(0, Math.min(100, rawJoinOpacity))
    : (Number.isFinite(user.profile.joinOpacity) ? user.profile.joinOpacity : 100);
  allowedProfile.linkLayout = linkLayouts.includes(incomingProfile.linkLayout) ? incomingProfile.linkLayout : (user.profile.linkLayout || 'stacked');
  allowedProfile.viewsBgColor = typeof incomingProfile.viewsBgColor === 'string' ? incomingProfile.viewsBgColor : user.profile.viewsBgColor || '#0c0e16';
  allowedProfile.viewsTextColor = typeof incomingProfile.viewsTextColor === 'string' ? incomingProfile.viewsTextColor : user.profile.viewsTextColor || '#ffffff';
  const rawViewsOpacity = Number(incomingProfile.viewsOpacity);
  allowedProfile.viewsOpacity = Number.isFinite(rawViewsOpacity)
    ? Math.max(0, Math.min(100, rawViewsOpacity))
    : (Number.isFinite(user.profile.viewsOpacity) ? user.profile.viewsOpacity : 60);
  const rawBoxOpacity = Number(incomingProfile.boxOpacity);
  allowedProfile.boxOpacity = Number.isFinite(rawBoxOpacity)
    ? Math.max(0, Math.min(100, rawBoxOpacity))
    : (Number.isFinite(user.profile.boxOpacity) ? user.profile.boxOpacity : 50);
  const rawBorderWidth = Number(incomingProfile.borderWidth);
  allowedProfile.borderWidth = Number.isFinite(rawBorderWidth)
    ? Math.max(0, Math.min(10, rawBorderWidth))
    : (Number.isFinite(user.profile.borderWidth) ? user.profile.borderWidth : 1);
  const rawBorderOpacity = Number(incomingProfile.borderOpacity);
  allowedProfile.borderOpacity = Number.isFinite(rawBorderOpacity)
    ? Math.max(0, Math.min(100, rawBorderOpacity))
    : (Number.isFinite(user.profile.borderOpacity) ? user.profile.borderOpacity : 20);
  if (typeof incomingProfile.showJoinDate !== 'undefined') {
    allowedProfile.showJoinDate = Boolean(incomingProfile.showJoinDate);
  }
  if (typeof incomingProfile.showUidTooltip !== 'undefined') {
    allowedProfile.showUidTooltip = Boolean(incomingProfile.showUidTooltip);
  }
  allowedProfile.faviconFile = typeof incomingProfile.faviconFile === 'string' ? incomingProfile.faviconFile : user.profile.faviconFile || '';
  allowedProfile.badgePosition = ['above', 'below', 'side'].includes(incomingProfile.badgePosition) ? incomingProfile.badgePosition : user.profile.badgePosition || 'below';
  allowedProfile.badgeBgColor = typeof incomingProfile.badgeBgColor === 'string' ? incomingProfile.badgeBgColor : user.profile.badgeBgColor || '#0c0e16';
  allowedProfile.badgeTextColor = typeof incomingProfile.badgeTextColor === 'string' ? incomingProfile.badgeTextColor : user.profile.badgeTextColor || '#ffffff';
  allowedProfile.badgeIconColor = typeof incomingProfile.badgeIconColor === 'string' ? incomingProfile.badgeIconColor : user.profile.badgeIconColor || '#999999';
  const rawBadgeOpacity = Number(incomingProfile.badgeBgOpacity);
  allowedProfile.badgeBgOpacity = Number.isFinite(rawBadgeOpacity) ? Math.min(100, Math.max(0, rawBadgeOpacity)) : user.profile.badgeBgOpacity || 40;
  const rawBadgeGlow = Number(incomingProfile.badgeGlow);
  allowedProfile.badgeGlow = Number.isFinite(rawBadgeGlow) ? Math.min(40, Math.max(0, rawBadgeGlow)) : user.profile.badgeGlow || 12;
  const badgeShapes = ['rounded', 'pill', 'square', 'circle', 'bevel', 'soft'];
  allowedProfile.badgeShape = badgeShapes.includes(incomingProfile.badgeShape) ? incomingProfile.badgeShape : user.profile.badgeShape || 'rounded';
  const rawBadgeVis = Array.isArray(incomingProfile.badgeVisibility) ? incomingProfile.badgeVisibility : [];
  const filteredVis = filterBadges(rawBadgeVis).filter((b) => {
    const lower = String(b || '').toLowerCase();
    if (isPremiumActive(user) && lower === 'premium') return true;
    return user.badges.includes(b);
  });
  allowedProfile.badgeVisibility = filteredVis;
  allowedProfile.enterBgColor = typeof incomingProfile.enterBgColor === 'string' ? incomingProfile.enterBgColor : user.profile.enterBgColor || 'rgba(0,0,0,0.8)';
  allowedProfile.enterTextColor = typeof incomingProfile.enterTextColor === 'string' ? incomingProfile.enterTextColor : user.profile.enterTextColor || '#ffffff';
  allowedProfile.backgroundFile = typeof incomingProfile.backgroundFile === 'string' ? incomingProfile.backgroundFile : user.profile.backgroundFile || '';
  allowedProfile.bannerFile = typeof incomingProfile.bannerFile === 'string' ? incomingProfile.bannerFile : user.profile.bannerFile || '';
  allowedProfile.avatarFile = typeof incomingProfile.avatarFile === 'string' ? incomingProfile.avatarFile : user.profile.avatarFile || '';
  allowedProfile.fontFile = typeof incomingProfile.fontFile === 'string' ? incomingProfile.fontFile : user.profile.fontFile || '';
  allowedProfile.cursorFile = typeof incomingProfile.cursorFile === 'string' ? incomingProfile.cursorFile : user.profile.cursorFile || '';
  allowedProfile.decorationFile = typeof incomingProfile.decorationFile === 'string' ? incomingProfile.decorationFile : user.profile.decorationFile || '';
  const allowedTrails = ['none', 'glow', 'particles'];
  allowedProfile.cursorTrail = allowedTrails.includes(incomingProfile.cursorTrail) ? incomingProfile.cursorTrail : user.profile.cursorTrail || 'none';
  const allowedCursors = ['system', 'custom', 'trail', 'cat', 'image'];
  allowedProfile.cursor = allowedCursors.includes(incomingProfile.cursor) ? incomingProfile.cursor : user.profile.cursor || 'system';

  const layout = ['card', 'left', 'center'].includes(body.layout) ? body.layout : user.layout;
  const widgets = {
    views: body.widgets?.views || user.widgets.views,
    audio: body.widgets?.audio || user.widgets.audio,
    location: body.widgets?.location || user.widgets.location
  };

  const alias = typeof body.alias === 'string' ? body.alias.slice(0, 80) : user.alias;

  let links = Array.isArray(body.links) ? body.links : user.links;
  const oldLinkImages = (Array.isArray(user.links) ? user.links : []).map((l) => l.image).filter((x) => typeof x === 'string' && x.startsWith('/uploads/'));
  links = links
    .slice(0, 25)
    .map((link) => ({
      id: link.id || uuidv4(),
      title: String(link.title || '').slice(0, 60),
      url: String(link.url || '').slice(0, 500),
      type: ['url', 'mail', 'phone'].includes(link.type) ? link.type : 'url',
      style: ['icon', 'block'].includes(link.style) ? link.style : 'block',
      icon: link.icon || 'link',
      tooltip: String(link.tooltip || '').slice(0, 120),
      image: typeof link.image === 'string' ? link.image.slice(0, 500) : '',
      iconPlacement: ['left', 'center'].includes(link.iconPlacement) ? link.iconPlacement : 'left',
      glowColor: typeof link.glowColor === 'string' ? link.glowColor.slice(0, 50) : '',
      glowIntensity: Number.isFinite(link.glowIntensity) ? Math.max(0, Math.min(1, Number(link.glowIntensity))) : 0.6,
      bgOpacity: Number.isFinite(link.bgOpacity) ? Math.max(0, Math.min(100, Number(link.bgOpacity))) : 100
    }));
  const newLinkImages = links.map((l) => l.image).filter((x) => typeof x === 'string' && x.startsWith('/uploads/'));

  const deleteIfReplaced = (oldPath, newPath) => {
    if (!oldPath || oldPath === newPath) return;
    deleteUploadFile(oldPath);
  };
  deleteIfReplaced(oldUploads.background, allowedProfile.backgroundFile);
  deleteIfReplaced(oldUploads.banner, allowedProfile.bannerFile);
  deleteIfReplaced(oldUploads.avatar, allowedProfile.avatarFile);
  deleteIfReplaced(oldUploads.favicon, allowedProfile.faviconFile);
  deleteIfReplaced(oldUploads.font, allowedProfile.fontFile);
  deleteIfReplaced(oldUploads.cursor, allowedProfile.cursorFile);
  oldLinkImages.forEach((img) => {
    if (img && !newLinkImages.includes(img)) {
      deleteUploadFile(img);
    }
  });

  user.profile = allowedProfile;
  user.layout = layout;
  user.widgets = widgets;
  user.badges = filterBadges(user.badges || []);
  user.links = links;
  user.alias = alias;

  if (!premiumActive) {
    user.profile.sparkles = 'none';
    user.profile.overlay = 'none';
    user.profile.enterAnimation = 'none';
    user.profile.font = 'System';
    user.profile.fontFile = '';
    user.profile.seoTitle = '';
    user.profile.seoDescription = '';
  }

  writeUsers(users);
  res.json({ success: true, user: sanitizeUser(user) });
});

app.post('/api/upload', requireAuth, (req, res) => {
  if (req.user?.frozen) {
    return res.status(423).json({ error: 'Account is frozen by admin' });
  }
  uploadLimiter(req, res, () => {});
  const quota = checkUploadQuota(req.user.id, isPremiumActive(req.user));
  if (!quota.ok) {
    return res.status(429).json({ error: 'Upload rate limit exceeded', retryAfter: quota.retryAfter });
  }
  upload.single('file')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    const current = req.user || (readUsers().find((u) => u.id === req.session.user.id));
    const isPremium = isPremiumActive(current);
  const isFont =
    req.file.mimetype?.startsWith('font/') ||
    req.file.mimetype?.includes('font') ||
    ['.ttf', '.otf', '.woff', '.woff2'].some((ext) => req.file.originalname?.toLowerCase().endsWith(ext));
    if (isFont) {
      if (!isPremium) {
        fs.unlink(req.file.path, () => {});
        return res.status(403).json({ error: 'Custom fonts require premium' });
      }
      const maxFont = 10 * 1024 * 1024;
      if (req.file.size > maxFont) {
        fs.unlink(req.file.path, () => {});
        return res.status(400).json({ error: 'Font size limit 10MB' });
      }
    }
  const isVideo = req.file.mimetype.startsWith('video/');
  const isMedia = req.file.mimetype.startsWith('image/') || req.file.mimetype.startsWith('audio/');
  const maxVideo = isPremium ? 20 * 1024 * 1024 : 10 * 1024 * 1024;
  const maxMedia = isPremium ? 15 * 1024 * 1024 : 5 * 1024 * 1024;
    const isLinkImage = req.body?.purpose === 'link-image';
    if (isLinkImage) {
      const max = MAX_LINK_IMAGE_MB * 1024 * 1024;
      if (!req.file.mimetype.startsWith('image/') || req.file.size > max) {
        fs.unlink(req.file.path, () => {});
        return res.status(400).json({ error: `Link image must be an image <= ${MAX_LINK_IMAGE_MB}MB` });
      }
    }
    const overLimit =
      (isVideo && req.file.size > maxVideo) ||
      (!isVideo && !isFont && isMedia && req.file.size > maxMedia);
    if (overLimit) {
      const limitMsg = isVideo
        ? (isPremium ? 'Video limit 20MB for premium' : 'Video limit 10MB for free')
        : (isPremium ? 'Media limit 10MB for premium' : 'Media limit 5MB for free');
      fs.unlink(req.file.path, () => {});
      return res.status(400).json({ error: limitMsg });
    }
    const relative = `/uploads/${req.file.filename}`;
    res.json({ success: true, url: relative });
  });
});

app.get('/api/sparkle/:color', (req, res) => {
  const color = req.params.color.toLowerCase();
  const { user: username } = req.query;
  if (!SPARKLE_COLORS.includes(color)) {
    return res.status(404).json({ error: 'Sparkle not found' });
  }

  let allowed = Boolean(req.session.user);
  if (!allowed && username) {
    const users = readUsers();
    const target = users.find((u) => u.username === String(username).toLowerCase());
    if (target && target.profile?.sparkles === color) {
      allowed = true;
    }
  }

  if (!allowed) {
    return res.status(403).json({ error: 'Unauthorized sparkle access' });
  }

  const sparklePath = path.join(__dirname, 'data', 'assets', `sparkle_${color}.gif`);
  if (!fs.existsSync(sparklePath)) {
    return res.status(404).json({ error: 'Sparkle not found' });
  }

  res.setHeader('Content-Type', 'image/gif');
  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(sparklePath);
});

app.use('/api/admin', requireAuth, requireAdmin);

app.get('/api/admin/meta', (req, res) => {
  res.json({ badges: BADGE_OPTIONS, admin: ADMIN_USERNAME });
});

app.get('/api/admin/state', (req, res) => {
  const state = readState();
  res.json(state);
});

app.post('/api/admin/state', (req, res) => {
  const current = readState();
  const next = {
    emergencyMode: req.body?.emergencyMode === true || req.body?.emergencyMode === 'true',
    message: typeof req.body?.message === 'string' && req.body.message.trim() ? req.body.message.trim() : current.message || 'Emergency maintenance mode enabled'
  };
  writeState(next);
  res.json({ success: true, state: next });
});

app.get('/api/admin/rewards', (req, res) => {
  const rewards = readRewards();
  res.json({ rewards });
});

app.post('/api/admin/rewards', (req, res) => {
  const codeRaw = String(req.body?.code || '').trim();
  if (codeRaw.length < 4 || codeRaw.length > 32) {
    return res.status(400).json({ error: 'Code must be 4-32 characters' });
  }
  const code = codeRaw.toUpperCase();
  const rewards = readRewards();
  if (rewards.find((r) => r.code === code)) {
    return res.status(400).json({ error: 'Code already exists' });
  }
  const maxUses = Math.min(Math.max(Number(req.body?.maxUses || 1), 1), 1000);
  const expiresDays = Number(req.body?.expiresDays || 0);
  let expiresAt = null;
  if (Number.isFinite(expiresDays) && expiresDays > 0) {
    const d = new Date();
    d.setDate(d.getDate() + Math.min(expiresDays, 365));
    expiresAt = d.toISOString();
  }
  const premiumDays = Math.max(0, Number(req.body?.premiumDays || 0));
  const customBadgeSlots = Math.max(0, Number(req.body?.customBadgeSlots || 0));
  const allowOneLetter = req.body?.allowOneLetter === true || req.body?.allowOneLetter === 'true';
  const badgeList = filterBadges(req.body?.badges);

  const entry = {
    code,
    premiumDays,
    badges: badgeList,
    customBadgeSlots,
    allowOneLetter,
    maxUses,
    usesLeft: maxUses,
    expiresAt,
    createdAt: new Date().toISOString()
  };
  rewards.push(entry);
  writeRewards(rewards);
  res.json({ success: true, reward: entry, rewards });
});

app.get('/api/admin/users', (req, res) => {
  const query = String(req.query.q || '').trim().toLowerCase();
  const users = readUsers();
  const filtered = query ? users.filter((u) => u.username.includes(query)) : users;
  res.json({ users: filtered.map((u) => sanitizeUser(u)) });
});

app.get('/api/admin/users/:username', (req, res) => {
  const users = readUsers();
  const idx = findUserIndex(users, req.params.username);
  if (idx === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ user: sanitizeUser(users[idx]) });
});

app.post('/api/admin/users/:username/premium', (req, res) => {
  const users = readUsers();
  const idx = findUserIndex(users, req.params.username);
  if (idx === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  const target = users[idx];
  const premiumFlag = req.body?.premium === true || req.body?.premium === 'true';
  const daysRaw = Number(req.body?.premiumUntilDays ?? req.body?.days ?? 0);
  const safeDays = Number.isFinite(daysRaw) && daysRaw > 0 ? Math.min(daysRaw, 3650) : 0;
  if (safeDays > 0) {
    const until = new Date();
    until.setDate(until.getDate() + safeDays);
    target.premiumUntil = until.toISOString();
  } else {
    target.premiumUntil = null;
  }
  target.premium = premiumFlag || safeDays > 0;
  users[idx] = normalizeUser(target);
  writeUsers(users);
  if (req.user?.id === target.id) {
    req.session.user = { id: target.id, username: target.username, role: target.role, premium: isPremiumActive(target) };
  }
  res.json({ success: true, user: sanitizeUser(users[idx]) });
});

app.post('/api/admin/users/:username/badges/add', (req, res) => {
  const badge = canonicalBadgeName(req.body?.badge);
  if (!badge) {
    return res.status(400).json({ error: 'Invalid badge' });
  }
  const users = readUsers();
  const idx = findUserIndex(users, req.params.username);
  if (idx === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  const target = users[idx];
  if (!target.badges.includes(badge)) {
    target.badges.push(badge);
  }
  users[idx] = normalizeUser(target);
  writeUsers(users);
  res.json({ success: true, user: sanitizeUser(users[idx]) });
});

app.post('/api/admin/users/:username/badges/remove', (req, res) => {
  const badge = canonicalBadgeName(req.body?.badge);
  if (!badge) {
    return res.status(400).json({ error: 'Invalid badge' });
  }
  const users = readUsers();
  const idx = findUserIndex(users, req.params.username);
  if (idx === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  const target = users[idx];
  target.badges = (target.badges || []).filter((b) => b.toLowerCase() !== badge.toLowerCase());
  users[idx] = normalizeUser(target);
  writeUsers(users);
  res.json({ success: true, user: sanitizeUser(users[idx]) });
});

app.post('/api/admin/users/:username/freeze', (req, res) => {
  const users = readUsers();
  const idx = findUserIndex(users, req.params.username);
  if (idx === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  const target = users[idx];
  if (isAdminUser(target)) {
    return res.status(400).json({ error: 'Admin cannot be frozen' });
  }
  target.frozen = req.body?.frozen === true || req.body?.frozen === 'true';
  users[idx] = normalizeUser(target);
  writeUsers(users);
  res.json({ success: true, user: sanitizeUser(users[idx]) });
});

app.post('/api/admin/users/:username/ban', (req, res) => {
  const users = readUsers();
  const idx = findUserIndex(users, req.params.username);
  if (idx === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  const target = users[idx];
  if (isAdminUser(target)) {
    return res.status(400).json({ error: 'Admin cannot be banned' });
  }
  target.banned = req.body?.banned === true || req.body?.banned === 'true';
  if (target.banned) {
    target.frozen = true;
    target.premium = false;
  }
  users[idx] = normalizeUser(target);
  writeUsers(users);
  res.json({ success: true, user: sanitizeUser(users[idx]) });
});

app.delete('/api/admin/users/:username', (req, res) => {
  const users = readUsers();
  const idx = findUserIndex(users, req.params.username);
  if (idx === -1) {
    return res.status(404).json({ error: 'User not found' });
  }
  const target = users[idx];
  if (isAdminUser(target)) {
    return res.status(400).json({ error: 'Admin cannot be deleted' });
  }
  users.splice(idx, 1);
  writeUsers(users);
  res.json({ success: true });
});

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  next();
});

app.listen(PORT, () => {
  console.log(`BIO service running at http://localhost:${PORT}`);
});
