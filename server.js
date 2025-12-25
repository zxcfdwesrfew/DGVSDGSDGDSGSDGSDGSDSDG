
const express = require('express');
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
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
const SPARKLE_COLORS = [
  'black',
  'blue',
  'green',
  'pink',
  'red',
  'white',
  'yellow'
];

function ensureStorage() {
  fs.mkdirSync(path.dirname(USERS_FILE), { recursive: true });
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) {
    fs.writeFileSync(USERS_FILE, '[]', 'utf8');
  }
}

function readUsers() {
  ensureStorage();
  try {
    const raw = fs.readFileSync(USERS_FILE, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    console.error('Failed to read users.json', err);
    return [];
  }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function sanitizeUser(user) {
  if (!user) return null;
  const clone = { ...user };
  delete clone.password;
  return clone;
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
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'bio-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 30
    }
  })
);

app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
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
    const allowed = ['image/', 'audio/', 'video/'];
    if (allowed.some((prefix) => file.mimetype.startsWith(prefix))) {
      cb(null, true);
    } else {
      cb(new Error('Only image, audio or video uploads are allowed'));
    }
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
  res.sendFile(path.join(__dirname, 'views', 'dashboard-advanced.html'));
});

app.get('/u/:username', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'profile.html'));
});

app.post('/api/register', async (req, res) => {
  const { username, password, plan } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const normalized = username.trim().toLowerCase();
  const premiumRequested = plan === 'premium';
  const minLength = premiumRequested ? 2 : 3;

  if (normalized.length < minLength || normalized.length > 20) {
    return res
      .status(400)
      .json({ error: premiumRequested ? 'Short usernames are a premium perk (2+ symbols)' : 'Username must be 3-20 chars' });
  }

  if (!/^[a-z0-9_]+$/i.test(normalized)) {
    return res.status(400).json({ error: 'Only letters, numbers and underscore are allowed' });
  }

  const users = readUsers();
  if (users.find((u) => u.username === normalized)) {
    return res.status(400).json({ error: 'Username already exists' });
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
      premium: premiumRequested,
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
      createdAt: now
    };

    users.push(user);
    writeUsers(users);
    req.session.user = { id: user.id, username: user.username, premium: user.premium };
    res.json({ success: true, redirect: '/dashboard', user: sanitizeUser(user) });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
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

  req.session.user = { id: user.id, username: user.username, premium: user.premium };
  res.json({ success: true, redirect: '/dashboard', user: sanitizeUser(user) });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  const users = readUsers();
  const current = users.find((u) => u.id === req.session.user.id);
  if (!current) {
    return res.status(401).json({ error: 'User not found' });
  }
  res.json({ user: sanitizeUser(current) });
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
  const body = req.body;
  const users = readUsers();
  const idx = users.findIndex((u) => u.id === req.session.user.id);
  if (idx === -1) {
    return res.status(401).json({ error: 'User not found' });
  }

  const user = users[idx];

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
  if (typeof incomingProfile.showJoinDate !== 'undefined') {
    allowedProfile.showJoinDate = Boolean(incomingProfile.showJoinDate);
  }
  if (typeof incomingProfile.showUidTooltip !== 'undefined') {
    allowedProfile.showUidTooltip = Boolean(incomingProfile.showUidTooltip);
  }
  allowedProfile.faviconFile = typeof incomingProfile.faviconFile === 'string' ? incomingProfile.faviconFile : user.profile.faviconFile || '';
  allowedProfile.badgePosition = ['above', 'below', 'side'].includes(incomingProfile.badgePosition) ? incomingProfile.badgePosition : user.profile.badgePosition || 'below';
  allowedProfile.enterBgColor = typeof incomingProfile.enterBgColor === 'string' ? incomingProfile.enterBgColor : user.profile.enterBgColor || 'rgba(0,0,0,0.8)';
  allowedProfile.enterTextColor = typeof incomingProfile.enterTextColor === 'string' ? incomingProfile.enterTextColor : user.profile.enterTextColor || '#ffffff';

  const layout = ['card', 'left', 'center'].includes(body.layout) ? body.layout : user.layout;
  const widgets = {
    views: body.widgets?.views || user.widgets.views,
    audio: body.widgets?.audio || user.widgets.audio,
    location: body.widgets?.location || user.widgets.location
  };

  const badges = Array.isArray(body.badges) ? body.badges.slice(0, 20) : user.badges;
  const alias = typeof body.alias === 'string' ? body.alias.slice(0, 80) : user.alias;

  let links = Array.isArray(body.links) ? body.links : user.links;
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
      image: typeof link.image === 'string' ? link.image.slice(0, 500) : ''
    }));

  user.profile = allowedProfile;
  user.layout = layout;
  user.widgets = widgets;
  user.badges = badges;
  user.links = links;
  user.alias = alias;

  if (!user.premium) {
    user.profile.sparkles = 'none';
    user.profile.overlay = 'none';
    user.profile.enterAnimation = 'none';
    user.profile.font = 'System';
    user.profile.seoTitle = '';
    user.profile.seoDescription = '';
  }

  writeUsers(users);
  res.json({ success: true, user: sanitizeUser(user) });
});

app.post('/api/upload', requireAuth, (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ error: err.message });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    const users = readUsers();
    const current = users.find((u) => u.id === req.session.user.id);
    const isPremium = Boolean(current?.premium);
    const maxVideo = isPremium ? 20 * 1024 * 1024 : 10 * 1024 * 1024;
    if (req.file.mimetype.startsWith('video/') && req.file.size > maxVideo) {
      fs.unlink(req.file.path, () => {});
      return res.status(400).json({ error: isPremium ? 'Video limit 20MB for premium' : 'Video limit 10MB for free' });
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

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  next();
});

app.listen(PORT, () => {
  console.log(`BIO service running at http://localhost:${PORT}`);
});
