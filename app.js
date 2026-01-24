// FILE: app.js
require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');

const { dbRun, dbGet, dbAll, ensureColumn, initDb } = require('./db');
const { makeAudit } = require('./lib/audit');
const { attachSessionToLocals } = require('./middleware/locals');
const { sendMailOrLog } = require('./lib/mailer');

// Routers
const publicRoutes = require('./routes/public');
const authRoutes = require('./routes/auth');
const modelRoutes = require('./routes/model');
const adminRoutes = require('./routes/admin');
const secureRoutes = require('./routes/secure');
const packageAckRoutes = require('./routes/package-ack');
const docRoutes = require('./routes/doc');
const inviteRoutes = require('./routes/invite');

const app = express();

// ----------------------
// STUDIO EMAILS
// ----------------------
const STUDIO_EMAILS = Object.freeze({
  owner: 'king_nxy@lumennyxstudios.com',
  admin: 'admin@lumennyxstudios.com',
  support: 'support@lumennyxstudios.com',
  models: 'models@lumennyxstudios.com',
  release: 'release@lumennyxstudios.com',
  compliance2257: '2257@lumennyxstudios.com',
  '2257': '2257@lumennyxstudios.com',
  legal: 'legal@lumennyxstudios.com',
  billing: 'billing@lumennyxstudios.com',
  contact: 'contact@lumennyxstudios.com',
});

// ----------------------
// BASIC EXPRESS SETUP
// ----------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Minimal request logging
app.use((req, res, next) => {
  const started = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - started;
    console.log(`${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`);
  });
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ----------------------
// SESSION / COOKIE CONFIG
// ----------------------
const COOKIE_SECURE_ENV = String(process.env.COOKIE_SECURE || '').trim().toLowerCase();

// NOTE:
// Your PM2 output showed node env "N/A", meaning NODE_ENV may be unset.
// So we cannot rely on isProd alone.
const envNodeEnv = String(process.env.NODE_ENV || '').trim().toLowerCase();
const isProd = envNodeEnv === 'production';

const cookieSecure = COOKIE_SECURE_ENV.length > 0 ? COOKIE_SECURE_ENV === 'true' : isProd;

// Optional: cookie max age in days
const COOKIE_MAX_AGE_DAYS = parseInt(process.env.COOKIE_MAX_AGE_DAYS || '7', 10);
const cookieMaxAgeMs =
  Number.isFinite(COOKIE_MAX_AGE_DAYS) && COOKIE_MAX_AGE_DAYS > 0
    ? COOKIE_MAX_AGE_DAYS * 24 * 60 * 60 * 1000
    : 7 * 24 * 60 * 60 * 1000;

// ----------------------
// TRUST PROXY (CRITICAL BEHIND NGINX/HTTPS)
// ----------------------
// If cookieSecure is true (HTTPS cookie), we MUST trust proxy,
// otherwise req.secure can be wrong and sessions can behave inconsistently.
const envTrustProxy = String(process.env.TRUST_PROXY || '').trim().toLowerCase();

// Default behavior:
// - If COOKIE_SECURE is true => trust proxy ON (required behind Nginx)
// - else => trust proxy depends on NODE_ENV production
let trustProxyEnabled = cookieSecure ? true : isProd;

// Allow explicit override
if (envTrustProxy === 'true') trustProxyEnabled = true;
if (envTrustProxy === 'false') trustProxyEnabled = false;

app.set('trust proxy', trustProxyEnabled ? 1 : false);

// ----------------------
// ✅ PERSISTENT SESSION STORE (SQLite)
// ----------------------
const SQLiteStore = require('connect-sqlite3')(session);

// Put session DB inside a runtime dir
const runtimeDir = path.join(__dirname, 'runtime');
if (!fs.existsSync(runtimeDir)) fs.mkdirSync(runtimeDir, { recursive: true });

const sessionDbPath = path.join(runtimeDir, 'sessions.sqlite');

app.use(
  session({
    // ✅ HARD-CODE cookie name so you can VERIFY you're running THIS build.
    // If you still see connect.sid, you are NOT running this file in production.
    name: 'lumennyx.sid',

    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,

    // IMPORTANT: behind proxy when using secure cookies
    proxy: true,

    store: new SQLiteStore({
      db: path.basename(sessionDbPath),
      dir: runtimeDir,
    }),

    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: cookieSecure,
      maxAge: cookieMaxAgeMs,
    },
  })
);

// ----------------------
// UPLOAD DIRS
// ----------------------
const uploadsRoot = path.join(__dirname, 'uploads');
const uploadDirs = {
  uploadsRoot,
  idUploadsDir: path.join(uploadsRoot, 'ids'),
  docUploadsDir: path.join(uploadsRoot, 'docs'),
  photoUploadsDir: path.join(uploadsRoot, 'photos'),
  sceneUploadsDir: path.join(uploadsRoot, 'scenes'),
  signatureUploadsDir: path.join(uploadsRoot, 'signatures'),
};

for (const dir of Object.values(uploadDirs)) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// ----------------------
// DB API SHIM
// ----------------------
const dbApi = Object.freeze({
  dbRun,
  dbGet,
  dbAll,
  ensureColumn,
  initDb,
});

// ----------------------
// AUDIT + CTX
// ----------------------
const audit = makeAudit(dbApi);

function getClientIp(req) {
  const xf = (req.headers['x-forwarded-for'] || '').toString();
  if (xf) return xf.split(',')[0].trim();
  return req.ip || req.connection?.remoteAddress || null;
}

const ctx = Object.freeze({
  STUDIO_EMAILS,
  db: dbApi,
  audit,
  security: { getClientIp },
  uploadDirs,
});

// Locals middleware (makes session + studio emails available in views)
app.use(attachSessionToLocals({ STUDIO_EMAILS }));

// ----------------------
// STATIC MOUNTS
// ----------------------
app.use('/css', express.static(path.join(__dirname, 'public', 'css')));
app.use('/img', express.static(path.join(__dirname, 'public', 'img')));
app.use('/js', express.static(path.join(__dirname, 'public', 'js')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/public', express.static(path.join(__dirname, 'public')));

// ============================================================
// DEBUG: session + cookie inspection
// Visit: /__session_debug
// ============================================================
app.get('/__session_debug', (req, res) => {
  res.json({
    ok: true,
    now: new Date().toISOString(),
    nodeEnv: process.env.NODE_ENV || null,
    trustProxy: app.get('trust proxy'),
    reqSecure: !!req.secure,
    xForwardedProto: req.headers['x-forwarded-proto'] || null,
    cookieSecure,
    sessionCookieName: 'lumennyx.sid',
    sessionId: req.sessionID || null,
    hasSession: !!req.session,
    ageConfirmed: !!req.session?.ageConfirmed,
    user: req.session?.user
      ? { id: req.session.user.id, username: req.session.user.username, role: req.session.user.role }
      : null,
  });
});

// ============================================================
// DEBUG: SMTP + mail sending test
// Visit: /__mail_test?to=you@domain.com
// ============================================================
app.get('/__mail_test', async (req, res) => {
  try {
    const to = String(req.query.to || process.env.MAIL_TO_STUDIO || '').trim();
    if (!to) return res.status(400).json({ ok: false, error: 'Missing ?to= email' });

    const subject = `Mail test (${new Date().toISOString()})`;
    const text = `This is a test email from LumenNyx Studios server.\n\nIf you received this, SMTP is working.`;

    const result = await sendMailOrLog({ to, subject, text });
    return res.status(result.ok ? 200 : 500).json(result);
  } catch (e) {
    console.error('/__mail_test error:', e);
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

// ----------------------
// ROUTES
// ----------------------
app.use('/', publicRoutes(ctx));
app.use('/', authRoutes(ctx));
app.use('/', inviteRoutes(ctx));
app.use('/', modelRoutes(ctx));
app.use('/', adminRoutes(ctx));
app.use('/', secureRoutes(ctx));
app.use('/', packageAckRoutes(ctx));
app.use('/', docRoutes(ctx));

// 404
app.use((req, res) => res.status(404).render('error', { message: 'Page not found.' }));

// Error handler
app.use((err, req, res, _next) => {
  console.error('UNHANDLED ERROR:', err);
  if (res.headersSent) return;

  const prod = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
  const msg = prod ? 'Server error.' : err?.message || 'Server error.';

  try {
    return res.status(500).render('error', { message: msg });
  } catch (_e) {
    return res.status(500).send(msg);
  }
});

// ----------------------
// START SERVER
// ----------------------
const PORT = parseInt(process.env.PORT || '3001', 10);

(async () => {
  try {
    if (typeof dbApi.initDb === 'function') await dbApi.initDb();

    console.log('MAIL CONFIG =>', {
      SMTP_HOST: process.env.SMTP_HOST || null,
      SMTP_PORT: process.env.SMTP_PORT || null,
      SMTP_SECURE: process.env.SMTP_SECURE || null,
      SMTP_USER: process.env.SMTP_USER || null,
      MAIL_LOG_ONLY: process.env.MAIL_LOG_ONLY || null,
      MAIL_VERIFY: process.env.MAIL_VERIFY || null,
      MAIL_TO_MODELS_APPLY: process.env.MAIL_TO_MODELS_APPLY || null,
    });

    console.log('SESSION CONFIG =>', {
      nodeEnv: process.env.NODE_ENV || null,
      trustProxy: app.get('trust proxy'),
      cookieSecure,
      sameSite: 'lax',
      cookieMaxAgeDays: Math.round(cookieMaxAgeMs / (24 * 60 * 60 * 1000)),
      sessionDbPath,
      cookieName: 'lumennyx.sid',
    });

    app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
  } catch (e) {
    console.error('Fatal startup error:', e);
    process.exit(1);
  }
})();
