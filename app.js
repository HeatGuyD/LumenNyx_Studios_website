// FILE: app.js
require('dotenv').config();

const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');

const { dbRun, dbGet, dbAll, ensureColumn, initDb } = require('./db');
const { makeAudit } = require('./lib/audit');
const { attachSessionToLocals } = require('./middleware/locals');
const { sendMailOrLog } = require('./lib/mailer'); // ✅ NEW: for /__mail_test

// Routers
const publicRoutes = require('./routes/public');
const authRoutes = require('./routes/auth');
const modelRoutes = require('./routes/model');
const adminRoutes = require('./routes/admin');
const secureRoutes = require('./routes/secure');
const packageAckRoutes = require('./routes/package-ack');
const docRoutes = require('./routes/doc');
const inviteRoutes = require('./routes/invite'); // ✅ NEW

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

// Respect TRUST_PROXY flag
const TRUST_PROXY = String(process.env.TRUST_PROXY || 'false').toLowerCase() === 'true';
if (TRUST_PROXY) {
  app.set('trust proxy', 1);
} else {
  app.set('trust proxy', false);
}

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

// Cookie secure behavior
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || '').trim();
const cookieSecure =
  COOKIE_SECURE.length > 0 ? COOKIE_SECURE.toLowerCase() === 'true' : process.env.NODE_ENV === 'production';

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: cookieSecure,
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
// ✅ DEBUG: SMTP + mail sending test
// Visit: http://localhost:3001/__mail_test?to=you@domain.com
// ============================================================
app.get('/__mail_test', async (req, res) => {
  try {
    const to = String(req.query.to || process.env.MAIL_TO_STUDIO || '').trim();
    if (!to) return res.status(400).json({ ok: false, error: 'Missing ?to= email' });

    const subject = `Mail test (${new Date().toISOString()})`;
    const text = `This is a test email from LumenNyx Studios local server.\n\nIf you received this, SMTP is working.`;

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
app.use('/', inviteRoutes(ctx)); // ✅ NEW (token accept + account creation)
app.use('/', modelRoutes(ctx));
app.use('/', adminRoutes(ctx));
app.use('/', secureRoutes(ctx));
app.use('/', packageAckRoutes(ctx));
app.use('/', docRoutes(ctx));

// 404
app.use((req, res) => {
  return res.status(404).render('error', { message: 'Page not found.' });
});

// Error handler
app.use((err, req, res, _next) => {
  console.error('UNHANDLED ERROR:', err);

  if (res.headersSent) return;

  const isProd = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
  const msg = isProd ? 'Server error.' : (err && err.message) ? err.message : 'Server error.';

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
    if (typeof dbApi.initDb === 'function') {
      await dbApi.initDb();
    }

    // ✅ Log SMTP config presence (not password)
    console.log('MAIL CONFIG =>', {
      SMTP_HOST: process.env.SMTP_HOST || null,
      SMTP_PORT: process.env.SMTP_PORT || null,
      SMTP_SECURE: process.env.SMTP_SECURE || null,
      SMTP_USER: process.env.SMTP_USER || null,
      MAIL_LOG_ONLY: process.env.MAIL_LOG_ONLY || null,
      MAIL_VERIFY: process.env.MAIL_VERIFY || null,
      MAIL_TO_MODELS_APPLY: process.env.MAIL_TO_MODELS_APPLY || null,
    });

    app.listen(PORT, () => {
      console.log(`Server listening on port ${PORT}`);
    });
  } catch (e) {
    console.error('Fatal startup error:', e);
    process.exit(1);
  }
})();
