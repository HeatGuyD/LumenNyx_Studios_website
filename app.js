require('dotenv').config();

const path = require('path');
const fs = require('fs');

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
// ----------------------
// NODEMAILER (SMTP) - TEST + HELPERS
// ----------------------


// Puppeteer is used to render your existing EJS "print" templates into a true PDF.
// Install once: npm i puppeteer
let puppeteer = null;
try {
  // eslint-disable-next-line global-require
  puppeteer = require('puppeteer');
} catch (_e) {
  puppeteer = null;
}

const app = express();

const nodemailer = require('nodemailer');

function makeMailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = String(process.env.SMTP_SECURE || 'false') === 'true';
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    throw new Error('SMTP is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASS in .env');
  }

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });
}

// Quick SMTP sanity test
app.get('/__email-test', async (req, res) => {
  try {
    const transporter = makeMailer();
    await transporter.verify();

    const to = process.env.MAIL_TO_STUDIO || process.env.SMTP_USER;

    await transporter.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to,
      replyTo: process.env.MAIL_REPLY_TO || undefined,
      subject: 'LumenNyx SMTP test',
      text: 'SMTP is working.',
    });

    return res.send('EMAIL SENT');
  } catch (e) {
    console.error('EMAIL TEST FAIL:', e);
    return res.status(500).send(String(e?.message || e));
  }
});

// Simple health check (safe)
app.get('/__running', (req, res) => res.send('RUNNING app.js'));

// ----------------------
// STUDIO CONTACT EMAILS (DOMAIN ALIASES)
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
// ADMIN (MUST BE IN .env IN REAL USE)
// ----------------------
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'King_Nyx').trim();
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || '').trim(); // REQUIRED
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || STUDIO_EMAILS.admin).trim();

function equalsIgnoreCase(a, b) {
  return String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
}

// ----------------------
// BASIC EXPRESS SETUP
// ----------------------
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Trust proxy only when you actually run behind a reverse proxy (nginx, etc.)
// app.set('trust proxy', 1);

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    },
  })
);

// Static assets (SAFE)
app.use('/css', express.static(path.join(__dirname, 'public', 'css')));
app.use('/img', express.static(path.join(__dirname, 'public', 'img')));

// IMPORTANT: Do NOT expose /uploads via express.static.

// ----------------------
// DATABASE SETUP
// ----------------------
const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

// Promisified helpers
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function (err, row) {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, function (err, rows) {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

// Auto-migration helper: add column if not exists
async function ensureColumn(tableName, columnDef) {
  const [columnName] = columnDef.split(/\s+/);
  const cols = await dbAll(`PRAGMA table_info(${tableName});`);
  const exists = cols.some((c) => c.name === columnName);
  if (!exists) {
    console.log(`Adding column ${columnName} to ${tableName}`);
    await dbRun(`ALTER TABLE ${tableName} ADD COLUMN ${columnDef};`);
  }
}

// ----------------------
// INITIAL DB SCHEMA & ADMIN SEED
// ----------------------
db.serialize(async () => {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      email TEXT,
      role TEXT NOT NULL DEFAULT 'model',
      status TEXT NOT NULL DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS model_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      legal_name TEXT,
      aliases TEXT,
      preferred_name TEXT,
      date_of_birth TEXT,
      country TEXT,
      state TEXT,
      phone TEXT,
      email TEXT,
      emergency_name TEXT,
      emergency_phone TEXT,
      age_truth_ack INTEGER DEFAULT 0,
      headshot_path TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS compliance_documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      doc_type TEXT NOT NULL,
      filename TEXT NOT NULL,
      uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS model_photos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      filename TEXT NOT NULL,
      caption TEXT,
      is_primary INTEGER DEFAULT 0,
      priority INTEGER DEFAULT 0,
      uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS master_releases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      signed_name TEXT NOT NULL,
      signed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      ip_address TEXT,
      user_agent TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  
    
  // ---- Signatures (typed-styled or drawn) ----
  await dbRun(`
    CREATE TABLE IF NOT EXISTS signatures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      method TEXT NOT NULL,                 -- 'typed' or 'drawn'
      typed_name TEXT,                      -- legal name used when method='typed'
      typed_style TEXT,                     -- style key, e.g. 'style1'
      signature_png TEXT NOT NULL,          -- relative path under uploads/signatures
      initials_png TEXT,                    -- optional relative path
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      ip_address TEXT,
      user_agent TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  // Link releases to signatures (non-breaking migration)
  await ensureColumn("master_releases", "signature_id INTEGER");
  await ensureColumn("master_releases", "signature_method TEXT");
  await ensureColumn("master_releases", "signature_png TEXT");

  // Expand model_profiles for applicant vetting (non-breaking)
  await ensureColumn("model_profiles", "fullbody_path TEXT");
  await ensureColumn("model_profiles", "portfolio_url TEXT");
  await ensureColumn("model_profiles", "bio TEXT");
  await ensureColumn("model_profiles", "experience_level TEXT");
  await ensureColumn("model_profiles", "application_submitted_at DATETIME");
  await ensureColumn("model_profiles", "admin_notes TEXT");

  await dbRun(`
    CREATE TABLE IF NOT EXISTS consent_policies (
      user_id INTEGER PRIMARY KEY,
      sti_testing_routine INTEGER DEFAULT 0,
      sti_disclosure_truth INTEGER DEFAULT 0,
      sti_notes TEXT,
      consent_allows_kissing INTEGER DEFAULT 0,
      consent_allows_nudity INTEGER DEFAULT 0,
      consent_allows_rough INTEGER DEFAULT 0,
      consent_allows_choking INTEGER DEFAULT 0,
      consent_hard_limits TEXT,
      consent_soft_limits TEXT,
      policy_no_substances INTEGER DEFAULT 0,
      policy_safe_word INTEGER DEFAULT 0,
      policy_breaks INTEGER DEFAULT 0,
      policy_reporting INTEGER DEFAULT 0,
      policy_understand_no_guaranteed_removal INTEGER DEFAULT 0,
      policy_internal_requests INTEGER DEFAULT 0,
      policy_removal_notes TEXT,
      contractor_acknowledge INTEGER DEFAULT 0,
      contractor_signature TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);


    
    // Migrate consent_policies for portal-first scene limits
  await ensureColumn("consent_policies", "consent_json TEXT");
  await ensureColumn("consent_policies", "consent_version TEXT");

  await dbRun(`
    CREATE TABLE IF NOT EXISTS scenes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      shoot_date TEXT,
      video_ref TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);


  await dbRun(`
    CREATE TABLE IF NOT EXISTS scene_models (
      scene_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      PRIMARY KEY (scene_id, user_id),
      FOREIGN KEY(scene_id) REFERENCES scenes(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  await ensureColumn('model_profiles', 'preferred_name TEXT');
  await ensureColumn('model_profiles', 'headshot_path TEXT');
  await ensureColumn('consent_policies', 'created_at DATETIME');

  // Seed / ensure admin account in DB
  try {
    if (!ADMIN_PASSWORD) {
      console.warn('WARNING: ADMIN_PASSWORD is not set in .env.');
    } else {
      const existingAdmin = await dbGet(
        `SELECT * FROM users WHERE LOWER(username) = ? LIMIT 1`,
        [ADMIN_USERNAME.toLowerCase()]
      );

      const adminHash = await bcrypt.hash(ADMIN_PASSWORD, 12);

      if (!existingAdmin) {
        await dbRun(
          `INSERT INTO users (username, password_hash, email, role, status)
           VALUES (?, ?, ?, 'admin', 'approved')`,
          [ADMIN_USERNAME, adminHash, ADMIN_EMAIL]
        );
        console.log('Admin account created:', ADMIN_USERNAME);
      } else {
        await dbRun(
          `UPDATE users
           SET password_hash = ?, email = ?, role = 'admin', status = 'approved'
           WHERE id = ?`,
          [adminHash, ADMIN_EMAIL, existingAdmin.id]
        );
        console.log('Admin account verified/reset:', ADMIN_USERNAME);
      }
    }
  } catch (err) {
    console.error('Admin seed error:', err);
  }
});

// ----------------------
// MULTER UPLOAD SETUP
// ----------------------
const uploadsRoot = path.join(__dirname, 'uploads');
const idUploadsDir = path.join(uploadsRoot, 'ids');
const docUploadsDir = path.join(uploadsRoot, 'docs');
const photoUploadsDir = path.join(uploadsRoot, 'photos');
const sceneUploadsDir = path.join(uploadsRoot, 'scenes');
const signatureUploadsDir = path.join(uploadsRoot, 'signatures');

for (const dir of [uploadsRoot, idUploadsDir, docUploadsDir, photoUploadsDir, sceneUploadsDir, signatureUploadsDir]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function safeExt(originalName) {
  const ext = path.extname(originalName || '').toLowerCase();
  return ext || '';
}

const documentStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, docUploadsDir),
  filename: (req, file, cb) => {
    const userPart = req.session.user ? `${req.session.user.id}_` : 'anonymous_';
    const uniqueName =
      userPart + Date.now() + '_' + Math.random().toString(36).slice(2) + safeExt(file.originalname);
    cb(null, uniqueName);
  },
});

const photoStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, photoUploadsDir),
  filename: (req, file, cb) => {
    const userPart = req.session.user ? `${req.session.user.id}_` : 'anonymous_';
    const uniqueName =
      userPart + Date.now() + '_' + Math.random().toString(36).slice(2) + safeExt(file.originalname);
    cb(null, uniqueName);
  },
});

const sceneStorage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, sceneUploadsDir),
  filename: (_req, file, cb) => {
    const uniqueName =
      Date.now() + '_' + Math.random().toString(36).slice(2) + safeExt(file.originalname);
    cb(null, uniqueName);
  },
});

const uploadDocument = multer({ storage: documentStorage, limits: { fileSize: 20 * 1024 * 1024 } });
const uploadPhoto = multer({ storage: photoStorage, limits: { fileSize: 10 * 1024 * 1024 } });
const uploadSceneFile = multer({ storage: sceneStorage, limits: { fileSize: 5 * 1024 * 1024 * 1024 } });

// ----------------------
// SESSION → LOCALS
// ----------------------
function attachSessionToLocals(req, res, next) {
  res.locals.currentUser = req.session.user || null;
  res.locals.message = req.session.message || null;
  res.locals.error = req.session.error || null;

  res.locals.CONTACT_EMAILS = STUDIO_EMAILS;
  res.locals.studioEmails = STUDIO_EMAILS;

  delete req.session.message;
  delete req.session.error;
  next();
}
app.use(attachSessionToLocals);

// ----------------------
// AUTH / ROLE HELPERS
// ----------------------
function ensureLoggedIn(req, res, next) {
  if (!req.session.user) {
    req.session.error = 'Please log in to access that page.';
    return res.redirect('/login');
  }
  next();
}

function ensureAgeConfirmed(req, res, next) {
  if (!req.session.ageConfirmed) return res.redirect('/age-check');
  next();
}

function ensureAdmin(req, res, next) {
  if (!req.session.ageConfirmed) return res.redirect('/age-check');
  if (!req.session.user) {
    req.session.error = 'Admin / staff access only.';
    return res.redirect('/login');
  }
  const role = req.session.user.role;
  if (role !== 'admin' && role !== 'staff') {
    req.session.error = 'Admin / staff access only.';
    return res.redirect('/login');
  }
  next();
}

function ensureModel(req, res, next) {
  if (!req.session.ageConfirmed) return res.redirect('/age-check');
  if (!req.session.user || req.session.user.role !== 'model') {
    req.session.error = 'Model access only.';
    return res.redirect('/login');
  }
  next();
}

// ----------------------
// PROTECTED UPLOAD SERVING (NO PUBLIC /uploads)
// ----------------------
function sanitizeFilename(name) {
  return path.basename(String(name || ''));
}

async function canAccessUserFile(req, fileOwnerUserId) {
  if (!req.session.user) return false;
  const role = req.session.user.role;
  if (role === 'admin' || role === 'staff') return true;
  if (role === 'model' && Number(req.session.user.id) === Number(fileOwnerUserId)) return true;
  return false;
}

// Docs: require login + owner/admin
app.get('/uploads/docs/:filename', ensureAgeConfirmed, ensureLoggedIn, async (req, res) => {
  const filename = sanitizeFilename(req.params.filename);
  try {
    const doc = await dbGet(
      `SELECT user_id, filename FROM compliance_documents WHERE filename = ? LIMIT 1`,
      [filename]
    );
    if (!doc) return res.status(404).send('Not found');
    const allowed = await canAccessUserFile(req, doc.user_id);
    if (!allowed) return res.status(403).send('Forbidden');
    return res.sendFile(path.join(docUploadsDir, filename));
  } catch (err) {
    console.error('Doc serve error:', err);
    return res.status(500).send('Server error');
  }
});

// Photos: require login + owner/admin
app.get('/uploads/photos/:filename', ensureAgeConfirmed, ensureLoggedIn, async (req, res) => {
  const filename = sanitizeFilename(req.params.filename);
  try {
    let owner = await dbGet(`SELECT user_id FROM model_photos WHERE filename = ? LIMIT 1`, [filename]);
    if (!owner) owner = await dbGet(`SELECT user_id FROM model_profiles WHERE headshot_path = ? LIMIT 1`, [filename]);
    if (!owner) return res.status(404).send('Not found');
    const allowed = await canAccessUserFile(req, owner.user_id);
    if (!allowed) return res.status(403).send('Forbidden');
    return res.sendFile(path.join(photoUploadsDir, filename));
  } catch (err) {
    console.error('Photo serve error:', err);
    return res.status(500).send('Server error');
  }
});

// Scenes: admin/staff only

app.get('/uploads/signatures/:filename', ensureAgeConfirmed, ensureLoggedIn, async (req, res) => {
  const filename = sanitizeFilename(req.params.filename);
  try {
    const owner = await dbGet(
      `SELECT user_id FROM signatures WHERE signature_png = ? OR initials_png = ? LIMIT 1`,
      [filename, filename]
    );
    if (!owner) return res.status(404).send('Not found');
    const allowed = await canAccessUserFile(req, owner.user_id);
    if (!allowed) return res.status(403).send('Forbidden');
    return res.sendFile(path.join(signatureUploadsDir, filename));
  } catch (err) {
    console.error('Signature serve error:', err);
    return res.status(500).send('Server error');
  }
});


app.get('/uploads/scenes/:filename', ensureAdmin, async (req, res) => {
  const filename = sanitizeFilename(req.params.filename);
  try {
    const scene = await dbGet(`SELECT id FROM scenes WHERE video_ref = ? LIMIT 1`, [filename]);
    if (!scene) return res.status(404).send('Not found');
    return res.sendFile(path.join(sceneUploadsDir, filename));
  } catch (err) {
    console.error('Scene serve error:', err);
    return res.status(500).send('Server error');
  }
});

// IDs: admin-only
app.get('/uploads/ids/:filename', ensureAdmin, (req, res) => {
  const filename = sanitizeFilename(req.params.filename);
  return res.sendFile(path.join(idUploadsDir, filename));
});

// ----------------------
// AGE GATE + LANDING
// ----------------------
app.get('/age-check', (req, res) => {
  if (!req.session.ageConfirmed) {
    return res.render('age-gate', { title: 'LumenNyx Studios – 18+ Portal', error: null });
  }
  return res.redirect('/');
});

app.post('/age-check', (req, res) => {
  const over18 = req.body.over18 === 'yes' || req.body.age_confirm === 'yes';
  if (!over18) {
    return res.render('age-gate', {
      title: 'LumenNyx Studios – 18+ Portal',
      error: 'You must confirm that you are at least 18 years old (21+ in some locations) to access this site.',
    });
  }
  req.session.ageConfirmed = true;
  return res.redirect('/');
});

app.get('/', (req, res) => {
  if (!req.session.ageConfirmed) return res.redirect('/age-check');

  if (req.session.user) {
    const role = req.session.user.role;
    if (role === 'admin' || role === 'staff') return res.redirect('/studio-panel');
    if (role === 'model') return res.redirect('/model/profile');
  }

  return res.render('video', { video: { title: 'LumenNyx Studios – Private Model Portal' } });
});

// ----------------------
// AUTH ROUTES
// ----------------------
app.get('/login', ensureAgeConfirmed, (req, res) => res.render('login'));

app.post('/login', ensureAgeConfirmed, async (req, res) => {
  const { username, password } = req.body;
  const normalizedUsername = (username || '').trim().toLowerCase();

  try {
    const user = await dbGet('SELECT * FROM users WHERE LOWER(username) = ?', [normalizedUsername]);

    if (!user) {
      req.session.error = 'Invalid username or password.';
      return res.redirect('/login');
    }

    const valid = await bcrypt.compare(String(password || ''), user.password_hash);
    if (!valid) {
      req.session.error = 'Invalid username or password.';
      return res.redirect('/login');
    }

    if (user.role === 'model' && user.status === 'pending') {
      req.session.error = 'Your model account is still pending review. We will contact you once it is approved.';
      return res.redirect('/login');
    }

    req.session.user = { id: user.id, username: user.username, role: user.role, status: user.status };

    if (user.role === 'admin' || user.role === 'staff') return res.redirect('/studio-panel');
    return res.redirect('/model/profile');
  } catch (err) {
    console.error('Login error:', err);
    req.session.error = 'An error occurred while trying to log you in.';
    return res.redirect('/login');
  }
});

app.get('/register', ensureAgeConfirmed, (req, res) => res.render('register'));

app.post(
  '/register',
  ensureAgeConfirmed,
  uploadPhoto.fields([
    { name: 'headshot', maxCount: 1 },
    { name: 'fullbody', maxCount: 1 },
  ]),
  async (req, res) => {
    const { username, password, email, portfolio_url, bio, experience_level } = req.body;
    const normalizedUsername = (username || '').trim();
    const normalizedEmail = (email || '').trim();

    if (!normalizedUsername || !password) {
      req.session.error = 'Username and password are required.';
      return res.redirect('/register');
    }

    if (equalsIgnoreCase(normalizedUsername, ADMIN_USERNAME)) {
      req.session.error = 'That username is not available.';
      return res.redirect('/register');
    }

    // Optional vetting assets
    const headshotFile = req.files?.headshot?.[0];
    const fullbodyFile = req.files?.fullbody?.[0];
    const headshotPath = headshotFile ? headshotFile.filename : null;
    const fullbodyPath = fullbodyFile ? fullbodyFile.filename : null;

    try {
      const hash = await bcrypt.hash(password, 10);

      const stmt = await dbRun(
        `INSERT INTO users (username, password_hash, email, role, status)
         VALUES (?, ?, ?, 'model', 'pending')`,
        [normalizedUsername, hash, normalizedEmail]
      );
      const newUserId = stmt.lastID;

      // Create (or update) the model profile immediately so admin can vet before approval.
      await dbRun(
        `INSERT INTO model_profiles (user_id, email, headshot_path, fullbody_path, portfolio_url, bio, experience_level, application_submitted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
         `,
        [
          newUserId,
          normalizedEmail || null,
          headshotPath,
          fullbodyPath,
          (portfolio_url || '').trim() || null,
          (bio || '').trim() || null,
          (experience_level || '').trim() || null,
        ]
      );

      req.session.message =
        'Application submitted. Your profile is pending review. You may log in to complete any additional details, but you will not be fully approved until the studio reviews your application.';
      return res.redirect('/login');
    } catch (err) {
      console.error('Register error:', err);
      req.session.error = 'Could not create account. Please try again.';
      return res.redirect('/register');
    }
  }
);

// Logout
function doLogout(req, res) {
  req.session.destroy(() => res.redirect('/age-check'));
}
app.get('/logout', (req, res) => doLogout(req, res));
app.post('/logout', (req, res) => doLogout(req, res));

// ----------------------
// STATIC / LEGAL PAGES
// ----------------------
app.get('/privacy', ensureAgeConfirmed, (req, res) => res.render('privacy'));
app.get('/terms', ensureAgeConfirmed, (req, res) => res.render('terms'));
app.get('/2257', ensureAgeConfirmed, (req, res) => res.render('2257'));

// ----------------------
// MODEL PORTAL
// ----------------------
async function loadModelProfile(userId) {
  try {
    const profile = await dbGet('SELECT * FROM model_profiles WHERE user_id = ?', [userId]);

    const documents = await dbAll(
      'SELECT * FROM compliance_documents WHERE user_id = ? ORDER BY uploaded_at DESC',
      [userId]
    );

    const photos = await dbAll(
      'SELECT * FROM model_photos WHERE user_id = ? ORDER BY is_primary DESC, priority DESC, uploaded_at DESC',
      [userId]
    );

    const masterRelease = await dbGet(
      'SELECT * FROM master_releases WHERE user_id = ? ORDER BY signed_at DESC LIMIT 1',
      [userId]
    );

    const policies = await dbGet('SELECT * FROM consent_policies WHERE user_id = ? LIMIT 1', [userId]);

    return { profile, documents, photos, masterRelease, policies };
  } catch (err) {
    console.error('Error loading model profile:', err);
    return { profile: null, documents: [], photos: [], masterRelease: null, policies: null };
  }
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff && typeof xff === 'string') {
    return xff.split(',')[0].trim();
  }
  return (req.ip || req.connection?.remoteAddress || '').toString();
}

app.get('/model/profile', ensureModel, async (req, res) => {
  const userId = req.session.user.id;
  const { profile, documents, photos, masterRelease, policies } = await loadModelProfile(userId);
  res.render('model-profile', { profile, documents, photos, masterRelease, policies });
});


// ----------------------
// SIGNATURE SETUP (Hybrid: typed-styled + drawn)
// ----------------------
app.get('/model/signature', ensureModel, async (req, res) => {
  const userId = req.session.user.id;
  const sig = await dbGet(
    `SELECT * FROM signatures WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`,
    [userId]
  );
  res.render('model-signature', { signature: sig });
});

app.post('/model/signature', ensureModel, async (req, res) => {
  const userId = req.session.user.id;
  const { method, typed_name, typed_style, signature_data_url, initials_data_url } = req.body;

  if (!method || !signature_data_url) {
    req.session.error = 'Please provide a signature.';
    return res.redirect('/model/signature');
  }

  const ua = req.headers['user-agent'] || '';
  const ip = getClientIp(req);

  function saveDataUrlPng(dataUrl, prefix) {
    const m = String(dataUrl || '').match(/^data:image\/png;base64,(.+)$/);
    if (!m) return null;
    const buf = Buffer.from(m[1], 'base64');
    const name = `${Date.now()}_${Math.random().toString(36).slice(2)}_${prefix}.png`;
    const fullPath = path.join(signatureUploadsDir, name);
    fs.writeFileSync(fullPath, buf);
    return name; // store filename only
  }

  try {
    const sigFile = saveDataUrlPng(signature_data_url, 'sig');
    const initFile = initials_data_url ? saveDataUrlPng(initials_data_url, 'init') : null;

    if (!sigFile) {
      req.session.error = 'Signature format not recognized. Please try again.';
      return res.redirect('/model/signature');
    }

    await dbRun(
      `INSERT INTO signatures (user_id, method, typed_name, typed_style, signature_png, initials_png, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId,
        String(method),
        (typed_name || '').trim() || null,
        (typed_style || '').trim() || null,
        sigFile,
        initFile,
        ip,
        ua,
      ]
    );

    req.session.message = 'Signature saved.';
    return res.redirect('/model/profile');
  } catch (err) {
    console.error('Signature save error:', err);
    req.session.error = 'Could not save signature.';
    return res.redirect('/model/signature');
  }
});


app.get('/model/release', ensureModel, async (req, res) => {
  const userId = req.session.user.id;
  const { profile, masterRelease } = await loadModelProfile(userId);
  res.render('model_master-release', { profile, masterRelease });
});

// FIXED: ensure userId + signed_name exist; save signature + timestamp (DB default) + IP + UA
app.post('/model/release', ensureModel, async (req, res) => {
  const userId = req.session.user.id;
  const { agree_master_release, signed_name } = req.body;

  if (!agree_master_release) {
    req.session.error = 'You must agree before signing.';
    return res.redirect('/model/release');
  }

  const name = (signed_name || '').trim();
  if (!name) {
    req.session.error = 'Please type your full legal name.';
    return res.redirect('/model/release');
  }

  try {
    const sig = await dbGet(
      `SELECT * FROM signatures WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`,
      [userId]
    );
    if (!sig) {
      req.session.error = 'Please set up your signature before signing.';
      return res.redirect('/model/signature');
    }

    await dbRun(
      `INSERT INTO master_releases (user_id, signed_name, ip_address, user_agent, signature_id, signature_method, signature_png)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        userId,
        name,
        getClientIp(req),
        req.headers['user-agent'] || '',
        sig.id,
        sig.method,
        sig.signature_png,
      ]
    );

    req.session.message = 'Master release signed and saved.';
    return res.redirect('/model/release');
  } catch (err) {
    console.error('Error saving master release:', err);
    req.session.error = 'Could not save master release.';
    return res.redirect('/model/release');
  }
});


// Backwards-compat
app.get('/model/profile/release', ensureModel, (req, res) => res.redirect('/model/release'));
app.post('/model/profile/release', ensureModel, (req, res) => res.redirect(307, '/model/release'));

app.get('/model/scenes', ensureModel, async (req, res) => {
  const userId = req.session.user.id;

  try {
    const scenes = await dbAll(
      `SELECT s.*
       FROM scenes s
       JOIN scene_models sm ON sm.scene_id = s.id
       WHERE sm.user_id = ?
       ORDER BY s.shoot_date DESC, s.created_at DESC`,
      [userId]
    );

    res.render('model-scenes', { scenes });
  } catch (err) {
    console.error('Error loading model scenes:', err);
    req.session.error = 'Could not load scenes.';
    res.redirect('/model/profile');
  }
});

// 1. BASIC IDENTITY & CONTACT
app.post('/model/profile/basic', ensureModel, async (req, res) => {
  const userId = req.session.user.id;

  const {
    legal_name,
    aliases,
    preferred_name,
    date_of_birth,
    country,
    state,
    phone,
    email,
    emergency_name,
    emergency_phone,
  } = req.body;

  if (!legal_name || !date_of_birth) {
    req.session.error = 'Legal name and date of birth are required.';
    return res.redirect('/model/profile');
  }

  try {
    const existing = await dbGet('SELECT id FROM model_profiles WHERE user_id = ?', [userId]);

    if (existing) {
      await dbRun(
        `UPDATE model_profiles
         SET legal_name = ?, aliases = ?, preferred_name = ?, date_of_birth = ?,
             country = ?, state = ?, phone = ?, email = ?, emergency_name = ?, emergency_phone = ?
         WHERE user_id = ?`,
        [
          legal_name.trim(),
          (aliases || '').trim(),
          (preferred_name || '').trim(),
          date_of_birth.trim(),
          (country || '').trim(),
          (state || '').trim(),
          (phone || '').trim(),
          (email || '').trim(),
          (emergency_name || '').trim(),
          (emergency_phone || '').trim(),
          userId,
        ]
      );
    } else {
      await dbRun(
        `INSERT INTO model_profiles (
           user_id, legal_name, aliases, preferred_name, date_of_birth,
           country, state, phone, email, emergency_name, emergency_phone
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          userId,
          legal_name.trim(),
          (aliases || '').trim(),
          (preferred_name || '').trim(),
          date_of_birth.trim(),
          (country || '').trim(),
          (state || '').trim(),
          (phone || '').trim(),
          (email || '').trim(),
          (emergency_name || '').trim(),
          (emergency_phone || '').trim(),
        ]
      );
    }

    req.session.message = 'Identity details saved.';
    res.redirect('/model/profile#identity');
  } catch (err) {
    console.error('Error saving identity details:', err);
    req.session.error = 'Could not save identity details.';
    res.redirect('/model/profile#identity');
  }
});

// 2. COMPLIANCE DOCUMENT UPLOAD
app.post('/model/profile/upload-doc', ensureModel, uploadDocument.single('document'), async (req, res) => {
  const userId = req.session.user.id;
  const { doc_type } = req.body;

  if (!req.file) {
    req.session.error = 'No file uploaded.';
    return res.redirect('/model/profile#docs');
  }

  try {
    await dbRun(
      `INSERT INTO compliance_documents (user_id, doc_type, filename)
       VALUES (?, ?, ?)`,
      [userId, doc_type || 'other', req.file.filename]
    );

    req.session.message = 'Document uploaded.';
    res.redirect('/model/profile#docs');
  } catch (err) {
    console.error('Error uploading document:', err);
    req.session.error = 'Could not upload document.';
    res.redirect('/model/profile#docs');
  }
});

// 2b. HEADSHOTS & PORTFOLIO PHOTOS
app.post('/model/profile/upload-photo', ensureModel, uploadPhoto.single('photo'), async (req, res) => {
  const userId = req.session.user.id;
  const { caption, is_primary } = req.body;

  if (!req.file) {
    req.session.error = 'No photo uploaded.';
    return res.redirect('/model/profile#photos');
  }

  try {
    if (is_primary) {
      await dbRun('UPDATE model_photos SET is_primary = 0 WHERE user_id = ?', [userId]);
    }

    await dbRun(
      `INSERT INTO model_photos (user_id, filename, caption, is_primary)
       VALUES (?, ?, ?, ?)`,
      [userId, req.file.filename, caption || '', is_primary ? 1 : 0]
    );

    if (is_primary) {
      const primaryPhoto = await dbGet(
        `SELECT filename FROM model_photos
         WHERE user_id = ? AND is_primary = 1
         ORDER BY uploaded_at DESC
         LIMIT 1`,
        [userId]
      );
      if (primaryPhoto) {
        await dbRun(`UPDATE model_profiles SET headshot_path = ? WHERE user_id = ?`, [
          primaryPhoto.filename,
          userId,
        ]);
      }
    }

    req.session.message = 'Photo uploaded.';
    res.redirect('/model/profile#photos');
  } catch (err) {
    console.error('Error uploading photo:', err);
    req.session.error = 'Could not upload photo.';
    res.redirect('/model/profile#photos');
  }
});

// 4. SAFETY, CONSENT & SCENE PREFERENCES
app.post('/model/profile/policies', ensureModel, async (req, res) => {
  const userId = req.session.user.id;
  const bool = (field) => req.body[field] === 'on';

  const payload = {
    sti_testing_routine: bool('sti_testing_routine'),
    sti_disclosure_truth: bool('sti_disclosure_truth'),
    sti_notes: (req.body.sti_notes || '').trim(),

    consent_allows_kissing: bool('consent_allows_kissing'),
    consent_allows_nudity: bool('consent_allows_nudity'),
    consent_allows_rough: bool('consent_allows_rough'),
    consent_allows_choking: bool('consent_allows_choking'),
    consent_hard_limits: (req.body.consent_hard_limits || '').trim(),
    consent_soft_limits: (req.body.consent_soft_limits || '').trim(),

    policy_no_substances: bool('policy_no_substances'),
    policy_safe_word: bool('policy_safe_word'),
    policy_breaks: bool('policy_breaks'),
    policy_reporting: bool('policy_reporting'),

    policy_understand_no_guaranteed_removal: bool('policy_understand_no_guaranteed_removal'),
    policy_internal_requests: bool('policy_internal_requests'),
    policy_removal_notes: (req.body.policy_removal_notes || '').trim(),

    contractor_acknowledge: bool('contractor_acknowledge'),
    contractor_signature: (req.body.contractor_signature || '').trim(),
  };

  try {
    await dbRun(
      `INSERT INTO consent_policies (
         user_id,
         sti_testing_routine,
         sti_disclosure_truth,
         sti_notes,
         consent_allows_kissing,
         consent_allows_nudity,
         consent_allows_rough,
         consent_allows_choking,
         consent_hard_limits,
         consent_soft_limits,
         policy_no_substances,
         policy_safe_word,
         policy_breaks,
         policy_reporting,
         policy_understand_no_guaranteed_removal,
         policy_internal_requests,
         policy_removal_notes,
         contractor_acknowledge,
         contractor_signature,
         created_at
       ) VALUES (
         ?,?,?,?,?,?,?,?,?,?,
         ?,?,?,?,?,?,?,?,?,
         CURRENT_TIMESTAMP
       )
       ON CONFLICT(user_id) DO UPDATE SET
         sti_testing_routine = excluded.sti_testing_routine,
         sti_disclosure_truth = excluded.sti_disclosure_truth,
         sti_notes = excluded.sti_notes,
         consent_allows_kissing = excluded.consent_allows_kissing,
         consent_allows_nudity = excluded.consent_allows_nudity,
         consent_allows_rough = excluded.consent_allows_rough,
         consent_allows_choking = excluded.consent_allows_choking,
         consent_hard_limits = excluded.consent_hard_limits,
         consent_soft_limits = excluded.consent_soft_limits,
         policy_no_substances = excluded.policy_no_substances,
         policy_safe_word = excluded.policy_safe_word,
         policy_breaks = excluded.policy_breaks,
         policy_reporting = excluded.policy_reporting,
         policy_understand_no_guaranteed_removal = excluded.policy_understand_no_guaranteed_removal,
         policy_internal_requests = excluded.policy_internal_requests,
         policy_removal_notes = excluded.policy_removal_notes,
         contractor_acknowledge = excluded.contractor_acknowledge,
         contractor_signature = excluded.contractor_signature,
         created_at = CURRENT_TIMESTAMP`,
      [
        userId,
        payload.sti_testing_routine,
        payload.sti_disclosure_truth,
        payload.sti_notes,
        payload.consent_allows_kissing,
        payload.consent_allows_nudity,
        payload.consent_allows_rough,
        payload.consent_allows_choking,
        payload.consent_hard_limits,
        payload.consent_soft_limits,
        payload.policy_no_substances,
        payload.policy_safe_word,
        payload.policy_breaks,
        payload.policy_reporting,
        payload.policy_understand_no_guaranteed_removal,
        payload.policy_internal_requests,
        payload.policy_removal_notes,
        payload.contractor_acknowledge,
        payload.contractor_signature,
      ]
    );


    // Portal-first: store full payload in JSON (prevents PDF checkbox glyph issues)
    const consentJson = JSON.stringify(payload);
    await dbRun(
      `UPDATE consent_policies SET consent_json = ?, consent_version = ? WHERE user_id = ?`,
      [consentJson, 'v1.0-2026-01-20', userId]
    );

    req.session.message = 'Safety & consent settings saved.';
    res.redirect('/model/profile#safety');
  } catch (err) {
    console.error('Error saving consent policies:', err);
    req.session.error = 'Could not save safety & consent settings.';
    res.redirect('/model/profile#safety');
  }
});

// ----------------------
// STUDIO PANEL (ADMIN)
// ----------------------
app.get('/studio-panel', ensureAdmin, async (req, res) => {
  try {
    const totalModelsRow = await dbGet("SELECT COUNT(*) AS count FROM users WHERE role = 'model'");
    const pendingModelsRow = await dbGet("SELECT COUNT(*) AS count FROM users WHERE role = 'model' AND status = 'pending'");
    const approvedModelsRow = await dbGet("SELECT COUNT(*) AS count FROM users WHERE role = 'model' AND status = 'approved'");
    const sceneCountRow = await dbGet('SELECT COUNT(*) AS count FROM scenes');

    const recentModels = await dbAll(
      `SELECT id, username, email, status, created_at
       FROM users
       WHERE role = 'model'
       ORDER BY created_at DESC
       LIMIT 5`
    );

    res.render('studio-panel', {
      stats: {
        totalModels: totalModelsRow?.count || 0,
        pendingModels: pendingModelsRow?.count || 0,
        approvedModels: approvedModelsRow?.count || 0,
        sceneCount: sceneCountRow?.count || 0,
      },
      recentModels,
      role: req.session.user.role,
      username: req.session.user.username,
      isAuthenticated: true,
    });
  } catch (err) {
    console.error('Error loading studio panel:', err);
    req.session.error = 'Could not load studio panel.';
    res.redirect('/');
  }
});

app.get('/studio-panel/models', ensureAdmin, async (req, res) => {
  try {
    const models = await dbAll(
      `SELECT u.id, u.username, u.email, u.status,
              mp.legal_name,
              mp.preferred_name,
              mp.date_of_birth,
              mp.headshot_path,
              (SELECT COUNT(*) FROM compliance_documents cd WHERE cd.user_id = u.id) AS docs_count,
              (SELECT COUNT(*) FROM model_photos p WHERE p.user_id = u.id) AS photos_count,
              (SELECT CASE WHEN COUNT(*) > 0 THEN 'Signed' ELSE 'Not signed' END
               FROM master_releases mr
               WHERE mr.user_id = u.id) AS release_status,
              (SELECT CASE WHEN COUNT(*) > 0 THEN 'Saved' ELSE 'Not completed' END
               FROM consent_policies cp
               WHERE cp.user_id = u.id) AS consent_status,
              (SELECT CASE WHEN COUNT(*) > 0 THEN 'Uploaded' ELSE 'None' END
               FROM compliance_documents cd2
               WHERE cd2.user_id = u.id AND cd2.doc_type = 'w9') AS w9_status
       FROM users u
       LEFT JOIN model_profiles mp ON mp.user_id = u.id
       WHERE u.role = 'model'
       ORDER BY u.created_at DESC`
    );

    res.render('studio-models', { models });
  } catch (err) {
    console.error('Error loading model list:', err);
    req.session.error = 'Could not load model list.';
    res.redirect('/studio-panel');
  }
});

// ----------------------
// ADMIN: Documentation Map (what's required / missing per model)
// ----------------------
app.get('/studio-panel/docs', ensureAdmin, async (req, res) => {
  try {
    const models = await dbAll(
      `SELECT u.id, u.username, u.email, u.status, u.created_at,
              mp.headshot_path, mp.fullbody_path, mp.portfolio_url, mp.experience_level, mp.application_submitted_at
       FROM users u
       LEFT JOIN model_profiles mp ON mp.user_id = u.id
       WHERE u.role='model'
       ORDER BY COALESCE(mp.application_submitted_at, u.created_at) DESC`
    );

    const rows = [];
    for (const m of models) {
      const docs = await dbAll(
        `SELECT doc_type, filename, uploaded_at
         FROM compliance_documents
         WHERE user_id = ?
         ORDER BY uploaded_at DESC`,
        [m.id]
      );

      const has = (type) => docs.some((d) => d.doc_type === type);
      const hasAny = (types) => types.some(has);

      const sig = await dbGet(`SELECT id FROM signatures WHERE user_id=? ORDER BY created_at DESC LIMIT 1`, [m.id]);
      const mr = await dbGet(`SELECT id FROM master_releases WHERE user_id=? ORDER BY signed_at DESC LIMIT 1`, [m.id]);
      const consent = await dbGet(`SELECT user_id, consent_json FROM consent_policies WHERE user_id=? LIMIT 1`, [m.id]);

      rows.push({
        ...m,
        checklist: {
          applicantPhotos: Boolean(m.headshot_path || m.fullbody_path),
          signature: Boolean(sig),
          masterRelease: Boolean(mr),
          identity: hasAny(['id_primary_front','id_primary_back','id_secondary','selfie_with_id']),
          w9: has('w9'),
          sti: has('sti_test'),
          consent: Boolean(consent && (consent.consent_json || 0)),
        },
        docs,
      });
    }

    res.render('studio-docs', { rows });
  } catch (err) {
    console.error('Studio docs map error:', err);
    req.session.error = 'Could not load documentation map.';
    return res.redirect('/studio-panel');
  }
});



app.get('/studio-panel/models/:id', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (!userId) {
    req.session.error = 'Invalid model id.';
    return res.redirect('/studio-panel/models');
  }

  try {
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user || user.role !== 'model') {
      req.session.error = 'Model account not found.';
      return res.redirect('/studio-panel/models');
    }

    const bundle = await loadModelProfile(userId);

    res.render('studio-model-view', {
      user,
      profile: bundle.profile,
      documents: bundle.documents,
      photos: bundle.photos,
      masterRelease: bundle.masterRelease,
      policies: bundle.policies,
    });
  } catch (err) {
    console.error('Error loading model inspection view:', err);
    req.session.error = 'Could not load model details.';
    res.redirect('/studio-panel/models');
  }
});

// PRINT: Identity Summary
app.get('/studio-panel/models/:id/identity', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  try {
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user || user.role !== 'model') {
      req.session.error = 'Model account not found.';
      return res.redirect('/studio-panel/models');
    }

    const profile = await dbGet('SELECT * FROM model_profiles WHERE user_id = ?', [userId]);
    const documents = await dbAll(
      'SELECT * FROM compliance_documents WHERE user_id = ? ORDER BY uploaded_at DESC',
      [userId]
    );
    const release = await dbGet(
      'SELECT * FROM master_releases WHERE user_id = ? ORDER BY signed_at DESC LIMIT 1',
      [userId]
    );
    const policies = await dbGet('SELECT * FROM consent_policies WHERE user_id = ? LIMIT 1', [userId]);

    res.render('print-model-identity', {
      user,
      modelUser: user,
      profile,
      documents,
      release,
      policies,
      generatedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error('Error loading identity print view:', err);
    req.session.error = 'Could not load identity summary.';
    res.redirect('/studio-panel/models');
  }
});

app.post('/studio-panel/models/:id/status', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const newStatus = (req.body.status || '').trim();

  if (!['pending', 'approved', 'disabled'].includes(newStatus)) {
    req.session.error = 'Invalid status.';
    return res.redirect('/studio-panel/models');
  }

  try {
    await dbRun('UPDATE users SET status = ? WHERE id = ?', [newStatus, userId]);
    req.session.message = 'Status updated.';
    res.redirect(`/studio-panel/models/${userId}`);
  } catch (err) {
    console.error('Error updating model status:', err);
    req.session.error = 'Could not update status.';
    res.redirect('/studio-panel/models');
  }
});

// PRINT: Master Release
app.get('/studio-panel/models/:id/master-release', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  try {
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    const profile = await dbGet('SELECT * FROM model_profiles WHERE user_id = ?', [userId]);
    const release = await dbGet(
      `SELECT * FROM master_releases
       WHERE user_id = ?
       ORDER BY signed_at DESC
       LIMIT 1`,
      [userId]
    );

    if (!user || user.role !== 'model' || !release) {
      req.session.error = 'No master release found for that model.';
      return res.redirect('/studio-panel/models');
    }

    res.render('print-model-release', { user, profile, release, masterRelease: release });
  } catch (err) {
    console.error('Error loading master release print view:', err);
    req.session.error = 'Could not load master release.';
    res.redirect('/studio-panel/models');
  }
});

// PRINT: Consent / Safety
app.get('/studio-panel/models/:id/consent', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  try {
    const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    const profile = await dbGet('SELECT * FROM model_profiles WHERE user_id = ?', [userId]);
    const policies = await dbGet('SELECT * FROM consent_policies WHERE user_id = ? LIMIT 1;', [userId]);

    if (!user || user.role !== 'model' || !policies) {
      req.session.error = 'No consent / safety info found for that model.';
      return res.redirect('/studio-panel/models');
    }

    res.render('print-model-consent', { user, profile, policies });
  } catch (err) {
    console.error('Error loading consent print view:', err);
    req.session.error = 'Could not load consent details.';
    res.redirect('/studio-panel/models');
  }
});

// ----------------------
// PDF + EMAIL HELPERS (NEW)
// ----------------------
const privateRoot = path.join(__dirname, 'private');
const pdfDir = path.join(privateRoot, 'pdfs');
if (!fs.existsSync(pdfDir)) fs.mkdirSync(pdfDir, { recursive: true });

function envBool(val, defaultValue = false) {
  if (val === undefined || val === null || val === '') return defaultValue;
  const s = String(val).trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

function getMailTransport() {
  const host = (process.env.SMTP_HOST || '').trim();
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = envBool(process.env.SMTP_SECURE, port === 465);
  const user = (process.env.SMTP_USER || '').trim();
  const pass = (process.env.SMTP_PASS || '').trim();

  if (!host || !user || !pass) {
    return null; // caller decides how to handle
  }

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });
}

function safePdfBase(name) {
  return String(name || '')
    .toLowerCase()
    .replace(/[^a-z0-9_\-]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 60) || 'document';
}

function nowStamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

async function renderViewToHtml(viewName, locals) {
  return new Promise((resolve, reject) => {
    app.render(viewName, locals, (err, html) => {
      if (err) return reject(err);
      resolve(html);
    });
  });
}

async function htmlToPdfBuffer(html) {
  if (!puppeteer) {
    throw new Error("Puppeteer is not installed. Run: npm i puppeteer");
  }

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  });

  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: ['domcontentloaded', 'networkidle0'] });

    const buffer = await page.pdf({
      format: 'Letter',
      printBackground: true,
      margin: { top: '0.5in', right: '0.5in', bottom: '0.5in', left: '0.5in' },
    });

    return buffer;
  } finally {
    await browser.close();
  }
}

async function generatePdfForModelDoc({ docKind, userId }) {
  // docKind: 'identity' | 'master-release' | 'consent'
  const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
  if (!user || user.role !== 'model') {
    const err = new Error('Model account not found.');
    err.statusCode = 404;
    throw err;
  }

  const profile = await dbGet('SELECT * FROM model_profiles WHERE user_id = ?', [userId]);
  const documents = await dbAll('SELECT * FROM compliance_documents WHERE user_id = ? ORDER BY uploaded_at DESC', [userId]);
  const release = await dbGet('SELECT * FROM master_releases WHERE user_id = ? ORDER BY signed_at DESC LIMIT 1', [userId]);
  const policies = await dbGet('SELECT * FROM consent_policies WHERE user_id = ? LIMIT 1', [userId]);

  let viewName = '';
  let locals = {};

  if (docKind === 'identity') {
    viewName = 'print-model-identity';
    locals = {
      user,
      modelUser: user,
      profile,
      documents,
      release,
      policies,
      generatedAt: new Date().toISOString(),
    };
  } else if (docKind === 'master-release') {
    if (!release) {
      const err = new Error('No master release found for that model.');
      err.statusCode = 404;
      throw err;
    }
    viewName = 'print-model-release';
    locals = { user, profile, release, masterRelease: release };
  } else if (docKind === 'consent') {
    if (!policies) {
      const err = new Error('No consent / safety info found for that model.');
      err.statusCode = 404;
      throw err;
    }
    viewName = 'print-model-consent';
    locals = { user, profile, policies };
  } else {
    const err = new Error('Invalid document type.');
    err.statusCode = 400;
    throw err;
  }

  const html = await renderViewToHtml(viewName, locals);
  const pdfBuffer = await htmlToPdfBuffer(html);

  const base = safePdfBase(`${docKind}_${user.username || user.id}`);
  const filename = `${nowStamp()}_${base}.pdf`;
  const fullPath = path.join(pdfDir, filename);

  fs.writeFileSync(fullPath, pdfBuffer);

  return {
    user,
    filename,
    fullPath,
    pdfBuffer,
  };
}

async function emailPdf({ to, subject, text, filename, pdfBuffer }) {
  const transport = getMailTransport();
  if (!transport) {
    const err = new Error('Email not configured. Set SMTP_HOST/SMTP_USER/SMTP_PASS (and SMTP_PORT/SMTP_SECURE).');
    err.statusCode = 500;
    throw err;
  }

  const from = (process.env.MAIL_FROM || '').trim() || `LumenNyx Studios <${STUDIO_EMAILS.support}>`;
  const replyTo = (process.env.MAIL_REPLY_TO || '').trim() || STUDIO_EMAILS.models;

  await transport.sendMail({
    from,
    to,
    replyTo,
    subject,
    text,
    attachments: [
      {
        filename,
        content: pdfBuffer,
        contentType: 'application/pdf',
      },
    ],
  });
}

// ----------------------
// PDF DOWNLOAD ROUTES (NEW)
// ----------------------
app.get('/studio-panel/models/:id/identity.pdf', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  try {
    const out = await generatePdfForModelDoc({ docKind: 'identity', userId });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${out.filename}"`);
    return res.send(out.pdfBuffer);
  } catch (err) {
    console.error('PDF identity error:', err);
    req.session.error = err.message || 'Could not generate PDF.';
    return res.redirect(`/studio-panel/models/${userId}`);
  }
});

app.get('/studio-panel/models/:id/master-release.pdf', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  try {
    const out = await generatePdfForModelDoc({ docKind: 'master-release', userId });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${out.filename}"`);
    return res.send(out.pdfBuffer);
  } catch (err) {
    console.error('PDF master release error:', err);
    req.session.error = err.message || 'Could not generate PDF.';
    return res.redirect(`/studio-panel/models/${userId}`);
  }
});

app.get('/studio-panel/models/:id/consent.pdf', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  try {
    const out = await generatePdfForModelDoc({ docKind: 'consent', userId });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${out.filename}"`);
    return res.send(out.pdfBuffer);
  } catch (err) {
    console.error('PDF consent error:', err);
    req.session.error = err.message || 'Could not generate PDF.';
    return res.redirect(`/studio-panel/models/${userId}`);
  }
});

// ----------------------
// PDF EMAIL ROUTES (ADMIN)
// ----------------------
// Optional POST body: { to: "someone@example.com" }
// If omitted, it emails the model's users.email and the model_profiles.email (if present), plus MAIL_TO_STUDIO if set.

function collectEmailTargets(user, profile, explicitTo) {
  const targets = new Set();

  if (explicitTo && String(explicitTo).trim()) targets.add(String(explicitTo).trim());

  if (user?.email && String(user.email).trim()) targets.add(String(user.email).trim());
  if (profile?.email && String(profile.email).trim()) targets.add(String(profile.email).trim());

  const studioArchive = (process.env.MAIL_TO_STUDIO || '').trim();
  if (studioArchive) targets.add(studioArchive);

  // Remove blanks
  for (const t of Array.from(targets)) {
    if (!t || !String(t).trim()) targets.delete(t);
  }

  return Array.from(targets);
}

// Some projects have generatePdfForModelDoc({docKind,userId})
// Others have generatePdfForModelDoc(userId, docKind)
// Others may return { filename, pdfBuffer } or different shapes.
// This wrapper tries both signatures and normalizes output.
async function generatePdfCompat({ docKind, userId }) {
  let out = null;
  let lastErr = null;

  // Attempt A: object signature
  try {
    out = await generatePdfForModelDoc({ docKind, userId });
  } catch (e) {
    lastErr = e;
  }

  // Attempt B: positional signature
  if (!out) {
    try {
      out = await generatePdfForModelDoc(userId, docKind);
    } catch (e) {
      lastErr = e;
    }
  }

  if (!out) {
    const msg = lastErr?.message || 'PDF generator failed.';
    const err = new Error(msg);
    err.original = lastErr;
    throw err;
  }

  // Normalize expected fields
  const normalized = {
    user: out.user || out.modelUser || null,
    filename: out.filename || out.fileName || `${docKind}_${userId}.pdf`,
    pdfBuffer: out.pdfBuffer || out.buffer || null,
    pdfPath: out.pdfPath || out.path || null,
  };

  // Some implementations only return a path string
  if (typeof out === 'string') {
    normalized.pdfPath = out;
    normalized.filename = `${docKind}_${userId}.pdf`;
  }

  // If your emailPdf() needs a buffer, ensure we have it
  // If we only have a file path, read into buffer
  if (!normalized.pdfBuffer && normalized.pdfPath) {
    normalized.pdfBuffer = fs.readFileSync(normalized.pdfPath);
  }

  return normalized;
}

async function getModelOrThrow(userId) {
  const user = await dbGet('SELECT * FROM users WHERE id = ?', [userId]);
  if (!user || user.role !== 'model') {
    const err = new Error('Model account not found.');
    err.statusCode = 404;
    throw err;
  }
  return user;
}

app.post('/studio-panel/models/:id/identity/email', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  try {
    // Always verify the model exists FIRST (prevents confusing generator errors)
    const user = await getModelOrThrow(userId);

    const profile = await dbGet('SELECT * FROM model_profiles WHERE user_id = ?', [userId]);

    const out = await generatePdfCompat({ docKind: 'identity', userId });

    // Ensure we have a user object for subject line
    const subjectUser = out.user || user;

    const toList = collectEmailTargets(subjectUser, profile, req.body?.to);

    if (!toList.length) {
      req.session.error =
        'No email address found for model, and no MAIL_TO_STUDIO set. Add an email on the account or pass {to}.';
      return res.redirect(`/studio-panel/models/${userId}`);
    }

    await emailPdf({
      to: toList.join(','),
      subject: `Identity Summary – ${subjectUser.username || 'Model'} – LumenNyx Studios`,
      text: `Attached: Identity Summary PDF.\nGenerated: ${new Date().toISOString()}\n`,
      filename: out.filename,
      pdfBuffer: out.pdfBuffer,
    });

    req.session.message = `Identity PDF emailed to: ${toList.join(', ')}`;
    return res.redirect(`/studio-panel/models/${userId}`);
  } catch (err) {
    console.error('Email identity PDF error:', err);
    req.session.error = err.message || 'Could not email PDF.';
    return res.redirect(`/studio-panel/models/${userId}`);
  }
});

app.post('/studio-panel/models/:id/master-release/email', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  try {
    const user = await getModelOrThrow(userId);
    const profile = await dbGet('SELECT * FROM model_profiles WHERE user_id = ?', [userId]);

    const out = await generatePdfCompat({ docKind: 'master-release', userId });
    const subjectUser = out.user || user;

    const toList = collectEmailTargets(subjectUser, profile, req.body?.to);

    if (!toList.length) {
      req.session.error =
        'No email address found for model, and no MAIL_TO_STUDIO set. Add an email on the account or pass {to}.';
      return res.redirect(`/studio-panel/models/${userId}`);
    }

    await emailPdf({
      to: toList.join(','),
      subject: `Master Release – ${subjectUser.username || 'Model'} – LumenNyx Studios`,
      text: `Attached: Master Release PDF.\nGenerated: ${new Date().toISOString()}\n`,
      filename: out.filename,
      pdfBuffer: out.pdfBuffer,
    });

    req.session.message = `Master Release PDF emailed to: ${toList.join(', ')}`;
    return res.redirect(`/studio-panel/models/${userId}`);
  } catch (err) {
    console.error('Email master release PDF error:', err);
    req.session.error = err.message || 'Could not email PDF.';
    return res.redirect(`/studio-panel/models/${userId}`);
  }
});

app.post('/studio-panel/models/:id/consent/email', ensureAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);

  try {
    const user = await getModelOrThrow(userId);
    const profile = await dbGet('SELECT * FROM model_profiles WHERE user_id = ?', [userId]);

    const out = await generatePdfCompat({ docKind: 'consent', userId });
    const subjectUser = out.user || user;

    const toList = collectEmailTargets(subjectUser, profile, req.body?.to);

    if (!toList.length) {
      req.session.error =
        'No email address found for model, and no MAIL_TO_STUDIO set. Add an email on the account or pass {to}.';
      return res.redirect(`/studio-panel/models/${userId}`);
    }

    await emailPdf({
      to: toList.join(','),
      subject: `Consent & Safety – ${subjectUser.username || 'Model'} – LumenNyx Studios`,
      text: `Attached: Consent & Safety PDF.\nGenerated: ${new Date().toISOString()}\n`,
      filename: out.filename,
      pdfBuffer: out.pdfBuffer,
    });

    req.session.message = `Consent & Safety PDF emailed to: ${toList.join(', ')}`;
    return res.redirect(`/studio-panel/models/${userId}`);
  } catch (err) {
    console.error('Email consent PDF error:', err);
    req.session.error = err.message || 'Could not email PDF.';
    return res.redirect(`/studio-panel/models/${userId}`);
  }
});

// ----------------------
// COMPAT ROUTES (so old buttons still work)
// ----------------------
app.post('/studio-panel/models/:id/email/identity', ensureAdmin, (req, res) => {
  return res.redirect(307, `/studio-panel/models/${req.params.id}/identity/email`);
});

app.post('/studio-panel/models/:id/email/master-release', ensureAdmin, (req, res) => {
  return res.redirect(307, `/studio-panel/models/${req.params.id}/master-release/email`);
});

app.post('/studio-panel/models/:id/email/consent', ensureAdmin, (req, res) => {
  return res.redirect(307, `/studio-panel/models/${req.params.id}/consent/email`);
});

// ----------------------
// BASIC 404
// ----------------------
app.use((req, res) => {
  res.status(404).send(`Cannot ${req.method} ${req.path}`);
});

// ----------------------
// START SERVER
// ----------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`LumenNyx portal listening on http://localhost:${PORT}`);
});
