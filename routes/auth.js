// FILE: routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const path = require('path');
const multer = require('multer');

const { sendMailOrLog } = require('../lib/mailer');

module.exports = function authRoutes(ctx) {
  const router = express.Router();
  const { dbGet, dbRun, ensureColumn } = ctx.db;

  // ---------------------------------------------------------
  // MODEL PRE-REGISTRATION (VETTING INTAKE)
  // This is NOT an account creation flow yet.
  // It stores an application so you can approve later.
  // ---------------------------------------------------------
  async function ensureApplicationsTable() {
    await dbRun(`
      CREATE TABLE IF NOT EXISTS model_applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT DEFAULT (datetime('now')),
        stage_name TEXT NOT NULL,
        legal_name TEXT,
        gender TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT,
        location TEXT,
        socials TEXT,
        portfolio TEXT,
        notes TEXT,
        status TEXT DEFAULT 'pending'
      )
    `);

    // Add-only columns for optional uploads (safe migrations)
    await ensureColumn('model_applications', 'headshot_filename TEXT');
    await ensureColumn('model_applications', 'photos_json TEXT'); // JSON array of filenames
  }

  // ---------------------------------------------------------
  // Upload support for /register
  // ---------------------------------------------------------
  const regStorage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, ctx.uploadDirs.photoUploadsDir),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || '').toLowerCase() || '';
      const safeExt = ext && ext.length <= 10 ? ext : '';
      const name = `anonymous_${Date.now()}_${Math.random().toString(36).slice(2)}${safeExt}`;
      cb(null, name);
    },
  });

  function isAllowedImage(mimetype) {
    const mt = String(mimetype || '').toLowerCase();
    return (
      mt === 'image/jpeg' ||
      mt === 'image/jpg' ||
      mt === 'image/png' ||
      mt === 'image/webp' ||
      mt === 'image/gif'
    );
  }

  // Accept any file fields to prevent "Unexpected field", normalize later.
  const registerUpload = multer({
    storage: regStorage,
    limits: { fileSize: 12 * 1024 * 1024, files: 8 },
    fileFilter: (_req, file, cb) => {
      if (!isAllowedImage(file.mimetype)) {
        return cb(new Error('Only JPG, PNG, WEBP, or GIF images are allowed.'));
      }
      return cb(null, true);
    },
  }).any();

  function normalizeRegisterFiles(filesArray) {
    const files = Array.isArray(filesArray) ? filesArray : [];

    const isHeadshotField = (f) => {
      const n = String(f?.fieldname || '').trim();
      return n === 'headshot' || n === 'headshot_file' || n === 'head_shot';
    };

    const isPortfolioField = (f) => {
      const n = String(f?.fieldname || '').trim();
      return (
        n === 'portfolio_photos' ||
        n === 'portfolio_photos[]' ||
        n === 'portfolioPhotos' ||
        n === 'portfolioPhotos[]' ||
        n === 'photos' ||
        n === 'photos[]'
      );
    };

    const headshot = files.find(isHeadshotField) || null;
    const portfolio = files.filter(isPortfolioField);

    // Fallback: if user uploaded files with unknown field names
    if (!headshot && portfolio.length === 0 && files.length > 0) {
      return {
        headshotFilename: files[0]?.filename || null,
        portfolioFilenames: files.slice(1).map((f) => f.filename).filter(Boolean),
      };
    }

    return {
      headshotFilename: headshot?.filename || null,
      portfolioFilenames: portfolio.map((f) => f.filename).filter(Boolean),
    };
  }

  function absUrl(baseUrl, rel) {
    const b = String(baseUrl || '').trim().replace(/\/+$/, '');
    const r = String(rel || '').trim();
    if (!b) return r;
    if (!r) return b;
    if (r.startsWith('http://') || r.startsWith('https://')) return r;
    return `${b}${r.startsWith('/') ? '' : '/'}${r}`;
  }

  router.get('/register', async (req, res) => {
    try {
      await ensureApplicationsTable();
      return res.render('register', { error: null, message: null, form: {} });
    } catch (e) {
      console.error('Register GET error:', e);
      return res.status(500).render('register', {
        error: 'Internal error loading registration form.',
        message: null,
        form: {},
      });
    }
  });

  router.post('/register', (req, res) => {
    registerUpload(req, res, async (uploadErr) => {
      const form = {
        stage_name: (req.body.stage_name || '').trim(),
        legal_name: (req.body.legal_name || '').trim(),
        gender: (req.body.gender || '').trim(),
        email: (req.body.email || '').trim(),
        phone: (req.body.phone || '').trim(),
        location: (req.body.location || '').trim(),
        socials: (req.body.socials || '').trim(),
        portfolio: (req.body.portfolio || '').trim(),
        notes: (req.body.notes || '').trim(),
        age_confirm: (req.body.age_confirm || '').trim(),
      };

      try {
        await ensureApplicationsTable();

        if (uploadErr) {
          return res.status(400).render('register', {
            error: uploadErr.message || 'Upload failed.',
            message: null,
            form,
          });
        }

        if (form.age_confirm !== 'yes') {
          return res.status(403).render('register', {
            error: 'You must confirm you are 18+ to submit.',
            message: null,
            form,
          });
        }

        if (!form.stage_name) {
          return res.render('register', { error: 'Stage name is required.', message: null, form });
        }
        if (!form.gender || !['Male', 'Female', 'Other'].includes(form.gender)) {
          return res.render('register', { error: 'Please select a valid gender option.', message: null, form });
        }
        if (!form.email || !form.email.includes('@')) {
          return res.render('register', { error: 'A valid email is required.', message: null, form });
        }

        const norm = normalizeRegisterFiles(req.files);
        const headshotFile = norm.headshotFilename || null;
        const extraPhotos = (norm.portfolioFilenames || []).slice(0, 7);
        const photosJson = extraPhotos.length ? JSON.stringify(extraPhotos) : null;

        const ins = await dbRun(
          `
          INSERT INTO model_applications
            (stage_name, legal_name, gender, email, phone, location, socials, portfolio, notes, headshot_filename, photos_json)
          VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `,
          [
            form.stage_name,
            form.legal_name || null,
            form.gender,
            form.email.toLowerCase(),
            form.phone || null,
            form.location || null,
            form.socials || null,
            form.portfolio || null,
            form.notes || null,
            headshotFile,
            photosJson,
          ]
        );

        const appId = ins?.lastID || null;

        try {
          ctx.audit.log(req, 'model_application_submitted', `Model application submitted: ${form.stage_name} (${form.email})`);
        } catch (_e) {}

        // ---------------------------------------------------------
        // Email notification to studio on every application
        // IMPORTANT: Do NOT fail the submission if email fails.
        // ---------------------------------------------------------
        const toStudio =
          process.env.MAIL_TO_MODELS_APPLY ||
          process.env.MAIL_TO_STUDIO ||
          ctx.STUDIO_EMAILS?.models ||
          ctx.STUDIO_EMAILS?.admin ||
          process.env.SMTP_USER;

        const baseUrl = String(process.env.BASE_URL || '').trim();
        const staffLoginUrl = absUrl(baseUrl, '/staff-login');
        const appViewUrl = absUrl(baseUrl, appId ? `/studio-panel/applications/${appId}` : '/studio-panel/applications');

        const headshotUrl = headshotFile ? absUrl(baseUrl, `/uploads/photos/${headshotFile}`) : '-';
        const photoUrls = extraPhotos.length
          ? extraPhotos.map((x) => absUrl(baseUrl, `/uploads/photos/${x}`)).join(', ')
          : '-';

        const subject = `New model application: ${form.stage_name}`;
        const text = [
          `A new model application was submitted.`,
          ``,
          `Application ID: ${appId || '(unknown)'}`,
          `Stage Name: ${form.stage_name}`,
          `Legal Name: ${form.legal_name || '-'}`,
          `Gender: ${form.gender}`,
          `Email: ${form.email}`,
          `Phone: ${form.phone || '-'}`,
          `Location: ${form.location || '-'}`,
          `Socials: ${form.socials || '-'}`,
          `Portfolio: ${form.portfolio || '-'}`,
          `Notes: ${form.notes || '-'}`,
          ``,
          `Headshot: ${headshotUrl}`,
          `Photos: ${photoUrls}`,
          ``,
          `View application: ${appViewUrl}`,
          `Staff login: ${staffLoginUrl}`,
        ].join('\n');

        try {
          await sendMailOrLog({ to: toStudio, subject, text });
        } catch (mailErr) {
          console.error('Register POST: email send failed (submission saved anyway):', mailErr?.message || mailErr);
        }

        return res.render('register', {
          error: null,
          message: 'Submitted. We will contact you after review if it’s a match.',
          form: {},
        });
      } catch (e) {
        console.error('Register POST error:', e);
        return res.status(500).render('register', {
          error: 'Internal error submitting your registration. Please try again.',
          message: null,
          form,
        });
      }
    });
  });

  // ---------------------------------------------------------
  // STAFF LOGIN (separate page)
  // Uses users table; enforces staff/admin role.
  // ---------------------------------------------------------
  router.get('/staff-login', (req, res) => {
    if (req.session?.user?.role === 'admin') return res.redirect('/studio-panel');
    return res.render('staff-login', { error: null, message: null });
  });

  router.post('/staff-login', async (req, res) => {
    try {
      const username = (req.body.username || '').trim();
      const password = (req.body.password || '').trim();

      if (!username || !password) {
        return res.render('staff-login', { error: 'Missing credentials.', message: null });
      }

      const user = await dbGet(
        `SELECT * FROM users WHERE LOWER(username) = LOWER(?) AND role IN ('admin','staff') LIMIT 1`,
        [username]
      );

      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.render('staff-login', { error: 'Invalid staff credentials.', message: null });
      }

      if (user.status && String(user.status).toLowerCase() === 'disabled') {
        return res.render('staff-login', { error: 'This account is disabled.', message: null });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
        status: user.status,
      };

      try {
        ctx.audit.log(req, 'staff_login', `Staff ${user.username} logged in`);
      } catch (_e) {}

      return req.session.save(() => res.redirect('/studio-panel'));
    } catch (e) {
      console.error('Staff login error:', e);
      return res.status(500).render('staff-login', { error: 'Internal error during staff login.', message: null });
    }
  });

  // ---------------------------------------------------------
  // LOGIN (model/general)
  // ---------------------------------------------------------
  router.get('/login', (req, res) => {
    if (req.session?.user) return res.redirect('/');
    return res.render('login', { error: null, message: null });
  });

  router.post('/login', async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password) {
        return res.render('login', { error: 'Missing credentials.', message: null });
      }

      const user = await dbGet(`SELECT * FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1`, [username.trim()]);
      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return res.render('login', { error: 'Invalid username or password.', message: null });
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
        status: user.status,
      };

      try {
        ctx.audit.log(req, 'login', `User ${user.username} logged in`);
      } catch (_e) {}

      return req.session.save(() => res.redirect('/'));
    } catch (e) {
      console.error('Login error:', e);
      return res.status(500).render('login', { error: 'Internal error during login.', message: null });
    }
  });

  // ---------------------------------------------------------
  // LOGOUT (support BOTH GET and POST)
  // ---------------------------------------------------------
  function doLogout(req, res) {
    try {
      ctx.audit.log(req, 'logout', 'User logged out');
    } catch (_e) {}

    req.session.destroy(() => res.redirect('/login'));
  }

  router.post('/logout', doLogout);
  router.get('/logout', doLogout);

  return router;
};
