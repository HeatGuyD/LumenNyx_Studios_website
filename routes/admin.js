// FILE: routes/admin.js
const express = require('express');
const crypto = require('crypto');
const { sendMailOrLog } = require('../lib/mailer');

let puppeteer = null;
try {
  puppeteer = require('puppeteer');
} catch (_e) {
  puppeteer = null;
}

module.exports = function adminRoutes(ctx) {
  const router = express.Router();
  const { dbRun, dbGet, dbAll, ensureColumn } = ctx.db;

  function requireAdmin(req, res, next) {
    // Staff/admin should NOT be forced through the public age gate.
    if (!req.session?.user) return res.redirect('/staff-login');

    if (req.session.user.role !== 'admin' && req.session.user.role !== 'staff') {
      return res.status(403).render('error', { message: 'Access denied.' });
    }

    // Compatibility for any routes that still check ageConfirmed
    if (req.session && !req.session.ageConfirmed) {
      req.session.ageConfirmed = true;
    }

    return next();
  }

  function consumeFlash(req) {
    const out = { message: null, error: null };
    if (req.session) {
      out.message = req.session.message || null;
      out.error = req.session.error || null;
      delete req.session.message;
      delete req.session.error;
    }
    return out;
  }

  async function initAdminMigrations() {
    await ensureColumn('scenes', 'code TEXT');
    await ensureColumn('scenes', 'status TEXT');
    await ensureColumn('scenes', 'storage_note TEXT');
  }

  // ------------------------------------------------------------
  // Applications table (shared with auth.js)
  // ------------------------------------------------------------
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
    await ensureColumn('model_applications', 'headshot_filename TEXT');
    await ensureColumn('model_applications', 'photos_json TEXT');
    await ensureColumn('model_applications', 'onboarded_user_id INTEGER');
    await ensureColumn('model_applications', 'onboarded_at TEXT');
  }

  async function ensureInvitesTable() {
    await dbRun(`
      CREATE TABLE IF NOT EXISTS application_invites (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        application_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        token TEXT NOT NULL UNIQUE,
        used INTEGER DEFAULT 0,
        used_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY(application_id) REFERENCES model_applications(id)
      )
    `);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_application_invites_token ON application_invites(token);`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_application_invites_app ON application_invites(application_id);`);
  }

  function safeJsonArray(str) {
    try {
      const v = JSON.parse(str);
      return Array.isArray(v) ? v : [];
    } catch (_e) {
      return [];
    }
  }

  function absUrl(baseUrl, rel) {
    const b = String(baseUrl || '').trim().replace(/\/+$/, '');
    const r = String(rel || '').trim();
    if (!b) return r;
    if (!r) return b;
    if (r.startsWith('http://') || r.startsWith('https://')) return r;
    return `${b}${r.startsWith('/') ? '' : '/'}${r}`;
  }

  function isValidEmail(email) {
    const e = String(email || '').trim();
    return e.length >= 6 && e.includes('@') && e.includes('.');
  }

  function computeBaseUrl(req) {
    // Prefer explicit BASE_URL when set correctly (e.g. https://booking.lumennyxstudios.com)
    const envBase = String(process.env.BASE_URL || '').trim();
    if (envBase) return envBase.replace(/\/+$/, '');

    // Otherwise derive from request (requires trust proxy so req.protocol respects X-Forwarded-Proto)
    const host = req.get('host');
    const proto = req.protocol; // should be https behind nginx if trust proxy is set
    if (host && proto) return `${proto}://${host}`;

    // Final fallback
    return 'http://localhost:3001';
  }

  // ------------------------------------------------------------
  // Studio Panel
  // ------------------------------------------------------------
  router.get('/studio-panel', requireAdmin, async (req, res) => {
    try {
      await initAdminMigrations();
      await ensureApplicationsTable();

      const flash = consumeFlash(req);

      const approvedRow = await dbGet(
        `SELECT COUNT(*) AS c FROM users WHERE role='model' AND status='approved'`,
        []
      );
      const pendingRow = await dbGet(
        `SELECT COUNT(*) AS c FROM users WHERE role='model' AND status='pending'`,
        []
      );
      const pendingAppsRow = await dbGet(
        `SELECT COUNT(*) AS c FROM model_applications WHERE status='pending'`,
        []
      );

      const stats = {
        approvedModels: approvedRow?.c || 0,
        pendingModels: pendingRow?.c || 0,
        totalModels: (approvedRow?.c || 0) + (pendingRow?.c || 0),
        pendingApplications: pendingAppsRow?.c || 0,
      };

      return res.render('studio-panel', {
        staff: req.session.user,
        stats,
        CONTACT_EMAILS: ctx.STUDIO_EMAILS,
        studioEmails: ctx.STUDIO_EMAILS,
        message: flash.message,
        error: flash.error,
      });
    } catch (e) {
      console.error('Studio panel error:', e);
      return res.status(500).render('error', { message: 'Could not load studio panel.' });
    }
  });

  // ------------------------------------------------------------
  // Applications List
  // ------------------------------------------------------------
  router.get('/studio-panel/applications', requireAdmin, async (req, res) => {
    try {
      await ensureApplicationsTable();
      const flash = consumeFlash(req);

      const status = String(req.query.status || 'pending').trim().toLowerCase();
      const allowed = new Set(['pending', 'approved', 'rejected', 'all']);
      const effective = allowed.has(status) ? status : 'pending';

      const where = effective === 'all' ? '' : `WHERE lower(status)=lower(?)`;
      const params = effective === 'all' ? [] : [effective];

      const rows = await dbAll(
        `
        SELECT id, created_at, stage_name, legal_name, gender, email, phone, location, socials, portfolio, notes,
               status, headshot_filename, photos_json, onboarded_user_id, onboarded_at
        FROM model_applications
        ${where}
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 500
        `,
        params
      );

      const apps = (rows || []).map((r) => {
        const photos = safeJsonArray(r.photos_json || '[]');
        return { ...r, photos, photos_count: photos.length };
      });

      return res.render('studio-applications', {
        staff: req.session.user,
        applications: apps,
        filterStatus: effective,
        message: flash.message,
        error: flash.error,
      });
    } catch (e) {
      console.error('Applications list error:', e);
      return res.status(500).render('error', { message: 'Could not load applications.' });
    }
  });

  // ------------------------------------------------------------
  // Application View
  // ------------------------------------------------------------
  router.get('/studio-panel/applications/:id', requireAdmin, async (req, res) => {
    try {
      await ensureApplicationsTable();
      const flash = consumeFlash(req);

      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).render('error', { message: 'Invalid application id.' });

      const row = await dbGet(
        `
        SELECT id, created_at, stage_name, legal_name, gender, email, phone, location, socials, portfolio, notes,
               status, headshot_filename, photos_json, onboarded_user_id, onboarded_at
        FROM model_applications
        WHERE id=?
        LIMIT 1
        `,
        [id]
      );

      if (!row) return res.status(404).render('error', { message: 'Application not found.' });

      const photos = safeJsonArray(row.photos_json || '[]');

      return res.render('studio-application-view', {
        staff: req.session.user,
        application: { ...row, photos },
        message: flash.message,
        error: flash.error,
      });
    } catch (e) {
      console.error('Application view error:', e);
      return res.status(500).render('error', { message: 'Could not load application.' });
    }
  });

  // ------------------------------------------------------------
  // Application Status Update
  // ------------------------------------------------------------
  router.post('/studio-panel/applications/:id/status', requireAdmin, async (req, res) => {
    const id = parseInt(req.params.id, 10);
    const status = String(req.body.status || '').trim().toLowerCase();
    const allowed = new Set(['pending', 'approved', 'rejected']);

    try {
      await ensureApplicationsTable();
      await ensureInvitesTable();

      if (!id) {
        req.session.error = 'Invalid application id.';
        return res.redirect('/studio-panel/applications');
      }
      if (!allowed.has(status)) {
        req.session.error = 'Invalid status value.';
        return res.redirect(`/studio-panel/applications/${id}`);
      }

      const appRow = await dbGet(
        `SELECT id, stage_name, legal_name, email, status FROM model_applications WHERE id=? LIMIT 1`,
        [id]
      );
      if (!appRow) {
        req.session.error = 'Application not found.';
        return res.redirect('/studio-panel/applications');
      }

      const applicantEmailRaw = String(appRow.email || '').trim();
      const applicantEmail = applicantEmailRaw.toLowerCase();
      const stageName = String(appRow.stage_name || '').trim() || 'Applicant';

      console.log('[APP STATUS UPDATE]', { id, status, applicantEmail });

      await dbRun(`UPDATE model_applications SET status=? WHERE id=?`, [status, id]);

      try {
        await ctx.audit.log(req, {
          action: 'application_status_updated',
          entityType: 'model_application',
          entityId: id,
          details: { status },
        });
      } catch (e) {
        console.warn('Audit log failed (ignored):', e?.message || e);
      }

      const baseUrl = computeBaseUrl(req);

      if (status === 'approved') {
        if (!isValidEmail(applicantEmail)) {
          req.session.error = `Approved, but applicant email is invalid/missing: "${applicantEmailRaw}".`;
          return res.redirect(`/studio-panel/applications/${id}`);
        }

        // Invalidate any prior unused invites for this application
        await dbRun(
          `UPDATE application_invites
           SET used=1, used_at=COALESCE(used_at, datetime('now'))
           WHERE application_id=? AND used=0`,
          [id]
        );

        const token = crypto.randomBytes(32).toString('hex');

        const ins = await dbRun(
          `INSERT INTO application_invites (application_id, email, token, used) VALUES (?, ?, ?, 0)`,
          [id, applicantEmail, token]
        );

        const acceptUrl = absUrl(baseUrl, `/apply/accept/${token}`);

        console.log('[APP APPROVED] invite created', {
          applicationId: id,
          inviteRowId: ins?.lastID,
          tokenPrefix: token.slice(0, 8),
          acceptUrl,
          baseUrl,
        });

        const subject = 'LumenNyx Studios – Application Approved';
        const text = [
          `Hi ${stageName},`,
          ``,
          `Thank you for applying to LumenNyx Studios. We’d like to move forward with you.`,
          ``,
          `Please complete your account setup using this secure one-time link:`,
          `${acceptUrl}`,
          ``,
          `This link can only be used once.`,
          ``,
          `— LumenNyx Studios`,
        ].join('\n');

        try {
          const r = await sendMailOrLog({ to: applicantEmail, subject, text });
          console.log('[APP APPROVED] email send result:', r);
          req.session.message = 'Application approved. Invite link emailed to applicant.';
        } catch (mailErr) {
          console.error('[APP APPROVED] email FAILED:', mailErr?.message || mailErr);
          req.session.error = 'Application approved, but the approval email failed to send. Check server logs.';
        }

        return res.redirect(`/studio-panel/applications/${id}`);
      }

      if (status === 'rejected') {
        if (!isValidEmail(applicantEmail)) {
          req.session.message = 'Application rejected. (No valid email to notify applicant.)';
          return res.redirect(`/studio-panel/applications/${id}`);
        }

        const subject = 'LumenNyx Studios – Application Update';
        const text = [
          `Hi ${stageName},`,
          ``,
          `Thank you for your interest in LumenNyx Studios.`,
          `At this time, we won’t be moving forward.`,
          ``,
          `We appreciate your submission and wish you the best.`,
          ``,
          `— LumenNyx Studios`,
        ].join('\n');

        try {
          const r = await sendMailOrLog({ to: applicantEmail, subject, text });
          console.log('[APP REJECTED] email send result:', r);
          req.session.message = 'Application rejected. Rejection email sent to applicant.';
        } catch (mailErr) {
          console.error('[APP REJECTED] email FAILED:', mailErr?.message || mailErr);
          req.session.error = 'Application rejected, but the rejection email failed to send. Check server logs.';
        }

        return res.redirect(`/studio-panel/applications/${id}`);
      }

      req.session.message = 'Application status updated.';
      return res.redirect(`/studio-panel/applications/${id}`);
    } catch (e) {
      console.error('Application status update error:', e);
      req.session.error = 'Could not update application status.';
      return res.redirect(`/studio-panel/applications/${id || ''}`);
    }
  });

  // ------------------------------------------------------------
  // MODELS LIST (unchanged)
  // ------------------------------------------------------------
  router.get('/studio-panel/models', requireAdmin, async (req, res) => {
    try {
      await initAdminMigrations();
      const flash = consumeFlash(req);

      const rows = await dbAll(
        `
        SELECT
          u.id,
          u.username,
          u.email AS user_email,
          u.status,

          mp.legal_name,
          mp.preferred_name,
          mp.date_of_birth,
          mp.headshot_path,

          (SELECT COUNT(*) FROM compliance_documents cd WHERE cd.user_id = u.id) AS docs_count,
          (SELECT COUNT(*) FROM model_photos ph WHERE ph.user_id = u.id) AS photos_count,

          CASE
            WHEN EXISTS (SELECT 1 FROM master_releases mr WHERE mr.user_id = u.id) THEN 'Signed'
            ELSE NULL
          END AS release_status,

          CASE
            WHEN EXISTS (SELECT 1 FROM consent_policies cp WHERE cp.user_id = u.id) THEN 'Saved'
            ELSE NULL
          END AS consent_status,

          CASE
            WHEN EXISTS (
              SELECT 1
              FROM compliance_documents cd
              WHERE cd.user_id = u.id AND lower(cd.doc_type) IN ('w9','w-9')
            ) THEN 'Uploaded'
            ELSE NULL
          END AS w9_status

        FROM users u
        LEFT JOIN model_profiles mp ON mp.user_id = u.id
        WHERE u.role='model'
        ORDER BY
          CASE u.status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
          u.id DESC
        LIMIT 500
        `,
        []
      );

      const models = (rows || []).map((r) => ({
        id: r.id,
        username: r.username,
        email: r.user_email || null,
        status: r.status,

        legal_name: r.legal_name || null,
        preferred_name: r.preferred_name || null,
        date_of_birth: r.date_of_birth || null,
        headshot_path: r.headshot_path || null,

        docs_count: r.docs_count || 0,
        photos_count: r.photos_count || 0,

        release_status: r.release_status || null,
        consent_status: r.consent_status || null,
        w9_status: r.w9_status || null,
      }));

      return res.render('studio-models', {
        staff: req.session.user,
        models,
        message: flash.message,
        error: flash.error,
      });
    } catch (e) {
      console.error('Studio models error:', e);
      return res.status(500).render('error', { message: 'Could not load models.' });
    }
  });

  // ------------------------------------------------------------
  // NEW: Model Inspect View (used by your studioModelView.ejs page)
  // GET /studio-panel/models/:id
  // ------------------------------------------------------------
  router.get('/studio-panel/models/:id', requireAdmin, async (req, res) => {
    try {
      const flash = consumeFlash(req);

      const id = parseInt(req.params.id, 10);
      if (!Number.isFinite(id) || id <= 0) {
        return res.status(400).render('error', { message: 'Invalid model id.' });
      }

      const user = await dbGet(
        `SELECT id, username, role, status, email, created_at
         FROM users
         WHERE id=? AND role='model'
         LIMIT 1`,
        [id]
      );
      if (!user) return res.status(404).render('error', { message: 'Model not found.' });

      const profile = await dbGet(
        `SELECT *
         FROM model_profiles
         WHERE user_id=?
         LIMIT 1`,
        [id]
      );

      const documents = await dbAll(
        `SELECT id, user_id, doc_type, filename, uploaded_at
         FROM compliance_documents
         WHERE user_id=?
         ORDER BY datetime(uploaded_at) DESC, id DESC`,
        [id]
      );

      const photos = await dbAll(
        `SELECT id, user_id, filename, caption, is_primary, priority, uploaded_at
         FROM model_photos
         WHERE user_id=?
         ORDER BY is_primary DESC, priority DESC, datetime(uploaded_at) DESC, id DESC`,
        [id]
      );

      const masterRelease = await dbGet(
        `SELECT *
         FROM master_releases
         WHERE user_id=?
         ORDER BY datetime(signed_at) DESC, id DESC
         LIMIT 1`,
        [id]
      );

      const policies = await dbGet(
        `SELECT *
         FROM consent_policies
         WHERE user_id=?
         LIMIT 1`,
        [id]
      );

      return res.render('studio-model-view', {
        staff: req.session.user,
        user,
        profile: profile || null,
        documents: documents || [],
        photos: photos || [],
        masterRelease: masterRelease || null,
        policies: policies || null,
        message: flash.message,
        error: flash.error,
      });
    } catch (e) {
      console.error('Studio model view error:', e);
      return res.status(500).render('error', { message: 'Could not load model.' });
    }
  });

  // ------------------------------------------------------------
  // NEW: Update model account status
  // POST /studio-panel/models/:id/status
  // ------------------------------------------------------------
  router.post('/studio-panel/models/:id/status', requireAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      const status = String(req.body?.status || '').trim().toLowerCase();
      const allowed = new Set(['pending', 'approved', 'active', 'disabled']);

      if (!Number.isFinite(id) || id <= 0 || !allowed.has(status)) {
        return res.status(400).render('error', { message: 'Invalid request.' });
      }

      await dbRun(`UPDATE users SET status=? WHERE id=? AND role='model'`, [status, id]);

      try {
        await ctx.audit.log(req, {
          action: 'model_status_updated',
          entityType: 'user',
          entityId: id,
          details: { status },
        });
      } catch (_) {}

      req.session.message = 'Model status updated.';
      return res.redirect(`/studio-panel/models/${id}`);
    } catch (e) {
      console.error('Model status update error:', e);
      return res.status(500).render('error', { message: 'Could not update model status.' });
    }
  });

  router.get('/studio-panel/docs', requireAdmin, (req, res) => {
    return res.redirect('/studio-panel/executed');
  });

  return router;
};
