// FILE: routes/model.js
const express = require('express');

module.exports = function modelRoutes(ctx) {
  const router = express.Router();
  const { dbRun, dbGet, dbAll } = ctx.db;

  function requireModel(req, res, next) {
    if (!req.session?.ageConfirmed) return res.redirect('/age-check');
    if (!req.session?.user) return res.redirect('/login');
    if (req.session.user.role !== 'model') {
      return res.status(403).render('error', { message: 'Access denied.' });
    }
    return next();
  }

  // ✅ Booking/compliance middleware (added via ctx in app.js)
  const requireModelCompliant = ctx.compliance?.requireModelCompliant;

  // Utility: best-effort flash passthrough (keeps your current pattern)
  function consumeFlash(req, res) {
    const message = res?.locals?.message || req?.session?.message || null;
    const error = res?.locals?.error || req?.session?.error || null;

    if (req.session) {
      delete req.session.message;
      delete req.session.error;
    }
    return { message, error };
  }

  // -------------------------
  // Model Profile (wired)
  // -------------------------
  router.get('/model/profile', requireModel, async (req, res) => {
    try {
      const userId = req.session.user.id;
      const flash = consumeFlash(req, res);

      const profile = await dbGet(`SELECT * FROM model_profiles WHERE user_id=? LIMIT 1`, [userId]);

      // Compliance documents uploaded (ID, W-9, etc.)
      const documents = await dbAll(
        `SELECT id, doc_type, filename, uploaded_at
         FROM compliance_documents
         WHERE user_id=?
         ORDER BY uploaded_at DESC`,
        [userId]
      );

      // Photos uploaded by model
      const photos = await dbAll(
        `SELECT id, filename, caption, is_primary, priority, uploaded_at
         FROM model_photos
         WHERE user_id=?
         ORDER BY is_primary DESC, priority DESC, uploaded_at DESC`,
        [userId]
      );

      // Master release signed record
      const masterRelease = await dbGet(
        `SELECT id, signed_name, signed_at
         FROM master_releases
         WHERE user_id=?
         ORDER BY signed_at DESC
         LIMIT 1`,
        [userId]
      );

      // Consent policies (your schema stores JSON + version)
      const policies = await dbGet(
        `SELECT user_id, consent_json, consent_version, updated_at, created_at
         FROM consent_policies
         WHERE user_id=? LIMIT 1`,
        [userId]
      );

      // ✅ LEGAL DOC TEMPLATES + EXECUTED LEGAL DOCS
      const legalTemplates = await dbAll(
        `SELECT id, slug, title, version, required, active, created_at, updated_at
         FROM legal_templates
         WHERE active=1
         ORDER BY required DESC, title ASC`
      );

      const executedLegal = await dbAll(
        `SELECT id, user_id, doc_kind, template_id, template_slug, template_title,
                template_version, signed_at, executed_pdf_filename
         FROM executed_documents
         WHERE user_id=? AND doc_kind='legal'
         ORDER BY datetime(signed_at) DESC, id DESC`,
        [userId]
      );

      const documentsMapped = (documents || []).map((d) => ({
        ...d,
        created_at: d.uploaded_at || d.created_at || null,
        public_url: d.filename ? `/uploads/docs/${encodeURIComponent(d.filename)}` : null,
      }));

      const photosMapped = (photos || []).map((p) => ({
        ...p,
        created_at: p.uploaded_at || p.created_at || null,
        public_url: p.filename ? `/uploads/photos/${encodeURIComponent(p.filename)}` : null,
      }));

      return res.render('model-profile', {
        currentUser: req.session.user,
        message: flash.message,
        error: flash.error,

        profile: profile || {},
        documents: documentsMapped || [],
        photos: photosMapped || [],

        masterRelease: masterRelease || null,
        policies: policies || null,

        legalTemplates: legalTemplates || [],
        executedLegal: executedLegal || [],
      });
    } catch (e) {
      console.error('Model profile error:', e);
      return res.status(500).render('error', { message: 'Could not load model profile.' });
    }
  });

  // -------------------------
  // Model Bookings (wired) ✅ NOW COMPLIANCE-GATED
  // -------------------------
  router.get(
    '/model/bookings',
    requireModel,
    requireModelCompliant ? requireModelCompliant : (req, _res, next) => next(),
    async (req, res) => {
      try {
        const userId = req.session.user.id;
        const flash = consumeFlash(req, res);

        const bookings = await dbAll(
          `
          SELECT b.id, b.title, b.shoot_date, b.status
          FROM booking_models bm
          JOIN bookings b ON b.id = bm.booking_id
          WHERE bm.user_id=?
          ORDER BY b.created_at DESC
          `,
          [userId]
        );

        return res.render('model-bookings', {
          currentUser: req.session.user,
          bookings: bookings || [],
          message: flash.message,
          error: flash.error,
        });
      } catch (e) {
        console.error('Model bookings error:', e);
        return res.status(500).render('error', { message: 'Could not load bookings.' });
      }
    }
  );

  router.get(
    '/model/bookings/:id',
    requireModel,
    requireModelCompliant ? requireModelCompliant : (req, _res, next) => next(),
    async (req, res) => {
      req.session.message = 'Booking detail view is not enabled yet. Please view bookings list.';
      return res.redirect('/model/bookings');
    }
  );

  // -------------------------
  // Model Scenes (wired)
  // If you ALSO want scenes hidden behind compliance, add requireModelCompliant here too.
  // -------------------------
  router.get('/model/scenes', requireModel, async (req, res) => {
    try {
      const userId = req.session.user.id;
      const flash = consumeFlash(req, res);

      const scenes = await dbAll(
        `
        SELECT s.id, s.title, s.shoot_date, s.description, s.video_ref,
               s.code, s.status
        FROM scene_models sm
        JOIN scenes s ON s.id = sm.scene_id
        WHERE sm.user_id=?
        ORDER BY s.created_at DESC
        `,
        [userId]
      );

      const mapped = (scenes || []).map((s) => ({
        ...s,
        role_label: 'Performer',
      }));

      return res.render('model-scenes', {
        currentUser: req.session.user,
        scenes: mapped,
        message: flash.message,
        error: flash.error,
      });
    } catch (e) {
      console.error('Model scenes error:', e);
      return res.status(500).render('error', { message: 'Could not load scenes.' });
    }
  });

  // -------------------------
  // Signature (GET + POST wired)
  // -------------------------
  router.get('/model/signature', requireModel, async (req, res) => {
    try {
      const userId = req.session.user.id;
      const flash = consumeFlash(req, res);

      const profile = await dbGet(`SELECT * FROM model_profiles WHERE user_id=? LIMIT 1`, [userId]);

      const signature = await dbGet(
        `SELECT id, method, typed_name, typed_style, signature_png, initials_png, created_at
         FROM signatures
         WHERE user_id=?
         ORDER BY created_at DESC
         LIMIT 1`,
        [userId]
      );

      return res.render('model-signature', {
        currentUser: req.session.user,
        profile: profile || {},
        signature: signature || null,
        message: flash.message,
        error: flash.error,
      });
    } catch (e) {
      console.error('Model signature GET error:', e);
      return res.status(500).render('error', { message: 'Could not load signature page.' });
    }
  });

  router.post('/model/signature', requireModel, async (req, res) => {
    try {
      const userId = req.session.user.id;

      const method = String(req.body.method || 'typed').trim().toLowerCase();
      const typed_name = String(req.body.typed_name || '').trim();
      const typed_style = String(req.body.typed_style || 'style1').trim();

      const signature_data_url = String(req.body.signature_data_url || '').trim();
      const initials_data_url = String(req.body.initials_data_url || '').trim();

      if (!typed_name) {
        req.session.error = 'Legal name is required.';
        return res.redirect('/model/signature');
      }
      if (!signature_data_url.startsWith('data:image')) {
        req.session.error = 'Signature image data is missing. Please type or draw your signature until it appears.';
        return res.redirect('/model/signature');
      }

      await dbRun(
        `
        INSERT INTO signatures (user_id, method, typed_name, typed_style, signature_png, initials_png, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          userId,
          method,
          typed_name,
          typed_style,
          signature_data_url,
          initials_data_url && initials_data_url.startsWith('data:image') ? initials_data_url : null,
          ctx.security?.getClientIp ? ctx.security.getClientIp(req) : (req.ip || null),
          req.headers['user-agent'] || null,
        ]
      );

      try {
        await ctx.audit.log(req, {
          action: 'signature_saved',
          entityType: 'signature',
          entityId: null,
          details: { method, typed_style },
        });
      } catch (_) {}

      req.session.message = 'Signature saved.';
      return res.redirect('/model/signature');
    } catch (e) {
      console.error('Model signature POST error:', e);
      req.session.error = 'Could not save signature.';
      return res.redirect('/model/signature');
    }
  });

  return router;
};
