// FILE: routes/doc_legal.js
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { sendMailOrLog } = require('../lib/mailer');

function sha256Hex(input) {
  const h = crypto.createHash('sha256');
  h.update(input);
  return h.digest('hex');
}

function sanitizeSlug(input) {
  return String(input || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9_-]/g, '')
    .slice(0, 60);
}

function sanitizeTitle(input) {
  return String(input || '').trim().slice(0, 120);
}

function toBool(v) {
  const s = String(v || '').trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff && typeof xff === 'string') return xff.split(',')[0].trim();
  return (req.ip || req.connection?.remoteAddress || '').toString();
}

function computeBaseUrl(req) {
  const envBase = String(process.env.BASE_URL || '').trim();
  if (envBase) return envBase.replace(/\/+$/, '');

  const host = req.get('host');
  const proto = req.protocol;
  if (host && proto) return `${proto}://${host}`;

  return 'http://localhost:3001';
}

function uniqEmails(arr) {
  const out = [];
  const seen = new Set();
  for (const raw of arr) {
    const e = String(raw || '').trim().toLowerCase();
    if (!e) continue;
    if (seen.has(e)) continue;
    seen.add(e);
    out.push(e);
  }
  return out;
}

/**
 * Normalize an auth guard that might be either:
 *  - express middleware: (req,res,next) => {}
 *  - factory returning middleware: () => (req,res,next) => {}
 *
 * We ONLY auto-call if the function declares 0 params (length === 0).
 * That matches patterns like requireAuth() and avoids calling real middleware.
 */
function normalizeGuard(mwOrFactory, name) {
  if (typeof mwOrFactory !== 'function') {
    return function guardMissing(_req, res, _next) {
      console.error(`Guard missing or invalid: ${name}`);
      return res.status(500).render('error', { message: 'Server configuration error.' });
    };
  }

  // Standard express middleware typically has (req,res,next) => length 3
  if (mwOrFactory.length >= 3) return mwOrFactory;

  // Factory-style guard: () => middleware
  if (mwOrFactory.length === 0) {
    try {
      const maybe = mwOrFactory();
      if (typeof maybe === 'function') return maybe;
    } catch (e) {
      console.error(`Guard factory threw for ${name}:`, e);
      return mwOrFactory;
    }
  }

  // Fallback: treat as middleware
  return mwOrFactory;
}

function ensureDirExists(dirPath) {
  try {
    fs.mkdirSync(dirPath, { recursive: true });
  } catch (e) {
    if (e && e.code !== 'EEXIST') console.error('Failed to ensure directory:', dirPath, e);
  }
}

module.exports = function attachLegalDocRoutes(router, ctx) {
  const { dbRun, dbGet, dbAll, ensureColumn } = ctx.db;
  const audit = ctx.audit;

  // Storage
  const executedPdfDir = ctx.uploadDirs.docUploadsDir;
  ensureDirExists(executedPdfDir);

  // Guards from ctx (doc.js injects these)
  const ensureLoggedIn = normalizeGuard(ctx.ensureLoggedIn, 'ensureLoggedIn');
  const ensureAdmin = normalizeGuard(ctx.ensureAdmin, 'ensureAdmin');

  // PDF renderer from ctx
  const renderPdfFromHtml = ctx.renderPdfFromHtml;

  async function getLatestSignature(userId) {
    return dbGet(`SELECT * FROM signatures WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`, [userId]);
  }

  function consumeFlash(req) {
    const out = { error: req.session?.error || null, message: req.session?.message || null };
    if (req.session) {
      delete req.session.error;
      delete req.session.message;
    }
    return out;
  }

  async function insertExecutedDoc({
    userId,
    docType,
    docKind,
    payload,
    signatureId,
    ip,
    ua,
    executedPdfFilename,
    templateId,
    templateSlug,
    templateTitle,
    templateVersion,
  }) {
    const payloadJson = JSON.stringify(payload);
    const docHash = sha256Hex(payloadJson);

    await dbRun(
      `INSERT INTO executed_documents
       (user_id, doc_type, doc_kind, payload_json, signature_id, ip_address, user_agent, document_hash, executed_pdf_filename,
        template_id, template_slug, template_title, template_version)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId,
        docType,
        docKind || null,
        payloadJson,
        signatureId || null,
        ip || null,
        ua || null,
        docHash,
        executedPdfFilename || null,
        templateId || null,
        templateSlug || null,
        templateTitle || null,
        templateVersion || null,
      ]
    );

    return docHash;
  }

  // -----------------------
  // SCHEMA (legal templates)
  // -----------------------
  (async () => {
    // Defensive: ensure executed_documents exists (doc.js already creates it)
    await dbRun(`
      CREATE TABLE IF NOT EXISTS executed_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        doc_type TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        signed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        signature_id INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        document_hash TEXT,
        executed_pdf_filename TEXT
      )
    `);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_executed_docs_user ON executed_documents(user_id);`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_executed_docs_type ON executed_documents(doc_type);`);

    await ensureColumn('executed_documents', `doc_kind TEXT`);
    await ensureColumn('executed_documents', `template_id INTEGER`);
    await ensureColumn('executed_documents', `template_slug TEXT`);
    await ensureColumn('executed_documents', `template_title TEXT`);
    await ensureColumn('executed_documents', `template_version TEXT`);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS legal_templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        body_html TEXT NOT NULL,
        version TEXT NOT NULL DEFAULT 'v1',
        required INTEGER DEFAULT 1,
        active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await dbRun(`CREATE INDEX IF NOT EXISTS idx_legal_templates_active ON legal_templates(active);`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_legal_templates_required ON legal_templates(required);`);
  })().catch((e) => console.error('doc_legal schema init failed:', e));

  // ============================================================
  // ✅ MODEL: VIEW EXECUTED LEGAL PDF (MODEL-ONLY, OWN-DOC ONLY)
  // ============================================================
  router.get('/model/legal/executed/:id/pdf', ensureLoggedIn, async (req, res) => {
    try {
      if (req.session?.user?.role !== 'model') {
        return res.status(403).render('error', { message: 'Access denied.' });
      }

      const userId = req.session.user.id;
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).render('error', { message: 'Invalid document id.' });

      const row = await dbGet(
        `SELECT id, user_id, doc_kind, executed_pdf_filename
         FROM executed_documents
         WHERE id=? AND doc_kind='legal'
         LIMIT 1`,
        [id]
      );

      if (!row || Number(row.user_id) !== Number(userId)) {
        return res.status(404).render('error', { message: 'Document not found.' });
      }
      if (!row.executed_pdf_filename) {
        return res.status(404).render('error', { message: 'PDF not available.' });
      }

      const fp = path.join(executedPdfDir, path.basename(row.executed_pdf_filename));
      if (!fs.existsSync(fp)) {
        return res.status(404).render('error', { message: 'PDF file missing on server.' });
      }

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="${path.basename(row.executed_pdf_filename)}"`);
      return res.sendFile(fp);
    } catch (e) {
      console.error('Model executed legal PDF error:', e);
      return res.status(500).render('error', { message: 'Could not load PDF.' });
    }
  });

  // ============================================================
  // ADMIN: LEGAL TEMPLATE LIBRARY
  // ============================================================
  router.get('/studio-panel/legal-templates', ensureAdmin, async (req, res) => {
    try {
      const flash = consumeFlash(req);
      const rows = await dbAll(
        `SELECT id, slug, title, version, required, active, created_at, updated_at
         FROM legal_templates
         ORDER BY active DESC, required DESC, id DESC`
      );
      return res.render('admin/legal-templates', {
        staff: req.session.user,
        templates: rows || [],
        ...flash,
      });
    } catch (e) {
      console.error('Legal templates list error:', e);
      return res.status(500).render('error', { message: 'Could not load legal templates.' });
    }
  });

  router.get('/studio-panel/legal-templates/new', ensureAdmin, async (req, res) => {
    const flash = consumeFlash(req);
    return res.render('admin/legal-template-edit', {
      staff: req.session.user,
      template: null,
      ...flash,
    });
  });

  router.post('/studio-panel/legal-templates/new', ensureAdmin, async (req, res) => {
    try {
      const title = sanitizeTitle(req.body.title);
      const slug = sanitizeSlug(req.body.slug || title);
      const version = String(req.body.version || 'v1').trim().slice(0, 20) || 'v1';
      const required = toBool(req.body.required) ? 1 : 0;
      const active = toBool(req.body.active) ? 1 : 0;
      const bodyHtml = String(req.body.body_html || '').trim();

      if (!title) {
        req.session.error = 'Title is required.';
        return res.redirect('/studio-panel/legal-templates/new');
      }
      if (!slug) {
        req.session.error = 'Slug is required.';
        return res.redirect('/studio-panel/legal-templates/new');
      }
      if (!bodyHtml || bodyHtml.length < 40) {
        req.session.error = 'Body HTML is required (at least ~40 chars).';
        return res.redirect('/studio-panel/legal-templates/new');
      }

      await dbRun(
        `INSERT INTO legal_templates (slug, title, body_html, version, required, active, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`,
        [slug, title, bodyHtml, version, required, active]
      );

      try {
        await audit.log(req, {
          action: 'legal_template_created',
          entityType: 'legal_template',
          entityId: null,
          details: { slug, title, version, required, active },
        });
      } catch (_) {}

      req.session.message = 'Legal template created.';
      return res.redirect('/studio-panel/legal-templates');
    } catch (e) {
      console.error('Legal template create error:', e);
      req.session.error = e.message || 'Could not create template.';
      return res.redirect('/studio-panel/legal-templates/new');
    }
  });

  router.get('/studio-panel/legal-templates/:id', ensureAdmin, async (req, res) => {
    try {
      const flash = consumeFlash(req);
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).render('error', { message: 'Invalid id.' });

      const row = await dbGet(`SELECT * FROM legal_templates WHERE id=? LIMIT 1`, [id]);
      if (!row) return res.status(404).render('error', { message: 'Template not found.' });

      return res.render('admin/legal-template-edit', {
        staff: req.session.user,
        template: row,
        ...flash,
      });
    } catch (e) {
      console.error('Legal template edit view error:', e);
      return res.status(500).render('error', { message: 'Could not load template.' });
    }
  });

  router.post('/studio-panel/legal-templates/:id', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) {
        req.session.error = 'Invalid id.';
        return res.redirect('/studio-panel/legal-templates');
      }

      const title = sanitizeTitle(req.body.title);
      const slug = sanitizeSlug(req.body.slug || title);
      const version = String(req.body.version || 'v1').trim().slice(0, 20) || 'v1';
      const required = toBool(req.body.required) ? 1 : 0;
      const active = toBool(req.body.active) ? 1 : 0;
      const bodyHtml = String(req.body.body_html || '').trim();

      if (!title) {
        req.session.error = 'Title is required.';
        return res.redirect(`/studio-panel/legal-templates/${id}`);
      }
      if (!slug) {
        req.session.error = 'Slug is required.';
        return res.redirect(`/studio-panel/legal-templates/${id}`);
      }
      if (!bodyHtml || bodyHtml.length < 40) {
        req.session.error = 'Body HTML is required (at least ~40 chars).';
        return res.redirect(`/studio-panel/legal-templates/${id}`);
      }

      await dbRun(
        `UPDATE legal_templates
         SET slug=?, title=?, body_html=?, version=?, required=?, active=?, updated_at=datetime('now')
         WHERE id=?`,
        [slug, title, bodyHtml, version, required, active, id]
      );

      try {
        await audit.log(req, {
          action: 'legal_template_updated',
          entityType: 'legal_template',
          entityId: id,
          details: { slug, title, version, required, active },
        });
      } catch (_) {}

      req.session.message = 'Legal template saved.';
      return res.redirect('/studio-panel/legal-templates');
    } catch (e) {
      console.error('Legal template update error:', e);
      req.session.error = e.message || 'Could not update template.';
      return res.redirect(`/studio-panel/legal-templates/${req.params.id}`);
    }
  });

  // ============================================================
  // MODEL: LEGAL SIGNING FLOW
  // ============================================================
  router.get('/model/legal', ensureLoggedIn, async (req, res) => {
    try {
      if (req.session?.user?.role !== 'model') {
        return res.status(403).render('error', { message: 'Access denied.' });
      }

      const userId = req.session.user.id;
      const flash = consumeFlash(req);

      const templates = await dbAll(
        `SELECT id, slug, title, version, required, active, updated_at
         FROM legal_templates
         WHERE active=1
         ORDER BY required DESC, id ASC`
      );

      // include id so you can link to /model/legal/executed/:id/pdf
      const execRows = await dbAll(
        `SELECT id, template_id, template_version, signed_at, executed_pdf_filename
         FROM executed_documents
         WHERE user_id=? AND doc_kind='legal'
         ORDER BY datetime(signed_at) DESC, id DESC`,
        [userId]
      );

      const latestByTemplateId = new Map();
      (execRows || []).forEach((r) => {
        if (!latestByTemplateId.has(r.template_id)) latestByTemplateId.set(r.template_id, r);
      });

      const items = (templates || []).map((t) => {
        const exec = latestByTemplateId.get(t.id) || null;
        const signed = !!exec;
        const needsResign = signed && String(exec.template_version || '') !== String(t.version || '');
        return {
          ...t,
          signed,
          signed_at: exec ? exec.signed_at : null,
          needs_resign: needsResign,
          executed_id: exec ? exec.id : null,
        };
      });

      const requiredMissing = items.filter((x) => x.required === 1 && !x.signed).length;
      const requiredNeedsResign = items.filter((x) => x.required === 1 && x.needs_resign).length;

      return res.render('model-legal-index', {
        currentUser: req.session.user,
        templates: items,
        requiredMissing,
        requiredNeedsResign,
        ...flash,
      });
    } catch (e) {
      console.error('Model legal index error:', e);
      return res.status(500).render('error', { message: 'Could not load legal documents.' });
    }
  });

  router.get('/model/legal/:slug', ensureLoggedIn, async (req, res) => {
    try {
      if (req.session?.user?.role !== 'model') {
        return res.status(403).render('error', { message: 'Access denied.' });
      }

      const userId = req.session.user.id;
      const slug = sanitizeSlug(req.params.slug);
      if (!slug) return res.status(400).render('error', { message: 'Invalid document.' });

      const flash = consumeFlash(req);

      const tpl = await dbGet(
        `SELECT id, slug, title, body_html, version, required, active, updated_at
         FROM legal_templates
         WHERE slug=? AND active=1
         LIMIT 1`,
        [slug]
      );
      if (!tpl) return res.status(404).render('error', { message: 'Document not found.' });

      const sig = await getLatestSignature(userId);

      const existing = await dbGet(
        `SELECT id, template_version, signed_at
         FROM executed_documents
         WHERE user_id=? AND doc_kind='legal' AND template_id=?
         ORDER BY datetime(signed_at) DESC, id DESC
         LIMIT 1`,
        [userId, tpl.id]
      );

      const needsResign = existing && String(existing.template_version || '') !== String(tpl.version || '');

      return res.render('model-legal-sign', {
        currentUser: req.session.user,
        template: tpl,
        signature: sig || null,
        alreadySigned: !!existing && !needsResign,
        needsResign: !!needsResign,
        ...flash,
      });
    } catch (e) {
      console.error('Model legal sign view error:', e);
      return res.status(500).render('error', { message: 'Could not load document.' });
    }
  });

  router.post('/model/legal/:slug', ensureLoggedIn, async (req, res) => {
    try {
      if (req.session?.user?.role !== 'model') {
        return res.status(403).render('error', { message: 'Access denied.' });
      }

      const userId = req.session.user.id;
      const slug = sanitizeSlug(req.params.slug);
      if (!slug) {
        req.session.error = 'Invalid document.';
        return res.redirect('/model/legal');
      }

      const tpl = await dbGet(
        `SELECT id, slug, title, body_html, version, required, active, updated_at
         FROM legal_templates
         WHERE slug=? AND active=1
         LIMIT 1`,
        [slug]
      );
      if (!tpl) {
        req.session.error = 'Document not found.';
        return res.redirect('/model/legal');
      }

      const sig = await getLatestSignature(userId);
      if (!sig) {
        req.session.error = 'Please complete your signature first (Signature Setup).';
        return res.redirect(`/model/legal/${slug}`);
      }

      const agree = req.body.agree === 'on';
      if (!agree) {
        req.session.error = 'You must check “I agree” to sign this document.';
        return res.redirect(`/model/legal/${slug}`);
      }

      const ip = getClientIp(req);
      const ua = req.headers['user-agent'] || '';

      const payload = {
        kind: 'legal_template',
        template: {
          id: tpl.id,
          slug: tpl.slug,
          title: tpl.title,
          version: tpl.version,
          updated_at: tpl.updated_at,
        },
        signer: {
          userId,
          username: req.session.user.username || null,
        },
        consent: {
          agreed: true,
          agreedAtIso: new Date().toISOString(),
        },
        audit: { ip, ua },
      };

      // signature image data-url
      let signatureDataUrl = null;
      try {
        const sp = String(sig.signature_png || '');
        if (sp.startsWith('data:image')) {
          signatureDataUrl = sp;
        } else {
          const sigPath = path.join(ctx.uploadDirs.signatureUploadsDir, path.basename(sig.signature_png));
          const buf = fs.readFileSync(sigPath);
          signatureDataUrl = `data:image/png;base64,${buf.toString('base64')}`;
        }
      } catch (_e) {
        signatureDataUrl = null;
      }

      // Render HTML via res.render callback (no ctx._res hacks)
      const html = await new Promise((resolve, reject) => {
        res.render(
          'print/legal-template',
          {
            template: tpl,
            payload,
            signature: { ...sig, signature_data_url: signatureDataUrl },
            studioEmails: ctx.STUDIO_EMAILS,
            audit: { ip, ua, signedAtIso: payload.consent.agreedAtIso },
          },
          (err, out) => (err ? reject(err) : resolve(out))
        );
      });

      const pdf = await renderPdfFromHtml({ html });

      ensureDirExists(executedPdfDir);

      const filename = `executed_legal_${tpl.slug}_${userId}_${Date.now()}_${Math.random().toString(36).slice(2)}.pdf`;
      fs.writeFileSync(path.join(executedPdfDir, filename), pdf);

      const hash = await insertExecutedDoc({
        userId,
        docType: tpl.slug,
        docKind: 'legal',
        payload,
        signatureId: sig.id,
        ip,
        ua,
        executedPdfFilename: filename,
        templateId: tpl.id,
        templateSlug: tpl.slug,
        templateTitle: tpl.title,
        templateVersion: tpl.version,
      });

      try {
        await audit.log(req, {
          action: 'legal_doc_signed',
          entityType: 'legal_template',
          entityId: tpl.id,
          details: { slug: tpl.slug, version: tpl.version, executedPdf: filename, hash },
        });
      } catch (_) {}

      req.session.message = 'Signed. Your executed PDF has been generated.';
      return res.redirect('/model/legal');
    } catch (e) {
      console.error('Model legal submit error:', e);
      req.session.error = e.message || 'Could not sign document.';
      return res.redirect('/model/legal');
    }
  });

  // ============================================================
  // ADMIN: LIST “LEGAL” EXECUTED DOCS
  // ============================================================
  router.get('/studio-panel/legal-executed', ensureAdmin, async (req, res) => {
    try {
      const flash = consumeFlash(req);
      const rows = await dbAll(
        `SELECT ed.*, u.username
         FROM executed_documents ed
         LEFT JOIN users u ON u.id = ed.user_id
         WHERE ed.doc_kind='legal'
         ORDER BY ed.signed_at DESC
         LIMIT 250`
      );
      return res.render('admin/legal-executed', {
        staff: req.session.user,
        rows: rows || [],
        ...flash,
      });
    } catch (e) {
      console.error('Legal executed list error:', e);
      return res.status(500).render('error', { message: 'Could not load signed legal documents.' });
    }
  });

  // ============================================================
  // ADMIN: email helper (secure link)
  // ============================================================
  async function getModelBundle(modelId) {
    const user = await dbGet(
      `SELECT id, username, email, status, role, created_at
       FROM users
       WHERE id=? AND role='model'
       LIMIT 1`,
      [modelId]
    );
    if (!user) return { user: null, profile: null };

    const profile = await dbGet(`SELECT * FROM model_profiles WHERE user_id=? LIMIT 1`, [modelId]);
    return { user, profile: profile || null };
  }

  async function sendPdfLinkEmail({ req, modelId, kind, extraTo }) {
    const { user, profile } = await getModelBundle(modelId);
    if (!user) throw new Error('Model not found.');

    // IMPORTANT: keep this as a single, valid JS expression (no line-ending "||" fragments).
    const MAIL_TO_STUDIO =
      (process.env.MAIL_TO_STUDIO && String(process.env.MAIL_TO_STUDIO).trim()) ||
      (ctx.STUDIO_EMAILS && ctx.STUDIO_EMAILS.admin) ||
      '';

    const recipients = uniqEmails([user.email, profile?.email, MAIL_TO_STUDIO, extraTo]);
    if (!recipients.length) throw new Error('No recipients found (model email + studio archive missing).');

    const baseUrl = computeBaseUrl(req);

    const map = {
      identity: {
        subject: `LumenNyx Studios — Identity PDF — ${user.username}`,
        url: `${baseUrl}/studio-panel/models/${modelId}/identity.pdf`,
      },
      'master-release': {
        subject: `LumenNyx Studios — Master Release PDF — ${user.username}`,
        url: `${baseUrl}/studio-panel/models/${modelId}/master-release.pdf`,
      },
      consent: {
        subject: `LumenNyx Studios — Consent & Safety PDF — ${user.username}`,
        url: `${baseUrl}/studio-panel/models/${modelId}/consent.pdf`,
      },
    };

    const item = map[kind];
    if (!item) throw new Error('Invalid email kind.');

    const text = [
      `Secure document link for internal recordkeeping.`,
      ``,
      `Model: ${user.username} (User ID: ${user.id})`,
      `Document: ${kind}`,
      ``,
      `Download/Preview (PDF):`,
      item.url,
      ``,
      `If you cannot access the link, you may not be logged in as staff/admin.`,
      ``,
      `— LumenNyx Studios`,
    ].join('\n');

    const result = await sendMailOrLog({ to: recipients.join(', '), subject: item.subject, text });
    return { recipients, result };
  }

  router.post('/studio-panel/models/:id/email/identity', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).render('error', { message: 'Invalid model id.' });

      const extraTo = String(req.body?.to || '').trim() || null;
      await sendPdfLinkEmail({ req, modelId: id, kind: 'identity', extraTo });

      req.session.message = 'Email sent (secure PDF link).';
      return res.redirect(`/studio-panel/models/${id}`);
    } catch (e) {
      console.error('Email identity error:', e);
      req.session.error = e.message || 'Could not send email.';
      return res.redirect(`/studio-panel/models/${req.params.id}`);
    }
  });
};
