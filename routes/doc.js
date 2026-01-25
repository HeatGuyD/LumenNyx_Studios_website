// FILE: routes/doc.js
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { sendMailOrLog } = require('../lib/mailer');

let puppeteer = null;
try {
  puppeteer = require('puppeteer');
} catch (_e) {
  puppeteer = null;
}

function sha256Hex(input) {
  const h = crypto.createHash('sha256');
  h.update(input);
  return h.digest('hex');
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff && typeof xff === 'string') return xff.split(',')[0].trim();
  return (req.ip || req.connection?.remoteAddress || '').toString();
}

function ensureLoggedIn(req, res, next) {
  // model-side pages still enforce age gate
  if (!req.session?.ageConfirmed) return res.redirect('/age-check');
  if (!req.session?.user?.id) return res.redirect('/login');
  next();
}

function ensureAdmin(req, res, next) {
  // IMPORTANT: Do NOT force staff/admin through public age gate.
  if (!req.session?.user) return res.redirect('/staff-login');

  const role = req.session.user.role;
  if (role !== 'admin' && role !== 'staff') {
    return res.status(403).render('error', { message: 'Forbidden' });
  }

  // Staff/admin sessions should pass any old checks that look for ageConfirmed
  if (req.session && !req.session.ageConfirmed) req.session.ageConfirmed = true;

  next();
}

async function renderPdfFromHtml({ html }) {
  if (!puppeteer) throw new Error('Puppeteer is not installed. Run: npm i puppeteer');

  const args = (process.env.PUPPETEER_ARGS || '--no-sandbox,--disable-setuid-sandbox')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const launchOptions = { headless: 'new', args };
  if (process.env.PUPPETEER_EXECUTABLE_PATH) {
    launchOptions.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
  }

  const browser = await puppeteer.launch(launchOptions);
  try {
    const page = await browser.newPage();
    await page.setContent(html, { waitUntil: 'networkidle0' });
    return await page.pdf({
      format: 'Letter',
      printBackground: true,
      margin: { top: '0.55in', right: '0.6in', bottom: '0.55in', left: '0.6in' },
    });
  } finally {
    await browser.close();
  }
}

// Legacy doc types (keep existing)
function requireLegacyDocType(docType) {
  const allowed = new Set(['privacy', 'payment', 'aftercare']);
  if (!allowed.has(docType)) {
    const err = new Error('Invalid doc type');
    err.status = 400;
    throw err;
  }
  return docType;
}

// Template slug safety
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

function escapeHtml(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
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

module.exports = function docRoutes(ctx) {
  const router = express.Router();
  const { dbRun, dbGet, dbAll, ensureColumn } = ctx.db;
  const audit = ctx.audit;

  // Storage
  const executedPdfDir = ctx.uploadDirs.docUploadsDir;

  // -----------------------
  // SCHEMA
  // -----------------------
  (async () => {
    // Existing executed_documents table
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

    // Extend executed_documents for template-driven “DocuSign-ish” flow (add-only)
    await ensureColumn('executed_documents', `doc_kind TEXT`); // 'legacy' or 'legal'
    await ensureColumn('executed_documents', `template_id INTEGER`);
    await ensureColumn('executed_documents', `template_slug TEXT`);
    await ensureColumn('executed_documents', `template_title TEXT`);
    await ensureColumn('executed_documents', `template_version TEXT`);

    // Template library
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
  })().catch((e) => console.error('docRoutes schema init failed:', e));

  function consumeFlash(req) {
    const out = { error: req.session?.error || null, message: req.session?.message || null };
    if (req.session) {
      delete req.session.error;
      delete req.session.message;
    }
    return out;
  }

  async function getLatestSignature(userId) {
    return dbGet(`SELECT * FROM signatures WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`, [userId]);
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

  // ============================================================
  // LEGACY DOC FLOW (keep)
  // /docs, /docs/:docType
  // ============================================================
  router.get('/docs', ensureLoggedIn, async (req, res) => {
    const flash = consumeFlash(req);
    return res.render('docs/index', { studioEmails: ctx.STUDIO_EMAILS, ...flash });
  });

  router.get('/docs/:docType', ensureLoggedIn, async (req, res) => {
    try {
      const docType = requireLegacyDocType(String(req.params.docType || '').trim());
      const userId = req.session.user.id;

      const sig = await getLatestSignature(userId);
      const viewMap = { privacy: 'docs/privacy', payment: 'docs/payment', aftercare: 'docs/aftercare' };
      const flash = consumeFlash(req);

      return res.render(viewMap[docType], {
        docType,
        signature: sig || null,
        studioEmails: ctx.STUDIO_EMAILS,
        ...flash,
      });
    } catch (e) {
      console.error('Doc view error:', e);
      return res.status(e.status || 500).render('error', { message: e.message || 'Could not load document.' });
    }
  });

  router.post('/docs/:docType', ensureLoggedIn, async (req, res) => {
    try {
      const docType = requireLegacyDocType(String(req.params.docType || '').trim());
      const userId = req.session.user.id;

      const sig = await getLatestSignature(userId);
      if (!sig) {
        req.session.error = 'Please complete your signature first (Signature Setup).';
        return res.redirect(`/docs/${docType}`);
      }

      const base = { docType, userId, submittedAtIso: new Date().toISOString() };
      let payload = { ...base };

      if (docType === 'privacy') {
        payload = {
          ...payload,
          ack_confidentiality: req.body.ack_confidentiality === 'on',
          ack_data_handling: req.body.ack_data_handling === 'on',
          ack_no_recording_by_performer: req.body.ack_no_recording_by_performer === 'on',
          ack_contact_method: (req.body.ack_contact_method || '').trim() || null,
          notes: (req.body.notes || '').trim() || null,
        };
        if (!payload.ack_confidentiality || !payload.ack_data_handling) {
          req.session.error = 'Please check the required acknowledgments.';
          return res.redirect(`/docs/privacy`);
        }
      }

      if (docType === 'payment') {
        payload = {
          ...payload,
          amount: (req.body.amount || '').trim(),
          method: (req.body.method || '').trim(),
          date: (req.body.date || '').trim(),
          ack_payment_correct: req.body.ack_payment_correct === 'on',
          notes: (req.body.notes || '').trim() || null,
        };
        if (!payload.amount || !payload.method || !payload.date || !payload.ack_payment_correct) {
          req.session.error = 'Please complete payment details and check the acknowledgment.';
          return res.redirect(`/docs/payment`);
        }
      }

      if (docType === 'aftercare') {
        payload = {
          ...payload,
          ack_boundaries_respected: req.body.ack_boundaries_respected === 'on',
          ack_no_injuries: req.body.ack_no_injuries === 'on',
          ack_aftercare_offered: req.body.ack_aftercare_offered === 'on',
          feedback: (req.body.feedback || '').trim() || null,
          concerns: (req.body.concerns || '').trim() || null,
        };
        if (!payload.ack_boundaries_respected || !payload.ack_aftercare_offered) {
          req.session.error = 'Please complete the required acknowledgments.';
          return res.redirect(`/docs/aftercare`);
        }
      }

      const printViewMap = {
        privacy: 'print/privacy',
        payment: 'print/payment',
        aftercare: 'print/aftercare',
      };

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

      const html = await new Promise((resolve, reject) => {
        res.render(
          printViewMap[docType],
          {
            payload,
            signature: { ...sig, signature_data_url: signatureDataUrl },
            booking: null,
            audit: {
              ip: getClientIp(req),
              ua: req.headers['user-agent'] || '',
              signedAtIso: new Date().toISOString(),
            },
            studioEmails: ctx.STUDIO_EMAILS,
          },
          (err, out) => (err ? reject(err) : resolve(out))
        );
      });

      const pdf = await renderPdfFromHtml({ html });

      const filename = `executed_${docType}_${userId}_${Date.now()}_${Math.random().toString(36).slice(2)}.pdf`;
      fs.writeFileSync(path.join(executedPdfDir, filename), pdf);

      const ip = getClientIp(req);
      const ua = req.headers['user-agent'] || '';
      const hash = await insertExecutedDoc({
        userId,
        docType,
        docKind: 'legacy',
        payload,
        signatureId: sig.id,
        ip,
        ua,
        executedPdfFilename: filename,
      });

      try {
        await audit.log(req, {
          action: 'executed_doc_signed',
          entityType: 'user',
          entityId: userId,
          details: { docType, executedPdf: filename, hash },
        });
      } catch (_) {}

      req.session.message = 'Saved. Your executed PDF has been generated.';
      return res.redirect('/docs');
    } catch (e) {
      console.error('Doc submit error:', e);
      req.session.error = e.message || 'Could not save document.';
      return res.redirect('/docs');
    }
  });

  // ============================================================
  // NEW: LEGAL TEMPLATE LIBRARY (ADMIN)
  // /studio-panel/legal-templates
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
  // NEW: MODEL LEGAL SIGNING FLOW
  // /model/legal
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

      const execRows = await dbAll(
        `SELECT template_id, template_version, signed_at, executed_pdf_filename
         FROM executed_documents
         WHERE user_id=? AND doc_kind='legal'
         ORDER BY signed_at DESC`,
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
         ORDER BY signed_at DESC
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
        audit: {
          ip,
          ua,
        },
      };

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
  // /studio-panel/legal-executed
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
  // ADMIN: PRINT / DOWNLOAD endpoints used by studio-model-view.ejs
  // ============================================================
  async function getModelBundle(modelId) {
    const user = await dbGet(
      `SELECT id, username, email, status, role, created_at
       FROM users
       WHERE id=? AND role='model'
       LIMIT 1`,
      [modelId]
    );
    if (!user) return { user: null, profile: null, masterRelease: null, policies: null };

    const profile = await dbGet(`SELECT * FROM model_profiles WHERE user_id=? LIMIT 1`, [modelId]);

    const masterRelease = await dbGet(
      `SELECT *
       FROM master_releases
       WHERE user_id=?
       ORDER BY datetime(signed_at) DESC, id DESC
       LIMIT 1`,
      [modelId]
    );

    const policies = await dbGet(`SELECT * FROM consent_policies WHERE user_id=? LIMIT 1`, [modelId]);

    return { user, profile: profile || null, masterRelease: masterRelease || null, policies: policies || null };
  }

  function buildIdentityHtml({ user, profile }) {
    const nowIso = new Date().toISOString();
    return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Identity Summary — ${escapeHtml(user?.username || 'Model')}</title>
  <style>
    body{font-family:Arial, sans-serif; color:#111; font-size:12px}
    h1{font-size:18px; margin:0 0 6px}
    .meta{margin:0 0 14px; color:#444}
    .box{border:1px solid #333; padding:10px; border-radius:8px}
    table{width:100%; border-collapse:collapse}
    th,td{padding:6px 8px; border-bottom:1px solid #e6e6e6; text-align:left; vertical-align:top}
    th{width:34%; color:#333; background:#fafafa}
    .small{color:#666; font-size:11px}
    .hr{border-top:1px solid #ddd; margin:14px 0}
  </style>
</head>
<body>
  <h1>Identity Summary</h1>
  <div class="meta">
    Generated: <strong>${escapeHtml(nowIso)}</strong>
  </div>
  <div class="box">
    <table>
      <tr><th>User ID</th><td>${escapeHtml(user?.id)}</td></tr>
      <tr><th>Username</th><td>${escapeHtml(user?.username)}</td></tr>
      <tr><th>Status</th><td>${escapeHtml(user?.status)}</td></tr>
      <tr><th>Email (Account)</th><td>${escapeHtml(user?.email || '—')}</td></tr>

      <tr><th>Preferred Name</th><td>${escapeHtml(profile?.preferred_name || '—')}</td></tr>
      <tr><th>Legal Name</th><td>${escapeHtml(profile?.legal_name || '—')}</td></tr>
      <tr><th>Date of Birth</th><td>${escapeHtml(profile?.date_of_birth || '—')}</td></tr>
      <tr><th>Phone</th><td>${escapeHtml(profile?.phone || '—')}</td></tr>
      <tr><th>Email (Profile)</th><td>${escapeHtml(profile?.email || '—')}</td></tr>
      <tr><th>Location</th><td>${escapeHtml([profile?.state, profile?.country].filter(Boolean).join(', ') || '—')}</td></tr>

      <tr><th>Emergency Contact</th><td>${escapeHtml(profile?.emergency_name || '—')} ${profile?.emergency_phone ? `(${escapeHtml(profile.emergency_phone)})` : ''}</td></tr>
      <tr><th>Aliases</th><td>${escapeHtml(profile?.aliases || '—')}</td></tr>
      <tr><th>Age Truth Ack</th><td>${profile?.age_truth_ack ? 'Yes' : 'No / Not stated'}</td></tr>
    </table>

    <div class="hr"></div>
    <div class="small">
      Internal record summary. Store executed PDFs + IDs securely per your compliance policy.
    </div>
  </div>
</body>
</html>`;
  }

  function buildMasterReleaseHtml({ user, masterRelease }) {
    const nowIso = new Date().toISOString();
    const signedAt = masterRelease?.signed_at || '—';
    const signedName = masterRelease?.signed_name || '—';
    const sigMethod = masterRelease?.signature_method || '—';
    const sigId = masterRelease?.signature_id || '—';
    const ip = masterRelease?.ip_address || '—';
    const ua = masterRelease?.user_agent || '—';

    return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Master Release — ${escapeHtml(user?.username || 'Model')}</title>
  <style>
    body{font-family:Arial, sans-serif; color:#111; font-size:12px}
    h1{font-size:18px; margin:0 0 6px}
    .meta{margin:0 0 14px; color:#444}
    .box{border:1px solid #333; padding:10px; border-radius:8px}
    .hr{border-top:1px solid #ddd; margin:14px 0}
    table{width:100%; border-collapse:collapse}
    th,td{padding:6px 8px; border-bottom:1px solid #e6e6e6; text-align:left; vertical-align:top}
    th{width:34%; color:#333; background:#fafafa}
    .small{color:#666; font-size:11px}
  </style>
</head>
<body>
  <h1>Master Release — Executed Summary</h1>
  <div class="meta">Generated: <strong>${escapeHtml(nowIso)}</strong></div>

  <div class="box">
    <table>
      <tr><th>User ID</th><td>${escapeHtml(user?.id)}</td></tr>
      <tr><th>Username</th><td>${escapeHtml(user?.username)}</td></tr>
      <tr><th>Signed Name</th><td>${escapeHtml(signedName)}</td></tr>
      <tr><th>Signed At</th><td>${escapeHtml(signedAt)}</td></tr>
      <tr><th>Signature Method</th><td>${escapeHtml(sigMethod)}</td></tr>
      <tr><th>Signature ID</th><td>${escapeHtml(sigId)}</td></tr>
    </table>

    <div class="hr"></div>
    <div class="small"><strong>Audit Trail</strong><br/>
      IP: ${escapeHtml(ip)}<br/>
      UA: ${escapeHtml(ua)}
    </div>
  </div>
</body>
</html>`;
  }

  function buildConsentHtml({ user, policies }) {
    const nowIso = new Date().toISOString();

    function yn(v) {
      return v ? 'Yes' : 'No';
    }

    return `<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Consent & Safety — ${escapeHtml(user?.username || 'Model')}</title>
  <style>
    body{font-family:Arial, sans-serif; color:#111; font-size:12px}
    h1{font-size:18px; margin:0 0 6px}
    .meta{margin:0 0 14px; color:#444}
    .box{border:1px solid #333; padding:10px; border-radius:8px}
    .hr{border-top:1px solid #ddd; margin:14px 0}
    table{width:100%; border-collapse:collapse}
    th,td{padding:6px 8px; border-bottom:1px solid #e6e6e6; text-align:left; vertical-align:top}
    th{width:34%; color:#333; background:#fafafa}
    .pre{white-space:pre-wrap}
    .small{color:#666; font-size:11px}
  </style>
</head>
<body>
  <h1>Consent & Safety — Summary</h1>
  <div class="meta">Generated: <strong>${escapeHtml(nowIso)}</strong></div>

  <div class="box">
    <table>
      <tr><th>User ID</th><td>${escapeHtml(user?.id)}</td></tr>
      <tr><th>Username</th><td>${escapeHtml(user?.username)}</td></tr>

      <tr><th>STI Routine Confirmed</th><td>${yn(!!policies?.sti_testing_routine)}</td></tr>
      <tr><th>STI Disclosure Truth Ack</th><td>${yn(!!policies?.sti_disclosure_truth)}</td></tr>
      <tr><th>STI Notes</th><td class="pre">${escapeHtml(policies?.sti_notes || '—')}</td></tr>

      <tr><th>Allows Kissing</th><td>${yn(!!policies?.consent_allows_kissing)}</td></tr>
      <tr><th>Allows Nudity</th><td>${yn(!!policies?.consent_allows_nudity)}</td></tr>
      <tr><th>Allows Rough</th><td>${yn(!!policies?.consent_allows_rough)}</td></tr>
      <tr><th>Allows Choking</th><td>${yn(!!policies?.consent_allows_choking)}</td></tr>

      <tr><th>Hard Limits</th><td class="pre">${escapeHtml(policies?.consent_hard_limits || '—')}</td></tr>
      <tr><th>Soft Limits</th><td class="pre">${escapeHtml(policies?.consent_soft_limits || '—')}</td></tr>

      <tr><th>No Substances</th><td>${yn(!!policies?.policy_no_substances)}</td></tr>
      <tr><th>Safe Word</th><td>${yn(!!policies?.policy_safe_word)}</td></tr>
      <tr><th>Breaks</th><td>${yn(!!policies?.policy_breaks)}</td></tr>
      <tr><th>Reporting</th><td>${yn(!!policies?.policy_reporting)}</td></tr>

      <tr><th>Contractor Ack</th><td>${yn(!!policies?.contractor_acknowledge)}</td></tr>
      <tr><th>Contractor Signature</th><td>${escapeHtml(policies?.contractor_signature || '—')}</td></tr>

      <tr><th>Created</th><td>${escapeHtml(policies?.created_at || '—')}</td></tr>
      <tr><th>Updated</th><td>${escapeHtml(policies?.updated_at || '—')}</td></tr>
    </table>

    <div class="hr"></div>
    <div class="small">
      Full JSON (if used) is stored in consent_json for audit completeness.
    </div>
  </div>
</body>
</html>`;
  }

  async function sendPdfLinkEmail({ req, modelId, kind, extraTo }) {
    const { user, profile } = await getModelBundle(modelId);
    if (!user) throw new Error('Model not found.');

    const MAIL_TO_STUDIO =
      (process.env.MAIL_TO_STUDIO && String(process.env.MAIL_TO_STUDIO).trim()) ||
      (ctx.STUDIO_EMAILS && ctx.STUDIO_EMAILS.admin) ||
      '';

    const recipients = uniqEmails([
      user.email,
      profile?.email,
      MAIL_TO_STUDIO,
      extraTo,
    ]);

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

  router.get('/studio-panel/models/:id/identity', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).render('error', { message: 'Invalid model id.' });

      const { user, profile } = await getModelBundle(id);
      if (!user) return res.status(404).render('error', { message: 'Model not found.' });

      const html = buildIdentityHtml({ user, profile });
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(html);
    } catch (e) {
      console.error('Identity print error:', e);
      return res.status(500).render('error', { message: 'Could not generate identity summary.' });
    }
  });

  router.get('/studio-panel/models/:id/identity.pdf', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).send('Invalid model id.');

      const { user, profile } = await getModelBundle(id);
      if (!user) return res.status(404).send('Model not found.');

      const html = buildIdentityHtml({ user, profile });
      const pdf = await renderPdfFromHtml({ html });

      const fn = `identity_${user.username || 'model'}_${id}.pdf`;
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="${fn}"`);
      return res.send(pdf);
    } catch (e) {
      console.error('Identity PDF error:', e);
      return res.status(500).send('Could not generate PDF.');
    }
  });

  router.get('/studio-panel/models/:id/master-release', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).render('error', { message: 'Invalid model id.' });

      const { user, masterRelease } = await getModelBundle(id);
      if (!user) return res.status(404).render('error', { message: 'Model not found.' });
      if (!masterRelease) return res.status(404).render('error', { message: 'Master release not found.' });

      const html = buildMasterReleaseHtml({ user, masterRelease });
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(html);
    } catch (e) {
      console.error('Master release print error:', e);
      return res.status(500).render('error', { message: 'Could not generate master release.' });
    }
  });

  router.get('/studio-panel/models/:id/master-release.pdf', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).send('Invalid model id.');

      const { user, masterRelease } = await getModelBundle(id);
      if (!user) return res.status(404).send('Model not found.');
      if (!masterRelease) return res.status(404).send('Master release not found.');

      const html = buildMasterReleaseHtml({ user, masterRelease });
      const pdf = await renderPdfFromHtml({ html });

      const fn = `master_release_${user.username || 'model'}_${id}.pdf`;
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="${fn}"`);
      return res.send(pdf);
    } catch (e) {
      console.error('Master release PDF error:', e);
      return res.status(500).send('Could not generate PDF.');
    }
  });

  router.get('/studio-panel/models/:id/consent', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).render('error', { message: 'Invalid model id.' });

      const { user, policies } = await getModelBundle(id);
      if (!user) return res.status(404).render('error', { message: 'Model not found.' });
      if (!policies) return res.status(404).render('error', { message: 'Consent & safety record not found.' });

      const html = buildConsentHtml({ user, policies });
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(html);
    } catch (e) {
      console.error('Consent print error:', e);
      return res.status(500).render('error', { message: 'Could not generate consent summary.' });
    }
  });

  router.get('/studio-panel/models/:id/consent.pdf', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).send('Invalid model id.');

      const { user, policies } = await getModelBundle(id);
      if (!user) return res.status(404).send('Model not found.');
      if (!policies) return res.status(404).send('Consent record not found.');

      const html = buildConsentHtml({ user, policies });
      const pdf = await renderPdfFromHtml({ html });

      const fn = `consent_${user.username || 'model'}_${id}.pdf`;
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="${fn}"`);
      return res.send(pdf);
    } catch (e) {
      console.error('Consent PDF error:', e);
      return res.status(500).send('Could not generate PDF.');
    }
  });

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

  router.post('/studio-panel/models/:id/email/master-release', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).render('error', { message: 'Invalid model id.' });

      const extraTo = String(req.body?.to || '').trim() || null;
      await sendPdfLinkEmail({ req, modelId: id, kind: 'master-release', extraTo });

      req.session.message = 'Email sent (secure PDF link).';
      return res.redirect(`/studio-panel/models/${id}`);
    } catch (e) {
      console.error('Email master release error:', e);
      req.session.error = e.message || 'Could not send email.';
      return res.redirect(`/studio-panel/models/${req.params.id}`);
    }
  });

  router.post('/studio-panel/models/:id/email/consent', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).render('error', { message: 'Invalid model id.' });

      const extraTo = String(req.body?.to || '').trim() || null;
      await sendPdfLinkEmail({ req, modelId: id, kind: 'consent', extraTo });

      req.session.message = 'Email sent (secure PDF link).';
      return res.redirect(`/studio-panel/models/${id}`);
    } catch (e) {
      console.error('Email consent error:', e);
      req.session.error = e.message || 'Could not send email.';
      return res.redirect(`/studio-panel/models/${req.params.id}`);
    }
  });

  // ============================================================
  // Keep your existing executed docs list + pdf serving routes
  // ============================================================
  router.get('/studio-panel/executed', ensureAdmin, async (req, res) => {
    try {
      const rows = await dbAll(
        `SELECT ed.*, u.username
         FROM executed_documents ed
         LEFT JOIN users u ON u.id = ed.user_id
         ORDER BY ed.signed_at DESC
         LIMIT 250`
      );
      return res.render('admin/executed', { rows: rows || [] });
    } catch (e) {
      console.error('Executed list error:', e);
      return res.status(500).render('error', { message: 'Could not load executed documents.' });
    }
  });

  router.get('/studio-panel/executed/:id/pdf', ensureAdmin, async (req, res) => {
    try {
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).send('Invalid id.');

      const row = await dbGet(`SELECT * FROM executed_documents WHERE id = ? LIMIT 1`, [id]);
      if (!row || !row.executed_pdf_filename) return res.status(404).send('Not found.');

      const fp = path.join(executedPdfDir, path.basename(row.executed_pdf_filename));
      if (!fs.existsSync(fp)) return res.status(404).send('File missing.');

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="${path.basename(row.executed_pdf_filename)}"`);
      return res.sendFile(fp);
    } catch (e) {
      console.error('Executed PDF serve error:', e);
      return res.status(500).send('Server error.');
    }
  });

  return router;
};
