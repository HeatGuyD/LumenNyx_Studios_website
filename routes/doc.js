// routes/doc.js
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

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
  if (!req.session?.ageConfirmed) return res.redirect('/age-check');
  if (!req.session?.user?.id) return res.redirect('/login');
  next();
}

function ensureAdmin(req, res, next) {
  if (!req.session?.ageConfirmed) return res.redirect('/age-check');
  if (!req.session?.user) return res.redirect('/staff-login');
  const role = req.session.user.role;
  if (role !== 'admin' && role !== 'staff') return res.status(403).render('error', { message: 'Forbidden' });
  next();
}

async function renderPdfFromHtml({ html }) {
  if (!puppeteer) throw new Error('Puppeteer is not installed. Run: npm i puppeteer');

  const args = (process.env.PUPPETEER_ARGS || '--no-sandbox,--disable-setuid-sandbox')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const launchOptions = { headless: 'new', args };
  if (process.env.PUPPETEER_EXECUTABLE_PATH) launchOptions.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;

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

function requireDocType(docType) {
  const allowed = new Set(['privacy', 'payment', 'aftercare']);
  if (!allowed.has(docType)) {
    const err = new Error('Invalid doc type');
    err.status = 400;
    throw err;
  }
  return docType;
}

module.exports = function docRoutes(ctx) {
  const router = express.Router();
  const { dbRun, dbGet, dbAll } = ctx.db;
  const audit = ctx.audit;

  // executed_documents table
  (async () => {
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
  })().catch((e) => console.error('executed_documents init failed:', e));

  const executedPdfDir = ctx.uploadDirs.docUploadsDir;

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

  async function insertExecutedDoc({ userId, docType, payload, signatureId, ip, ua, executedPdfFilename }) {
    const payloadJson = JSON.stringify(payload);
    const docHash = sha256Hex(payloadJson);

    await dbRun(
      `INSERT INTO executed_documents
       (user_id, doc_type, payload_json, signature_id, ip_address, user_agent, document_hash, executed_pdf_filename)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [userId, docType, payloadJson, signatureId || null, ip, ua, docHash, executedPdfFilename || null]
    );

    return docHash;
  }

  // -------------------------
  // MODEL: docs index
  // -------------------------
  router.get('/docs', ensureLoggedIn, async (req, res) => {
    const flash = consumeFlash(req);
    return res.render('docs/index', { studioEmails: ctx.STUDIO_EMAILS, ...flash });
  });

  // -------------------------
  // MODEL: doc form views
  // -------------------------
  router.get('/docs/:docType', ensureLoggedIn, async (req, res) => {
    try {
      const docType = requireDocType(String(req.params.docType || '').trim());
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

  // -------------------------
  // MODEL: submit doc -> executed PDF
  // -------------------------
  router.post('/docs/:docType', ensureLoggedIn, async (req, res) => {
    try {
      const docType = requireDocType(String(req.params.docType || '').trim());
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

      // Use your actual print view filenames
      const printViewMap = {
        privacy: 'print/privacy',
        payment: 'print/payment',
        aftercare: 'print/aftercare',
      };

      // signature base64 for prints (preferred)
      let signatureDataUrl = null;
      try {
        const sigPath = path.join(ctx.uploadDirs.signatureUploadsDir, path.basename(sig.signature_png));
        const buf = fs.readFileSync(sigPath);
        signatureDataUrl = `data:image/png;base64,${buf.toString('base64')}`;
      } catch (_e) {
        signatureDataUrl = null;
      }

      const html = await new Promise((resolve, reject) => {
        res.render(
          printViewMap[docType],
          {
            payload,
            signature: { ...sig, signature_data_url: signatureDataUrl },
            booking: null, // templates must not depend on booking
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

      // Save PDF
      const filename = `executed_${docType}_${userId}_${Date.now()}_${Math.random().toString(36).slice(2)}.pdf`;
      fs.writeFileSync(path.join(executedPdfDir, filename), pdf);

      const ip = getClientIp(req);
      const ua = req.headers['user-agent'] || '';
      const hash = await insertExecutedDoc({
        userId,
        docType,
        payload,
        signatureId: sig.id,
        ip,
        ua,
        executedPdfFilename: filename,
      });

      await audit.log(req, {
        action: 'executed_doc_signed',
        entityType: 'user',
        entityId: userId,
        details: { docType, executedPdf: filename, hash },
      });

      req.session.message = 'Saved. Your executed PDF has been generated.';
      return res.redirect('/docs');
    } catch (e) {
      console.error('Doc submit error:', e);
      req.session.error = e.message || 'Could not save document.';
      return res.redirect('/docs');
    }
  });

  // -------------------------
  // ADMIN: list executed docs
  // -------------------------
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
