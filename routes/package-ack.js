const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

let puppeteer = null;
try {
  // npm i puppeteer
  puppeteer = require('puppeteer');
} catch (e) {
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

function ensureAgeConfirmed(req, res, next) {
  if (!req.session?.ageConfirmed) return res.redirect('/age-check');
  next();
}

function ensureAdmin(req, res, next) {
  if (!req.session?.ageConfirmed) return res.redirect('/age-check');
  if (!req.session?.user) return res.redirect('/login');
  const role = req.session.user.role;
  if (role !== 'admin' && role !== 'staff') return res.status(403).render('error', { message: 'Forbidden' });
  next();
}

async function renderPdfFromHtml({ html, baseUrl }) {
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
    if (baseUrl) {
      await page.setContent(html, { waitUntil: 'networkidle0' });
    } else {
      await page.setContent(html, { waitUntil: 'networkidle0' });
    }

    const pdf = await page.pdf({
      format: 'Letter',
      printBackground: true,
      margin: { top: '0.55in', right: '0.6in', bottom: '0.55in', left: '0.6in' },
    });
    return pdf;
  } finally {
    await browser.close();
  }
}

function safeBaseUrl(req) {
  const APP_BASE_URL = process.env.APP_BASE_URL || '';
  if (APP_BASE_URL && APP_BASE_URL.startsWith('http')) return APP_BASE_URL.replace(/\/+$/, '');
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${proto}://${host}`.replace(/\/+$/, '');
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

/**
 * Assumes you already have booking_recipients table from the earlier “package token” feature:
 * - booking_recipients(token TEXT UNIQUE, booking_id INTEGER, user_id INTEGER, status TEXT, etc)
 * If your table name differs, change the SELECTs below accordingly.
 */
module.exports = function packageAckRoutes(ctx) {
  const router = express.Router();

  const { dbRun, dbGet } = ctx.db;
  const audit = ctx.audit;

  // Ensure executed_documents table exists (safe to call at startup)
  (async () => {
    await dbRun(`
      CREATE TABLE IF NOT EXISTS executed_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_id INTEGER,
        user_id INTEGER NOT NULL,
        doc_type TEXT NOT NULL,                -- privacy | payment | aftercare
        payload_json TEXT NOT NULL,
        signed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        signature_id INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        document_hash TEXT,
        executed_pdf_filename TEXT
      )
    `);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_executed_docs_booking ON executed_documents(booking_id);`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_executed_docs_user ON executed_documents(user_id);`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_executed_docs_type ON executed_documents(doc_type);`);
  })().catch((e) => console.error('executed_documents init failed:', e));

  // Optional: store executed PDFs in uploads/docs (admin + owner access already exists in your secure routes)
  const executedPdfDir = ctx.uploadDirs.docUploadsDir;

  // Upload handler if you later want to attach supporting PDFs (not required for this feature)
  const upload = multer({
    storage: multer.diskStorage({
      destination: (_req, _file, cb) => cb(null, ctx.uploadDirs.docUploadsDir),
      filename: (req, file, cb) => {
        const userPart = req.session?.user?.id ? `${req.session.user.id}_` : 'token_';
        const uniqueName = `${userPart}${Date.now()}_${Math.random().toString(36).slice(2)}${path.extname(
          file.originalname || ''
        ).toLowerCase()}`;
        cb(null, uniqueName);
      },
    }),
    limits: { fileSize: 20 * 1024 * 1024 },
  });

  async function getRecipientByToken(token) {
    const rec = await dbGet(
      `SELECT br.*, b.title AS booking_title, b.shoot_date, b.location
       FROM booking_recipients br
       LEFT JOIN bookings b ON b.id = br.booking_id
       WHERE br.token = ? LIMIT 1`,
      [token]
    );
    return rec;
  }

  async function getLatestSignature(userId) {
    return dbGet(`SELECT * FROM signatures WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`, [userId]);
  }

  async function upsertExecutedDoc({
    bookingId,
    userId,
    docType,
    payload,
    signatureId,
    ip,
    ua,
    executedPdfFilename,
  }) {
    const payloadJson = JSON.stringify(payload);
    const docHash = sha256Hex(payloadJson);

    // Keep last executed version (insert new row for strict history OR update latest).
    // Recommendation: insert new row to preserve history.
    await dbRun(
      `INSERT INTO executed_documents (
         booking_id, user_id, doc_type,
         payload_json, signature_id,
         ip_address, user_agent,
         document_hash, executed_pdf_filename
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [bookingId || null, userId, docType, payloadJson, signatureId || null, ip, ua, docHash, executedPdfFilename || null]
    );

    return docHash;
  }

  // -----------------------------
  // PACKAGE FLOW: SHOW DOC (token)
  // -----------------------------
  router.get('/package/:token/ack/:docType', ensureAgeConfirmed, async (req, res) => {
    try {
      const token = String(req.params.token || '').trim();
      const docType = requireDocType(String(req.params.docType || '').trim());

      const rec = await getRecipientByToken(token);
      if (!rec) return res.status(404).render('error', { message: 'Package link not found.' });

      const sig = await getLatestSignature(rec.user_id);

      const booking = {
        id: rec.booking_id,
        title: rec.booking_title || `Booking ${rec.booking_id}`,
        shoot_date: rec.shoot_date || null,
        location: rec.location || null,
      };

      const viewMap = {
        privacy: 'package/privacy',
        payment: 'package/payment',
        aftercare: 'package/aftercare',
      };

      return res.render(viewMap[docType], {
        token,
        docType,
        booking,
        signature: sig || null,
        studioEmails: ctx.STUDIO_EMAILS,
      });
    } catch (e) {
      console.error('Ack view error:', e);
      return res.status(e.status || 500).render('error', { message: e.message || 'Could not load document.' });
    }
  });

  // -----------------------------
  // PACKAGE FLOW: SUBMIT DOC (token)
  // -----------------------------
  router.post('/package/:token/ack/:docType', ensureAgeConfirmed, async (req, res) => {
    try {
      const token = String(req.params.token || '').trim();
      const docType = requireDocType(String(req.params.docType || '').trim());

      const rec = await getRecipientByToken(token);
      if (!rec) return res.status(404).render('error', { message: 'Package link not found.' });

      const userId = rec.user_id;
      const bookingId = rec.booking_id;

      // Must have a signature on file (your portal already collects signature images)
      const sig = await getLatestSignature(userId);
      if (!sig) {
        req.session.error = 'Please complete your signature first (Signature Setup).';
        return res.redirect(`/package/${token}`); // or a dedicated signature page
      }

      // Build payload based on docType
      const base = {
        docType,
        bookingId,
        userId,
        submittedAtIso: new Date().toISOString(),
      };

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
          return res.redirect(`/package/${token}/ack/privacy`);
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
          return res.redirect(`/package/${token}/ack/payment`);
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
          return res.redirect(`/package/${token}/ack/aftercare`);
        }
      }

      // Render executed PDF from a print template
      const printViewMap = {
        privacy: 'print/print-privacy',
        payment: 'print/print-payment',
        aftercare: 'print/print-aftercare',
      };

      const baseUrl = safeBaseUrl(req);
      const html = await new Promise((resolve, reject) => {
        res.render(
          printViewMap[docType],
          {
            booking: {
              id: rec.booking_id,
              title: rec.booking_title || `Booking ${rec.booking_id}`,
              shoot_date: rec.shoot_date || null,
              location: rec.location || null,
            },
            payload,
            signature: sig,
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

      const pdf = await renderPdfFromHtml({ html, baseUrl });

      // Save executed PDF file
      const filename = `executed_${docType}_${userId}_${Date.now()}_${Math.random().toString(36).slice(2)}.pdf`;
      const fullPath = path.join(executedPdfDir, filename);
      fs.writeFileSync(fullPath, pdf);

      // Persist executed doc record + hash
      const ip = getClientIp(req);
      const ua = req.headers['user-agent'] || '';
      const docHash = await upsertExecutedDoc({
        bookingId,
        userId,
        docType,
        payload,
        signatureId: sig.id,
        ip,
        ua,
        executedPdfFilename: filename,
      });

      // Audit trail
      await audit.log(req, {
        action: 'executed_doc_signed',
        entityType: 'booking',
        entityId: bookingId || null,
        details: { docType, userId, executedPdf: filename, hash: docHash },
      });

      req.session.message = 'Saved. Your executed copy has been generated.';
      return res.redirect(`/package/${token}`);
    } catch (e) {
      console.error('Ack submit error:', e);
      req.session.error = e.message || 'Could not save document.';
      return res.redirect(`/package/${String(req.params.token || '').trim()}`);
    }
  });

  // -----------------------------
  // ADMIN: VIEW/DOWNLOAD EXECUTED PDF
  // -----------------------------
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
