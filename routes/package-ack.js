// FILE: routes/package-ack.js
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');

let puppeteer = null;
try {
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
  if (!req.session?.user) return res.redirect('/staff-login'); // ✅ FIX: staff login route
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

module.exports = function packageAckRoutes(ctx) {
  const router = express.Router();

  const { dbRun, dbGet } = ctx.db;
  const audit = ctx.audit;

  (async () => {
    await dbRun(`
      CREATE TABLE IF NOT EXISTS executed_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        booking_id INTEGER,
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
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_executed_docs_booking ON executed_documents(booking_id);`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_executed_docs_user ON executed_documents(user_id);`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_executed_docs_type ON executed_documents(doc_type);`);
  })().catch((e) => console.error('executed_documents init failed:', e));

  const executedPdfDir = ctx.uploadDirs.docUploadsDir;

  // present but not required for your current flow
  multer({
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
    return dbGet(
      `SELECT br.*, b.title AS booking_title, b.shoot_date, b.location
       FROM booking_recipients br
       LEFT JOIN bookings b ON b.id = br.booking_id
       WHERE br.token = ? LIMIT 1`,
      [token]
    );
  }

  async function getLatestSignature(userId) {
    return dbGet(`SELECT * FROM signatures WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`, [userId]);
  }

  async function insertExecutedDoc({ bookingId, userId, docType, payload, signatureId, ip, ua, executedPdfFilename }) {
    const payloadJson = JSON.stringify(payload);
    const docHash = sha256Hex(payloadJson);

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

  router.post('/package/:token/ack/:docType', ensureAgeConfirmed, async (req, res) => {
    try {
      const token = String(req.params.token || '').trim();
      const docType = requireDocType(String(req.params.docType || '').trim());

      const rec = await getRecipientByToken(token);
      if (!rec) return res.status(404).render('error', { message: 'Package link not found.' });

      const userId = rec.user_id;
      const bookingId = rec.booking_id;

      const sig = await getLatestSignature(userId);
      if (!sig) {
        req.session.error = 'Please complete your signature first (Signature Setup).';
        return res.redirect(`/package/${token}`);
      }

      const base = { docType, bookingId, userId, submittedAtIso: new Date().toISOString() };
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

      const printViewMap = {
        privacy: 'print/print-privacy',
        payment: 'print/print-payment',
        aftercare: 'print/print-aftercare',
      };

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

      const pdf = await renderPdfFromHtml({ html });

      const filename = `executed_${docType}_${userId}_${Date.now()}_${Math.random().toString(36).slice(2)}.pdf`;
      fs.writeFileSync(path.join(executedPdfDir, filename), pdf);

      const ip = getClientIp(req);
      const ua = req.headers['user-agent'] || '';
      const docHash = await insertExecutedDoc({
        bookingId,
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
