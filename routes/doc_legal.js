// FILE: routes/doc_legal.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

module.exports = function attachLegalDocRoutes(router, ctx) {
  const { dbRun, dbGet, dbAll, ensureColumn } = ctx.db;
  const audit = ctx.audit;

  const ensureLoggedIn = ctx.ensureLoggedIn;
  const ensureAdmin = ctx.ensureAdmin; // kept for future use
  const renderPdfFromHtml = ctx.renderPdfFromHtml;

  const executedPdfDir = ctx.uploadDirs.docUploadsDir;
  const signatureUploadsDir = ctx.uploadDirs.signatureUploadsDir;

  // -----------------------------
  // Helpers
  // -----------------------------
  function escapeHtml(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function escapeRegExp(s) {
    return String(s || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function getClientIp(req) {
    const xff = req.headers['x-forwarded-for'];
    if (xff && typeof xff === 'string') return xff.split(',')[0].trim();
    return (req.ip || req.connection?.remoteAddress || '').toString();
  }

  function ensureDirExists(dirPath) {
    try {
      fs.mkdirSync(dirPath, { recursive: true });
    } catch (e) {
      if (e && e.code !== 'EEXIST') console.error('Failed to ensure directory:', dirPath, e);
    }
  }

  function consumeFlash(req) {
    const out = { error: req.session?.error || null, message: req.session?.message || null };
    if (req.session) {
      delete req.session.error;
      delete req.session.message;
    }
    return out;
  }

  function safeJsonParse(str, fallback) {
    try {
      const v = JSON.parse(str);
      return v === undefined || v === null ? fallback : v;
    } catch (_e) {
      return fallback;
    }
  }

  function normalizeSlug(slug) {
    return String(slug || '').trim().toLowerCase();
  }

  function isTruthy(v) {
    return v === true || v === 'true' || v === 'on' || v === '1' || v === 1;
  }

  function cleanVal(v) {
    const s = String(v ?? '').trim();
    return s.length ? s : null;
  }

  function safeFilenamePart(s) {
    return String(s || '').replace(/[^a-z0-9_.-]/gi, '_');
  }

  function pickViewName() {
    // Many installs still have model-legal-sign.ejs. Others have model-legal-fill.ejs.
    // This picks whichever exists so we stop 500s from missing views.
    try {
      const viewsDir = ctx.viewsDir || path.join(process.cwd(), 'views');
      const signPath = path.join(viewsDir, 'model-legal-sign.ejs');
      if (fs.existsSync(signPath)) return 'model-legal-sign';

      const fillPath = path.join(viewsDir, 'model-legal-fill.ejs');
      if (fs.existsSync(fillPath)) return 'model-legal-fill';
    } catch (_e) {}

    // Default to fill (newer)
    return 'model-legal-fill';
  }

  // -----------------------------
  // DB access helpers
  // -----------------------------
  async function getLatestSignature(userId) {
    return dbGet(
      `SELECT id, method, typed_name, typed_style, signature_png, initials_png, created_at
       FROM signatures
       WHERE user_id=?
       ORDER BY datetime(created_at) DESC, id DESC
       LIMIT 1`,
      [userId]
    );
  }

  async function getTemplateBySlug(slug) {
    return dbGet(
      `SELECT id, slug, title, body_html, version, required, active, updated_at, created_at, fields_json
       FROM legal_templates
       WHERE lower(slug)=lower(?) AND active=1
       LIMIT 1`,
      [slug]
    );
  }

  async function getLatestExecutedForTemplate(userId, templateId) {
    return dbGet(
      `SELECT id, template_id, template_version, signed_at, executed_pdf_filename, document_hash
       FROM executed_documents
       WHERE user_id=? AND doc_kind='legal' AND template_id=?
       ORDER BY datetime(signed_at) DESC, id DESC
       LIMIT 1`,
      [userId, templateId]
    );
  }

  async function insertExecutedLegalDoc({
    userId,
    template,
    payload,
    signatureId,
    ip,
    ua,
    executedPdfFilename,
    documentHash,
  }) {
    await dbRun(
      `INSERT INTO executed_documents
       (user_id, doc_type, doc_kind, payload_json, signature_id, ip_address, user_agent, document_hash, executed_pdf_filename,
        template_id, template_slug, template_title, template_version)
       VALUES (?, ?, 'legal', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId,
        'legal_template',
        JSON.stringify(payload),
        signatureId || null,
        ip || null,
        ua || null,
        documentHash || null,
        executedPdfFilename || null,
        template.id,
        template.slug,
        template.title,
        template.version,
      ]
    );

    const row = await dbGet(`SELECT last_insert_rowid() AS id`, []);
    return row?.id || null;
  }

  // IMPORTANT: decouple "signed" from "pdf rendered"
  async function updateExecutedPdf(executedId, executedPdfFilename, documentHash) {
    if (!executedId) return;
    await dbRun(
      `UPDATE executed_documents
       SET executed_pdf_filename = COALESCE(executed_pdf_filename, ?),
           document_hash = COALESCE(document_hash, ?)
       WHERE id = ?`,
      [executedPdfFilename || null, documentHash || null, executedId]
    );
  }

  // -----------------------------
  // Field schemas (DB or defaults)
  // -----------------------------
  function defaultFieldsForSlug(slug) {
    const s = normalizeSlug(slug);

    // Common identity block used across docs
    const identity = [
      { key: 'performer_legal_name', label: 'Performer Legal Name', type: 'text', required: true, max: 120 },
      { key: 'performer_stage_name', label: 'Stage Name / Alias', type: 'text', required: false, max: 120 },
      { key: 'performer_dob', label: 'Date of Birth', type: 'date', required: true },
      { key: 'performer_email', label: 'Email', type: 'email', required: true, max: 180 },
      { key: 'performer_phone', label: 'Phone', type: 'text', required: false, max: 40 },
    ];

    const address = [
      { key: 'address_line1', label: 'Address (Street)', type: 'text', required: true, max: 180 },
      { key: 'address_line2', label: 'Address (Apt/Unit)', type: 'text', required: false, max: 60 },
      { key: 'address_city', label: 'City', type: 'text', required: true, max: 80 },
      { key: 'address_state', label: 'State', type: 'text', required: true, max: 40 },
      { key: 'address_zip', label: 'ZIP', type: 'text', required: true, max: 20 },
      { key: 'address_country', label: 'Country', type: 'text', required: false, max: 60 },
    ];

    if (s === '2257-compliance') {
      return [
        ...identity,
        ...address,
        {
          key: 'id_type',
          label: 'Government ID Type',
          type: 'select',
          required: true,
          options: ['Driver License', 'State ID', 'Passport', 'Other'],
        },
        { key: 'id_issuer', label: 'Issuing Authority / State / Country', type: 'text', required: true, max: 80 },
        { key: 'id_number', label: 'ID Number', type: 'text', required: true, max: 80 },
        { key: 'id_issue_date', label: 'ID Issue Date', type: 'date', required: false },
        { key: 'id_expiration_date', label: 'ID Expiration Date', type: 'date', required: false },
        { key: 'ack_age_18', label: 'I confirm I am 18+ and the DOB entered is truthful', type: 'checkbox', required: true },
      ];
    }

    if (s.includes('consent') || s.includes('limits')) {
      return [
        { key: 'shoot_date', label: 'Shoot Date', type: 'date', required: false },
        { key: 'shoot_location', label: 'Shoot Location', type: 'text', required: false, max: 140 },
        { key: 'scene_partners', label: 'Scene Partner(s)', type: 'text', required: false, max: 180 },
        ...identity,
        { key: 'allows_kissing', label: 'Allows Kissing', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'allows_nudity_topless', label: 'Allows Topless Nudity', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'allows_nudity_full', label: 'Allows Full Nudity', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'allows_oral_giving', label: 'Allows Oral (Giving)', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'allows_oral_receiving', label: 'Allows Oral (Receiving)', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'allows_vaginal', label: 'Allows Vaginal Intercourse', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'allows_anal', label: 'Allows Anal Intercourse', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'allows_rough', label: 'Allows Rough Pace / Dynamics', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'allows_spanking', label: 'Allows Spanking', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'allows_hair_pulling', label: 'Allows Hair Pulling', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'allows_choking', label: 'Allows Choking / Breath Play', type: 'select', required: true, options: ['Yes', 'No', 'Conditional'] },
        { key: 'hard_limits', label: 'Hard Limits (No-Go)', type: 'textarea', required: false, max: 2000 },
        { key: 'soft_limits', label: 'Soft Limits / Conditions', type: 'textarea', required: false, max: 2000 },
        { key: 'safeword', label: 'Safeword', type: 'text', required: true, max: 60 },
        { key: 'nonverbal_signal', label: 'Non-Verbal Stop Signal', type: 'text', required: false, max: 120 },
        { key: 'notes', label: 'Special Notes / Conditions', type: 'textarea', required: false, max: 3000 },
        { key: 'ack_understood', label: 'I understand I can stop at any time and consent can be withdrawn', type: 'checkbox', required: true },
      ];
    }

    if (s.includes('sti') || s.includes('test')) {
      return [
        { key: 'shoot_date', label: 'Shoot Date', type: 'date', required: false },
        { key: 'shoot_location', label: 'Shoot Location', type: 'text', required: false, max: 140 },
        ...identity,
        { key: 'testing_facility', label: 'Testing Facility / Provider', type: 'text', required: true, max: 140 },
        { key: 'specimen_date', label: 'Specimen Collection Date', type: 'date', required: true },
        { key: 'ack_truth', label: 'I affirm these testing details are truthful', type: 'checkbox', required: true },
      ];
    }

    // Generic “signature + identity” for everything else
    return [
      ...identity,
      { key: 'ack_read', label: 'I have read and understand this document', type: 'checkbox', required: true },
    ];
  }

  /**
   * CRITICAL FIX:
   * - If fields_json parses to [] or {fields: []}, we MUST fallback to defaults,
   *   otherwise the UI shows no inputs and the model can only "sign".
   */
  function parseFieldsJson(fieldsJson, slug) {
    const fallback = defaultFieldsForSlug(slug);

    if (!fieldsJson) return fallback;

    const v = safeJsonParse(fieldsJson, null);
    if (!v) return fallback;

    if (Array.isArray(v)) return v.length ? v : fallback;
    if (Array.isArray(v.fields)) return v.fields.length ? v.fields : fallback;

    return fallback;
  }

  function validateFields(schema, body) {
    const errors = [];
    const values = {};

    for (const f of schema || []) {
      const key = String(f.key || '').trim();
      if (!key) continue;

      const raw = body ? body[key] : undefined;

      if (String(f.type || '').toLowerCase() === 'checkbox') {
        const checked = isTruthy(raw);
        values[key] = checked;
        if (f.required && !checked) errors.push(`${f.label || key} is required.`);
        continue;
      }

      const v = cleanVal(raw);
      values[key] = v;

      if (f.required && !v) {
        errors.push(`${f.label || key} is required.`);
        continue;
      }

      if (v && f.max && String(v).length > Number(f.max)) {
        errors.push(`${f.label || key} is too long.`);
      }

      if (v && String(f.type || '').toLowerCase() === 'email') {
        const s = String(v);
        if (!s.includes('@') || !s.includes('.')) errors.push(`${f.label || key} must be a valid email.`);
      }
    }

    return { errors, values };
  }

  async function resolveSignatureDataUrl(signatureRow) {
    if (!signatureRow) return null;

    const sp = String(signatureRow.signature_png || '');
    if (!sp) return null;

    // If stored as data URL, use directly
    if (sp.startsWith('data:image')) return sp;

    // Otherwise treat as filename under signatureUploadsDir
    try {
      const sigPath = path.join(signatureUploadsDir, path.basename(sp));
      const buf = fs.readFileSync(sigPath);
      return `data:image/png;base64,${buf.toString('base64')}`;
    } catch (_e) {
      return null;
    }
  }

  /**
   * INLINE BODY FIELDS (OPTIONAL)
   * If template.body_html contains placeholders like {{performer_legal_name}},
   * replace them with real form inputs/selects/textarea/checkbox.
   *
   * If a template has ZERO placeholders, body renders unchanged.
   */
  function renderBodyWithInputs(bodyHtml, schema, values, prefill) {
    let html = String(bodyHtml || '');
    if (!html) return html;

    const getVal = (k) => {
      const v = values && values[k] !== undefined && values[k] !== null ? values[k] : null;
      if (v !== null && v !== '') return v;
      const p = prefill && prefill[k] !== undefined && prefill[k] !== null ? prefill[k] : null;
      if (p !== null && p !== '') return p;
      return '';
    };

    (schema || []).forEach((f) => {
      const key = String(f && f.key ? f.key : '').trim();
      if (!key) return;

      const type = String(f.type || 'text').toLowerCase();
      const required = f.required ? 'required' : '';
      const max = f.max ? `maxlength="${Number(f.max)}"` : '';
      const valRaw = getVal(key);
      const valEsc = escapeHtml(valRaw);

      let inputHtml = '';

      if (type === 'textarea') {
        inputHtml = `<textarea class="inline-fill" name="${escapeHtml(key)}" ${required} ${max}>${valEsc}</textarea>`;
      } else if (type === 'select') {
        const opts = (f.options || [])
          .map((opt) => {
            const o = String(opt);
            const selected = String(valRaw) === o ? 'selected' : '';
            return `<option value="${escapeHtml(o)}" ${selected}>${escapeHtml(o)}</option>`;
          })
          .join('');
        inputHtml = `<select class="inline-fill" name="${escapeHtml(key)}" ${required}><option value="">— Select —</option>${opts}</select>`;
      } else if (type === 'checkbox') {
        const checked = isTruthy(valRaw) ? 'checked' : '';
        // Checkbox inline includes its label text, but still posts the key name
        inputHtml = `<label class="inline-check"><input class="inline-fill" type="checkbox" name="${escapeHtml(
          key
        )}" value="1" ${checked} ${required}/> <span>${escapeHtml(f.label || key)}</span></label>`;
      } else {
        const itype = type === 'email' || type === 'date' ? type : 'text';
        inputHtml = `<input class="inline-fill" type="${itype}" name="${escapeHtml(key)}" value="${valEsc}" ${required} ${max} />`;
      }

      // Replace ALL occurrences of {{ key }}
      const re = new RegExp(`\\{\\{\\s*${escapeRegExp(key)}\\s*\\}\\}`, 'g');
      html = html.replace(re, inputHtml);
    });

    return html;
  }

  // ------------------------------------------------------------
  // MIGRATION: add fields_json column (safe)
  // ------------------------------------------------------------
  (async () => {
    try {
      await ensureColumn('legal_templates', `fields_json TEXT`);
    } catch (e) {
      console.error('doc_legal migration failed:', e);
    }
  })();

  // ============================================================
  // MODEL: Legal index
  // GET /model/legal
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
        `SELECT id, template_id, template_version, signed_at
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
      const flash = consumeFlash(req);
      return res.render('model-legal-index', {
        currentUser: req.session?.user || null,
        templates: [],
        requiredMissing: 0,
        requiredNeedsResign: 0,
        error: flash.error || 'Could not load legal documents.',
        message: flash.message || null,
      });
    }
  });

  // ============================================================
  // MODEL: View + Fill + Sign template
  // GET /model/legal/:slug
  // POST /model/legal/:slug
  // ============================================================
  router.get('/model/legal/:slug', ensureLoggedIn, async (req, res) => {
    try {
      if (req.session?.user?.role !== 'model') {
        return res.status(403).render('error', { message: 'Access denied.' });
      }

      const slug = normalizeSlug(req.params.slug);
      const userId = req.session.user.id;
      const flash = consumeFlash(req);

      const template = await getTemplateBySlug(slug);
      if (!template) return res.status(404).render('error', { message: 'Document not found.' });

      const signature = await getLatestSignature(userId);
      const signatureDataUrl = await resolveSignatureDataUrl(signature);

      const latestExec = await getLatestExecutedForTemplate(userId, template.id);
      const alreadySigned = !!latestExec && String(latestExec.template_version || '') === String(template.version || '');
      const needsResign = !!latestExec && String(latestExec.template_version || '') !== String(template.version || '');

      const schema = parseFieldsJson(template.fields_json, template.slug);

      // Prefill (best effort) from model_profiles + users
      const user = await dbGet(`SELECT id, username, email FROM users WHERE id=? LIMIT 1`, [userId]);
      const profile = await dbGet(`SELECT * FROM model_profiles WHERE user_id=? LIMIT 1`, [userId]);

      const prefill = {
        performer_legal_name: profile?.legal_name || profile?.preferred_name || null,
        performer_stage_name: profile?.preferred_name || null,
        performer_dob: profile?.date_of_birth || null,
        performer_email: profile?.email || user?.email || null,
        performer_phone: profile?.phone || null,

        // Address tries multiple column names (since schemas vary)
        address_line1: profile?.address_line1 || profile?.address || null,
        address_line2: profile?.address_line2 || null,
        address_city: profile?.city || null,
        address_state: profile?.state || null,
        address_zip: profile?.zip || null,
        address_country: profile?.country || null,
      };

      // Inline placeholder -> input rendering (optional)
      const bodyInlineHtml = renderBodyWithInputs(template.body_html, schema, {}, prefill);

      // View choice: sign vs fill
      const viewName = pickViewName();

      return res.render(viewName, {
        currentUser: req.session.user,
        template,
        schema,
        prefill,
        values: {},
        bodyInlineHtml,

        signature: signature ? { ...signature, signature_data_url: signatureDataUrl } : null,

        alreadySigned,
        needsResign,
        latestExecId: latestExec?.id || null,

        ...flash,
      });
    } catch (e) {
      console.error('Model legal view error:', e);
      return res.status(500).render('error', { message: 'Could not load document.' });
    }
  });

  router.post('/model/legal/:slug', ensureLoggedIn, async (req, res) => {
    try {
      if (req.session?.user?.role !== 'model') {
        return res.status(403).render('error', { message: 'Access denied.' });
      }

      const slug = normalizeSlug(req.params.slug);
      const userId = req.session.user.id;

      const template = await getTemplateBySlug(slug);
      if (!template) {
        req.session.error = 'Document not found.';
        return res.redirect('/model/legal');
      }

      const schema = parseFieldsJson(template.fields_json, template.slug);
      const { errors, values } = validateFields(schema, req.body || {});

      // Must agree to sign
      if (!isTruthy(req.body.agree_to_sign)) {
        errors.push('You must check the agreement box to sign.');
      }

      // Signature captured at signing time (do NOT rely on prior saved signature)
      const signatureDataUrl = String(req.body.signature_data_url || '').trim();
      const typedName = String(req.body.typed_name || '').trim();

      if (!typedName) errors.push('Printed name is required.');
      if (!signatureDataUrl.startsWith('data:image')) {
        errors.push('Signature is missing. Please draw your signature until it appears.');
      }

      if (errors.length) {
        const signature = await getLatestSignature(userId);
        const signatureOnFile = signature ? await resolveSignatureDataUrl(signature) : null;

        const user = await dbGet(`SELECT id, username, email FROM users WHERE id=? LIMIT 1`, [userId]);
        const profile = await dbGet(`SELECT * FROM model_profiles WHERE user_id=? LIMIT 1`, [userId]);

        const prefill = {
          performer_legal_name: profile?.legal_name || profile?.preferred_name || null,
          performer_stage_name: profile?.preferred_name || null,
          performer_dob: profile?.date_of_birth || null,
          performer_email: profile?.email || user?.email || null,
          performer_phone: profile?.phone || null,

          address_line1: profile?.address_line1 || profile?.address || null,
          address_line2: profile?.address_line2 || null,
          address_city: profile?.city || null,
          address_state: profile?.state || null,
          address_zip: profile?.zip || null,
          address_country: profile?.country || null,
        };

        const bodyInlineHtml = renderBodyWithInputs(template.body_html, schema, values || {}, prefill);
        const viewName = pickViewName();

        return res.render(viewName, {
          currentUser: req.session.user,
          template,
          schema,
          prefill,
          values: values || {},
          bodyInlineHtml,

          signature: signature ? { ...signature, signature_data_url: signatureOnFile } : null,

          alreadySigned: false,
          needsResign: false,
          latestExecId: null,

          error: errors.join(' '),
          message: null,
        });
      }

      // Create payload stored to executed_documents
      const ip = getClientIp(req);
      const ua = req.headers['user-agent'] || '';

      const payload = {
        kind: 'legal_template_execution',
        template: {
          id: template.id,
          slug: template.slug,
          title: template.title,
          version: template.version,
        },
        signer: {
          userId,
          username: req.session.user.username,
          printed_name: typedName,
        },
        fields: values,
        consent: {
          agreed: true,
          agreedAtIso: new Date().toISOString(),
        },
        audit: { ip, ua },
      };

      // Use signature captured now (not from signatures table) for PDF
      const signatureForPdf = {
        full_name: typedName,
        typed_name: typedName,
        signature_data_url: signatureDataUrl,
      };

      // Hash up-front and INSERT FIRST (so signing is never blocked by PDF generation)
      const documentHash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');

      const executedId = await insertExecutedLegalDoc({
        userId,
        template,
        payload,
        signatureId: null,
        ip,
        ua,
        executedPdfFilename: null,
        documentHash,
      });

      // Best-effort PDF generation (never block signing)
      let pdfFilename = null;
      try {
        const html = await new Promise((resolve, reject) => {
          res.render(
            'print/legal-template',
            {
              template,
              payload,
              signature: signatureForPdf,
              audit: { ip, ua, signedAtIso: new Date().toISOString() },
              studioEmails: ctx.STUDIO_EMAILS,
            },
            (err, out) => (err ? reject(err) : resolve(out))
          );
        });

        const pdf = await renderPdfFromHtml({ html });

        ensureDirExists(executedPdfDir);

        pdfFilename = `executed_legal_${safeFilenamePart(template.slug)}_${userId}_${Date.now()}_${Math.random()
          .toString(36)
          .slice(2)}.pdf`;

        fs.writeFileSync(path.join(executedPdfDir, pdfFilename), pdf);

        await updateExecutedPdf(executedId, pdfFilename, documentHash);
      } catch (pdfErr) {
        console.error('Legal PDF generation failed (non-blocking):', pdfErr);
      }

      try {
        await audit?.log?.(req, {
          action: 'executed_legal_template_signed',
          entityType: 'user',
          entityId: userId,
          details: {
            templateId: template.id,
            slug: template.slug,
            executedId,
            executedPdf: pdfFilename || null,
            documentHash,
            pdfGenerated: !!pdfFilename,
          },
        });
      } catch (_) {}

      req.session.message = pdfFilename
        ? 'Saved. Your executed PDF has been generated.'
        : 'Saved. Your document is signed, but the PDF could not be generated right now (staff can regenerate later).';

      return res.redirect('/model/legal');
    } catch (e) {
      console.error('Model legal sign error:', e);
      req.session.error = e.message || 'Could not sign document.';
      return res.redirect('/model/legal');
    }
  });

  // ============================================================
  // MODEL: View executed PDF
  // GET /model/legal/executed/:id/pdf
  // ============================================================
  router.get('/model/legal/executed/:id/pdf', ensureLoggedIn, async (req, res) => {
    try {
      if (req.session?.user?.role !== 'model') {
        return res.status(403).render('error', { message: 'Access denied.' });
      }

      const userId = req.session.user.id;
      const id = parseInt(req.params.id, 10);
      if (!id) return res.status(400).render('error', { message: 'Invalid id.' });

      const row = await dbGet(
        `SELECT id, user_id, executed_pdf_filename
         FROM executed_documents
         WHERE id=? AND doc_kind='legal'
         LIMIT 1`,
        [id]
      );

      if (!row) return res.status(404).render('error', { message: 'Not found.' });
      if (Number(row.user_id) !== Number(userId)) return res.status(403).render('error', { message: 'Forbidden.' });
      if (!row.executed_pdf_filename) return res.status(404).render('error', { message: 'PDF missing.' });

      const fp = path.join(executedPdfDir, path.basename(row.executed_pdf_filename));
      if (!fs.existsSync(fp)) return res.status(404).render('error', { message: 'File missing.' });

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `inline; filename="${path.basename(row.executed_pdf_filename)}"`);
      return res.sendFile(fp);
    } catch (e) {
      console.error('Model executed pdf error:', e);
      return res.status(500).render('error', { message: 'Server error.' });
    }
  });

  // ============================================================
  // ADMIN: Helpful routes (optional)
  // NOTE: Your existing doc.js already has admin preview endpoints.
  // This file intentionally avoids duplicating them.
  // ============================================================
};
