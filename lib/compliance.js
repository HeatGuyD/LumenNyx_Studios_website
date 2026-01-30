// FILE: lib/compliance.js
// Centralized compliance gating for model actions (bookings, scenes, etc.)
//
// Usage (in routes):
//   router.get('/model/bookings', requireModel, ctx.compliance.requireModelCompliant, ...)

function makeCompliance(ctx) {
  const { dbGet, dbAll } = ctx.db;

  async function requireModelCompliant(req, res, next) {
    try {
      // Must be logged in as model
      const user = req.session?.user;
      if (!user?.id) return res.redirect('/login');
      if (user.role !== 'model') return res.status(403).render('error', { message: 'Access denied.' });

      const userId = user.id;

      // 1) Must have a saved signature
      const sig = await dbGet(
        `SELECT id FROM signatures WHERE user_id=? ORDER BY datetime(created_at) DESC, id DESC LIMIT 1`,
        [userId]
      );
      if (!sig) {
        req.session.error = 'Please complete your signature first.';
        return res.redirect('/model/profile');
      }

      // 2) Must have a master release
      const mr = await dbGet(
        `SELECT id FROM master_releases WHERE user_id=? ORDER BY datetime(signed_at) DESC, id DESC LIMIT 1`,
        [userId]
      );
      if (!mr) {
        req.session.error = 'You must sign the Master Release before bookings are available.';
        return res.redirect('/model/profile');
      }

      // 3) Must have consent policies
      const pol = await dbGet(`SELECT user_id FROM consent_policies WHERE user_id=? LIMIT 1`, [userId]);
      if (!pol) {
        req.session.error = 'You must complete Consent & Safety before bookings are available.';
        return res.redirect('/model/profile');
      }

      // 4) Must have all REQUIRED legal templates signed (doc_kind='legal')
      // If you want strict version enforcement, enable the version check section below.
      const requiredTemplates = await dbAll(
        `SELECT id, version, title
         FROM legal_templates
         WHERE active=1 AND required=1
         ORDER BY id ASC`
      );

      for (const t of requiredTemplates || []) {
        const exec = await dbGet(
          `SELECT template_version
           FROM executed_documents
           WHERE user_id=? AND doc_kind='legal' AND template_id=?
           ORDER BY datetime(signed_at) DESC, id DESC
           LIMIT 1`,
          [userId, t.id]
        );

        if (!exec) {
          req.session.error = 'All required legal documents must be signed before bookings are available.';
          return res.redirect('/docs');
        }

        // OPTIONAL STRICT VERSION ENFORCEMENT:
        // If template version changes, force re-sign.
        // const needsResign = String(exec.template_version || '') !== String(t.version || '');
        // if (needsResign) {
        //   req.session.error = `A required document was updated and needs to be re-signed: ${t.title}`;
        //   return res.redirect('/docs');
        // }
      }

      return next();
    } catch (e) {
      console.error('requireModelCompliant error:', e);
      req.session.error = 'Compliance check failed. Please try again.';
      return res.redirect('/model/profile');
    }
  }

  return { requireModelCompliant };
}

module.exports = { makeCompliance };
