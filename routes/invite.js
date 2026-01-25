// FILE: routes/invite.js
const express = require('express');
const bcrypt = require('bcrypt');

module.exports = function inviteRoutes(ctx) {
  const router = express.Router();
  const { dbRun, dbGet, ensureColumn } = ctx.db;

  async function ensureSchema() {
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

    await ensureColumn('model_applications', 'onboarded_user_id INTEGER');
    await ensureColumn('model_applications', 'onboarded_at TEXT');

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

  function isValidEmail(email) {
    const e = String(email || '').trim().toLowerCase();
    return e.length >= 6 && e.includes('@') && e.includes('.');
  }

  function sanitizeUsername(input) {
    return String(input || '')
      .trim()
      .replace(/\s+/g, '_')
      .replace(/[^\w]/g, '')
      .slice(0, 24);
  }

  async function usernameTaken(username) {
    const row = await dbGet(
      `SELECT id FROM users WHERE lower(username)=lower(?) LIMIT 1`,
      [username]
    );
    return !!row;
  }

  async function getInviteByToken(token) {
    return dbGet(
      `
      SELECT ai.*,
             ma.stage_name,
             ma.legal_name,
             ma.status AS app_status
      FROM application_invites ai
      LEFT JOIN model_applications ma ON ma.id = ai.application_id
      WHERE ai.token = ?
      LIMIT 1
      `,
      [token]
    );
  }

  function isApprovedApp(inv) {
    return String(inv?.app_status || '').trim().toLowerCase() === 'approved';
  }

  // GET: show setup page
  // Do NOT force global age-gate here; the form has its own 18+ checkbox
  router.get('/apply/accept/:token', async (req, res) => {
    try {
      await ensureSchema();

      const token = String(req.params.token || '').trim();
      if (!token) return res.status(400).render('error', { message: 'Invalid invite token.' });

      const inv = await getInviteByToken(token);
      if (!inv) return res.status(404).render('error', { message: 'Invite link not found.' });
      if (Number(inv.used) === 1) return res.status(410).render('error', { message: 'This invite link has already been used.' });

      // CRITICAL: only allow if the application is approved
      if (!isApprovedApp(inv)) {
        return res.status(403).render('error', { message: 'This invite is not active.' });
      }

      const preUsername = sanitizeUsername(inv.stage_name || 'model') || 'model';
      const preEmail = String(inv.email || '').trim().toLowerCase();

      return res.render('apply-accept', {
        token,
        error: null,
        form: {
          username: preUsername,
          email: preEmail,
        },
      });
    } catch (e) {
      console.error('Invite accept GET error:', e);
      return res.status(500).render('error', { message: 'Could not load account setup page.' });
    }
  });

  // POST: create account + set session + mark invite used
  router.post('/apply/accept/:token', async (req, res) => {
    try {
      await ensureSchema();

      const token = String(req.params.token || '').trim();
      if (!token) return res.status(400).render('error', { message: 'Invalid invite token.' });

      const inv = await getInviteByToken(token);
      if (!inv) return res.status(404).render('error', { message: 'Invite link not found.' });
      if (Number(inv.used) === 1) return res.status(410).render('error', { message: 'This invite link has already been used.' });

      // CRITICAL: only allow if the application is approved
      if (!isApprovedApp(inv)) {
        return res.status(403).render('error', { message: 'This invite is not active.' });
      }

      const usernameRaw = String(req.body.username || '').trim();
      const emailRaw = String(req.body.email || '').trim().toLowerCase();
      const password = String(req.body.password || '').trim();
      const password2 = String(req.body.password2 || '').trim();
      const ageConfirm = String(req.body.age_confirm || '').trim().toLowerCase();

      const form = { username: usernameRaw, email: emailRaw };

      // Require 18+ confirmation unless session already has it
      if (!req.session?.ageConfirmed) {
        if (ageConfirm !== 'yes') {
          return res.status(400).render('apply-accept', {
            token,
            error: 'You must confirm you are 18+ to continue.',
            form,
          });
        }
        req.session.ageConfirmed = true;
      }

      const username = sanitizeUsername(usernameRaw);
      if (!username || username.length < 3) {
        return res.status(400).render('apply-accept', {
          token,
          error: 'Username must be at least 3 characters (letters/numbers/underscore).',
          form,
        });
      }

      // Security: do not allow changing invite email
      const inviteEmail = String(inv.email || '').trim().toLowerCase();
      if (!isValidEmail(emailRaw) || emailRaw !== inviteEmail) {
        return res.status(400).render('apply-accept', {
          token,
          error: 'Email must match the invited email address.',
          form: { ...form, email: inviteEmail },
        });
      }

      if (!password || password.length < 8) {
        return res.status(400).render('apply-accept', {
          token,
          error: 'Password must be at least 8 characters.',
          form,
        });
      }
      if (password !== password2) {
        return res.status(400).render('apply-accept', {
          token,
          error: 'Passwords do not match.',
          form,
        });
      }

      if (await usernameTaken(username)) {
        return res.status(400).render('apply-accept', {
          token,
          error: 'That username is already taken. Please choose another.',
          form,
        });
      }

      // If a user already exists by email, update password + username
      let user = await dbGet(`SELECT * FROM users WHERE lower(email)=lower(?) LIMIT 1`, [inviteEmail]);
      const hash = await bcrypt.hash(password, 12);

      if (!user) {
        const ins = await dbRun(
          `INSERT INTO users (username, email, password_hash, role, status)
           VALUES (?, ?, ?, 'model', 'approved')`,
          [username, inviteEmail, hash]
        );
        user = await dbGet(`SELECT * FROM users WHERE id=? LIMIT 1`, [ins.lastID]);
      } else {
        await dbRun(`UPDATE users SET password_hash=? WHERE id=?`, [hash, user.id]);
        await dbRun(`UPDATE users SET username=? WHERE id=?`, [username, user.id]);
        user = await dbGet(`SELECT * FROM users WHERE id=? LIMIT 1`, [user.id]);
      }

      // Mark invite used
      await dbRun(`UPDATE application_invites SET used=1, used_at=datetime('now') WHERE id=?`, [inv.id]);

      // Mark application onboarded
      if (inv.application_id) {
        await dbRun(
          `UPDATE model_applications
           SET onboarded_user_id=?, onboarded_at=datetime('now')
           WHERE id=?`,
          [user.id, inv.application_id]
        );
      }

      // Log them in
      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
        status: user.status,
      };

      // Audit (non-blocking)
      try {
        await ctx.audit.log(req, {
          action: 'invite_accepted',
          entityType: 'user',
          entityId: user.id,
          details: { inviteId: inv.id, applicationId: inv.application_id || null },
        });
      } catch (_) {}

      return req.session.save(() => res.redirect('/model/profile'));
    } catch (e) {
      console.error('Invite accept POST error:', e);
      return res.status(500).render('error', { message: 'Could not complete account setup.' });
    }
  });

  return router;
};
