const express = require('express');
const bcrypt = require('bcrypt');

module.exports = function inviteRoutes(ctx) {
  const router = express.Router();
  const { dbGet, dbRun, ensureColumn } = ctx.db;

  async function ensureInviteTable() {
    // ensureApplicationInvitesTable-compatible schema
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
    await ensureColumn('model_applications', 'onboarded_user_id INTEGER');
    await ensureColumn('model_applications', 'onboarded_at TEXT');
  }

  // GET invite page
  router.get('/invite/:token', async (req, res) => {
    try {
      await ensureInviteTable();
      await ensureApplicationsTable();

      const token = String(req.params.token || '').trim();
      if (!token) return res.status(400).render('error', { message: 'Invalid invite token.' });

      const invite = await dbGet(
        `
        SELECT ai.id, ai.application_id, ai.email, ai.used,
               ma.stage_name
        FROM application_invites ai
        LEFT JOIN model_applications ma ON ma.id = ai.application_id
        WHERE ai.token = ?
        LIMIT 1
        `,
        [token]
      );

      if (!invite) return res.status(404).render('error', { message: 'Invite link not found.' });
      if (invite.used) return res.status(410).render('error', { message: 'This invite link has already been used.' });

      return res.render('invite-accept', {
        email: invite.email,
        stage_name: invite.stage_name || '',
        token,
        message: null,
        error: null,
        form: {},
      });
    } catch (e) {
      console.error('Invite GET error:', e);
      return res.status(500).render('error', { message: 'Could not load invite page.' });
    }
  });

  // POST redeem invite (create model account)
  router.post('/invite/:token', async (req, res) => {
    try {
      await ensureInviteTable();
      await ensureApplicationsTable();

      const token = String(req.params.token || '').trim();
      if (!token) return res.status(400).render('error', { message: 'Invalid invite token.' });

      const invite = await dbGet(
        `
        SELECT ai.id, ai.application_id, ai.email, ai.used,
               ma.stage_name
        FROM application_invites ai
        LEFT JOIN model_applications ma ON ma.id = ai.application_id
        WHERE ai.token = ?
        LIMIT 1
        `,
        [token]
      );

      if (!invite) return res.status(404).render('error', { message: 'Invite link not found.' });
      if (invite.used) return res.status(410).render('error', { message: 'This invite link has already been used.' });

      const username = String(req.body.username || '').trim();
      const password = String(req.body.password || '').trim();
      const password2 = String(req.body.password2 || '').trim();

      const form = { username };

      if (!username || username.length < 3) {
        return res.status(400).render('invite-accept', {
          email: invite.email,
          stage_name: invite.stage_name || '',
          token,
          error: 'Username must be at least 3 characters.',
          message: null,
          form,
        });
      }
      if (!password || password.length < 8) {
        return res.status(400).render('invite-accept', {
          email: invite.email,
          stage_name: invite.stage_name || '',
          token,
          error: 'Password must be at least 8 characters.',
          message: null,
          form,
        });
      }
      if (password !== password2) {
        return res.status(400).render('invite-accept', {
          email: invite.email,
          stage_name: invite.stage_name || '',
          token,
          error: 'Passwords do not match.',
          message: null,
          form,
        });
      }

      // Ensure username not taken
      const existing = await dbGet(`SELECT id FROM users WHERE LOWER(username)=LOWER(?) LIMIT 1`, [username]);
      if (existing) {
        return res.status(400).render('invite-accept', {
          email: invite.email,
          stage_name: invite.stage_name || '',
          token,
          error: 'That username is already taken.',
          message: null,
          form,
        });
      }

      const password_hash = await bcrypt.hash(password, 10);

      // Create the model user
      const ins = await dbRun(
        `
        INSERT INTO users (username, password_hash, role, status, email, email_verified)
        VALUES (?, ?, 'model', 'approved', ?, 1)
        `,
        [username, password_hash, String(invite.email || '').toLowerCase()]
      );

      const userId = ins?.lastID;

      // Seed model_profiles if table exists (safe)
      try {
        await dbRun(
          `
          INSERT OR IGNORE INTO model_profiles (user_id, preferred_name, email, created_at, updated_at)
          VALUES (?, ?, ?, datetime('now'), datetime('now'))
          `,
          [userId, invite.stage_name || null, String(invite.email || '').toLowerCase()]
        );
      } catch (e) {
        // model_profiles might not exist in some installs; don't block account creation
        console.warn('model_profiles seed skipped:', e?.message || e);
      }

      // Mark invite used
      await dbRun(`UPDATE application_invites SET used=1, used_at=datetime('now') WHERE id=?`, [invite.id]);

      // Mark application as onboarded
      await dbRun(
        `UPDATE model_applications SET onboarded_user_id=?, onboarded_at=datetime('now') WHERE id=?`,
        [userId, invite.application_id]
      );

      // Redirect to login
      req.session.message = 'Account created. You can log in now.';
      return req.session.save(() => res.redirect('/login'));
    } catch (e) {
      console.error('Invite POST error:', e);
      return res.status(500).render('error', { message: 'Could not create account from invite.' });
    }
  });

  return router;
};
