// routes/public.js
const express = require('express');

module.exports = function publicRoutes(ctx) {
  const router = express.Router();

  // Health check
  router.get('/__health', (req, res) => {
    res.type('text').send('Public routes OK');
  });

  // Age gate (GET)
  router.get('/age-check', (req, res) => {
    if (req.session?.ageConfirmed) return res.redirect('/');
    return res.render('age-gate', { error: null });
  });

  // Age gate (POST)
  router.post('/age-check', (req, res) => {
    const ok = req.body?.age_confirm === 'yes';
    if (!ok) {
      return res.status(403).render('age-gate', { error: 'You must be 18+ to enter.' });
    }

    req.session.ageConfirmed = true;

    // Ensure session is persisted before redirect
    return req.session.save(() => res.redirect('/'));
  });

  // Home (booking portal landing / routing hub)
  router.get('/', (req, res) => {
    // Age gate enforced globally in app.js middleware

    if (req.session?.user) {
      if (req.session.user.role === 'admin') return res.redirect('/studio-panel');
      if (req.session.user.role === 'model') return res.redirect('/model/profile');
      // If other roles exist, keep them on landing for now
    }

    return res.render('index');
  });

  router.get('/privacy', (req, res) => res.render('privacy'));
  router.get('/terms', (req, res) => res.render('terms'));
  router.get('/2257', (req, res) => res.render('2257'));

  return router;
};
