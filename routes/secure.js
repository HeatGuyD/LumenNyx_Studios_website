const express = require('express');

module.exports = function secureRoutes(ctx) {
  const router = express.Router();

  // Placeholder for secure download endpoints
  router.get('/secure', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    return res.send('SECURE ROUTES STUB');
  });

  return router;
};
