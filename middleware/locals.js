// middleware/locals.js
function attachSessionToLocals({ STUDIO_EMAILS }) {
  return function attach(req, res, next) {
    const user = req.session?.user || null;

    // User/session locals
    res.locals.currentUser = user;
    res.locals.isAuthenticated = Boolean(user && user.id);
    res.locals.username = user?.username || '';

    // Flash locals (one-time)
    res.locals.message = req.session?.message || null;
    res.locals.error = req.session?.error || null;

    // Portal-wide emails
    res.locals.CONTACT_EMAILS = STUDIO_EMAILS;
    res.locals.studioEmails = STUDIO_EMAILS;

    // Legacy safety (in case any old template still references it)
    if (typeof res.locals.videos === 'undefined') res.locals.videos = [];

    // Clear flash after exposing it to templates
    if (req.session) {
      delete req.session.message;
      delete req.session.error;
    }

    next();
  };
}

module.exports = { attachSessionToLocals };
