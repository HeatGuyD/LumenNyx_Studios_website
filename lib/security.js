// lib/security.js
const crypto = require('crypto');
const path = require('path');

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff && typeof xff === 'string') return xff.split(',')[0].trim();
  return (req.ip || req.connection?.remoteAddress || '').toString();
}

function sha256Hex(bufferOrString) {
  const h = crypto.createHash('sha256');
  h.update(bufferOrString);
  return h.digest('hex');
}

function sanitizeFilename(name) {
  return path.basename(String(name || ''));
}

module.exports = { getClientIp, sha256Hex, sanitizeFilename };
