// FILE: lib/mailer.js
const nodemailer = require('nodemailer');

function envBool(key, fallback = false) {
  const v = String(process.env[key] ?? '').trim().toLowerCase();
  if (!v) return fallback;
  return v === 'true' || v === '1' || v === 'yes' || v === 'y';
}

function pickSmtpConfig() {
  const host = String(process.env.SMTP_HOST || '').trim();
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = envBool('SMTP_SECURE', port === 465);

  const user = String(process.env.SMTP_USER || '').trim();
  const pass = String(process.env.SMTP_PASS || '').trim();

  return { host, port, secure, user, pass };
}

function mailFrom() {
  return String(process.env.MAIL_FROM || process.env.SMTP_USER || 'no-reply@localhost').trim();
}

async function createTransportOrNull() {
  const { host, port, secure, user, pass } = pickSmtpConfig();

  // Explicit "log only" mode (no SMTP)
  if (envBool('MAIL_LOG_ONLY', false)) {
    return null;
  }

  // If any required is missing, we fall back to logging
  if (!host || !user || !pass) {
    return null;
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },
  });

  // Optional verify (surface real Gmail/auth issues)
  if (envBool('MAIL_VERIFY', false)) {
    await transporter.verify(); // throws if auth/connection fails
  }

  return transporter;
}

/**
 * sendMailOrLog
 * - If SMTP is configured + works, sends email
 * - Otherwise logs the payload to console
 * - Never throws unless MAIL_VERIFY=true and verify fails (that is intentional)
 */
async function sendMailOrLog({ to, subject, html, text }) {
  const payload = {
    from: mailFrom(),
    to,
    replyTo: process.env.MAIL_REPLY_TO ? String(process.env.MAIL_REPLY_TO).trim() : undefined,
    subject,
    text: text || undefined,
    html: html || undefined,
  };

  let transporter;
  try {
    transporter = await createTransportOrNull();
  } catch (e) {
    // This is where verify/auth errors show up clearly
    console.error('MAIL: Transport verify/create failed:', e?.message || e);
    console.error('MAIL: Payload was:', payload);
    return { ok: false, error: e?.message || String(e) };
  }

  // No SMTP configured => log and succeed
  if (!transporter) {
    console.log('MAIL (LOG ONLY / NO SMTP) =>', payload);
    return { ok: true, skipped: true };
  }

  try {
    const info = await transporter.sendMail(payload);
    console.log('MAIL SENT =>', { to: payload.to, subject: payload.subject, messageId: info?.messageId });
    return { ok: true, messageId: info?.messageId || null };
  } catch (e) {
    console.error('MAIL SEND FAILED =>', e?.message || e);
    console.error('MAIL: Payload was:', payload);
    return { ok: false, error: e?.message || String(e) };
  }
}

module.exports = {
  sendMailOrLog,
};
