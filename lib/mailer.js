// FILE: lib/mailer.js
const nodemailer = require('nodemailer');

function envBool(name, fallback = false) {
  const v = process.env[name];
  if (v === undefined || v === null || String(v).trim() === '') return fallback;
  return String(v).trim().toLowerCase() === 'true';
}

function envInt(name, fallback) {
  const v = process.env[name];
  const n = parseInt(String(v || ''), 10);
  return Number.isFinite(n) ? n : fallback;
}

function requiredEnv(name) {
  const v = process.env[name];
  return String(v || '').trim();
}

function buildTransportConfig() {
  const host = requiredEnv('SMTP_HOST');
  const port = envInt('SMTP_PORT', 587);

  // Respect SMTP_SECURE explicitly; if not set, infer from port.
  const secure =
    process.env.SMTP_SECURE !== undefined
      ? envBool('SMTP_SECURE', false)
      : port === 465;

  const user = requiredEnv('SMTP_USER');
  const pass = requiredEnv('SMTP_PASS');

  if (!host || !user || !pass) {
    return { ok: false, error: 'SMTP is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASS in .env' };
  }

  return {
    ok: true,
    cfg: {
      host,
      port,
      secure,
      auth: { user, pass },
      // Helps debug SMTP problems
      logger: envBool('MAIL_DEBUG', false),
      debug: envBool('MAIL_DEBUG', false),
    },
  };
}

function mailFrom() {
  // For Gmail/Workspace, best results are usually from the authenticated user.
  return (process.env.MAIL_FROM || process.env.SMTP_USER || 'no-reply@localhost').trim();
}

async function getTransporterOrNull() {
  const logOnly = envBool('MAIL_LOG_ONLY', false);
  if (logOnly) return null;

  const built = buildTransportConfig();
  if (!built.ok) return null;

  const transporter = nodemailer.createTransport(built.cfg);

  // Optional verify (helps catch auth/port issues immediately)
  const doVerify = envBool('MAIL_VERIFY', false);
  if (doVerify) {
    await transporter.verify(); // throws if connection/auth fails
  }

  return transporter;
}

async function sendMailOrLog({ to, subject, html, text }) {
  const logOnly = envBool('MAIL_LOG_ONLY', false);

  // Normalize recipients
  const toNorm = String(to || '').trim();
  if (!toNorm) {
    return { ok: false, error: 'Missing "to" address' };
  }

  if (logOnly) {
    console.log('MAIL (LOG_ONLY) =>', { to: toNorm, subject, text: text?.slice?.(0, 2000) });
    return { ok: true, skipped: true };
  }

  const transporter = await getTransporterOrNull();
  if (!transporter) {
    console.log('MAIL (NO SMTP CONFIG) =>', { to: toNorm, subject });
    return { ok: true, skipped: true };
  }

  const info = await transporter.sendMail({
    from: mailFrom(),
    to: toNorm,
    replyTo: (process.env.MAIL_REPLY_TO || '').trim() || undefined,
    subject: String(subject || '').trim(),
    text: text || undefined,
    html: html || undefined,
  });

  console.log('MAIL SENT =>', {
    to: toNorm,
    subject: String(subject || '').trim(),
    messageId: info?.messageId,
    response: info?.response,
  });

  return { ok: true, messageId: info.messageId };
}

module.exports = { sendMailOrLog };
