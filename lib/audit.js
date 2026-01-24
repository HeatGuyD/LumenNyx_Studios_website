// lib/audit.js
const { getClientIp } = require('./security');

function makeAudit({ dbRun }) {
  async function auditLog(req, { action, entityType, entityId = null, details = null }) {
    try {
      const actor = req.session?.user || null;

      await dbRun(
        `INSERT INTO audit_events (
          actor_user_id, actor_username, actor_role,
          action, entity_type, entity_id,
          ip_address, user_agent, details_json,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [
          actor?.id || null,
          actor?.username || null,
          actor?.role || null,
          String(action || ''),
          String(entityType || ''),
          entityId !== null ? Number(entityId) : null,
          getClientIp(req),
          req.headers['user-agent'] || '',
          details ? JSON.stringify(details) : null,
        ]
      );
    } catch (e) {
      console.error('AUDIT LOG FAIL:', e);
    }
  }

  // Back-compat aliases
  return {
    auditLog,
    log: async (req, actionOrObj, maybeDetails) => {
      // Support two calling styles:
      // 1) log(req, {action, entityType, entityId, details})
      // 2) log(req, 'action_string', 'details_string')
      if (actionOrObj && typeof actionOrObj === 'object') {
        return auditLog(req, actionOrObj);
      }
      return auditLog(req, {
        action: String(actionOrObj || ''),
        entityType: 'system',
        entityId: null,
        details: maybeDetails ? { message: String(maybeDetails) } : null,
      });
    },
  };
}

module.exports = { makeAudit };
