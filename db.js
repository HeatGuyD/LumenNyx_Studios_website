// FILE: db.js
// Canonical DB module for LumenNyx portal
// - better-sqlite3 for reliability
// - Preserves API: dbRun/dbGet/dbAll/ensureColumn/initDb
// - Single DB file path (DB_PATH env override)

const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

// Single canonical DB path:
// Prefer DB_PATH, else /var/www/lumennyx/database.sqlite when running from that folder,
// else fallback to local directory.
const dbPath =
  (process.env.DB_PATH && String(process.env.DB_PATH).trim()) ||
  path.join(__dirname, "database.sqlite");

// Ensure directory exists
try {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
} catch (_) {}

// Open DB
const db = new Database(dbPath);

// Pragmas for production stability/perf
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("synchronous = NORMAL");

// ----------------------
// Promise-wrapped helpers
// ----------------------
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    try {
      const stmt = db.prepare(sql);
      const info = stmt.run(params);
      resolve({ lastID: info.lastInsertRowid, changes: info.changes });
    } catch (err) {
      reject(err);
    }
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    try {
      const stmt = db.prepare(sql);
      const row = stmt.get(params);
      resolve(row);
    } catch (err) {
      reject(err);
    }
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    try {
      const stmt = db.prepare(sql);
      const rows = stmt.all(params);
      resolve(rows);
    } catch (err) {
      reject(err);
    }
  });
}

// ----------------------
// Migration helper
// - SQLite cannot ALTER TABLE ADD COLUMN with non-constant DEFAULT (CURRENT_TIMESTAMP / datetime('now') / etc)
// - So we add without DEFAULT then backfill existing rows.
// ----------------------
function _hasNonConstantDefault(columnDefUpper) {
  return (
    columnDefUpper.includes("DEFAULT CURRENT_TIMESTAMP") ||
    columnDefUpper.includes("DEFAULT (DATETIME('NOW'))") ||
    columnDefUpper.includes("DEFAULT (DATE('NOW'))") ||
    columnDefUpper.includes("DEFAULT (TIME('NOW'))") ||
    columnDefUpper.includes("DEFAULT (STRFTIME(")
  );
}

function _stripDefaultClause(columnDef) {
  return String(columnDef || "").replace(/\s+DEFAULT\s+.+$/i, "").trim();
}

async function ensureColumn(tableName, columnDef) {
  const [columnName] = String(columnDef || "").split(/\s+/);
  if (!columnName) return;

  const cols = await dbAll(`PRAGMA table_info(${tableName});`);
  const exists = (cols || []).some((c) => c.name === columnName);
  if (exists) return;

  const defUpper = String(columnDef || "").toUpperCase();

  if (_hasNonConstantDefault(defUpper)) {
    const stripped = _stripDefaultClause(columnDef);

    console.log(
      `DB MIGRATION: Adding column ${columnName} to ${tableName} (without non-constant DEFAULT)`
    );

    await dbRun(`ALTER TABLE ${tableName} ADD COLUMN ${stripped};`);

    try {
      await dbRun(
        `UPDATE ${tableName}
         SET ${columnName} = COALESCE(${columnName}, datetime('now'))
         WHERE ${columnName} IS NULL OR ${columnName} = ''`
      );
    } catch (e) {
      console.warn(
        `DB MIGRATION: Backfill failed for ${tableName}.${columnName}:`,
        e?.message || e
      );
    }
    return;
  }

  console.log(`DB MIGRATION: Adding column ${columnName} to ${tableName}`);
  await dbRun(`ALTER TABLE ${tableName} ADD COLUMN ${columnDef};`);
}

// ----------------------
// One-time init
// ----------------------
let _initPromise = null;

async function initDb() {
  if (_initPromise) return _initPromise;

  _initPromise = (async () => {
    await dbRun("PRAGMA foreign_keys = ON;");

    // ---- Existing feature table ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        filename TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // ---- Users ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'model',
        status TEXT NOT NULL DEFAULT 'pending',
        email TEXT,
        email_verified INTEGER DEFAULT 0,
        verification_token TEXT,
        is_paid_member INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await ensureColumn("users", "status TEXT NOT NULL DEFAULT 'pending'");
    await ensureColumn("users", "email_verified INTEGER DEFAULT 0");
    await ensureColumn("users", "verification_token TEXT");
    await ensureColumn("users", "is_paid_member INTEGER DEFAULT 0");
    await ensureColumn("users", "email TEXT");

    // ---- Model profiles ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS model_profiles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE,
        legal_name TEXT,
        aliases TEXT,
        preferred_name TEXT,
        date_of_birth TEXT,
        country TEXT,
        state TEXT,
        phone TEXT,
        email TEXT,
        emergency_name TEXT,
        emergency_phone TEXT,
        age_truth_ack INTEGER DEFAULT 0,
        headshot_path TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    await ensureColumn("model_profiles", "legal_name TEXT");
    await ensureColumn("model_profiles", "aliases TEXT");
    await ensureColumn("model_profiles", "preferred_name TEXT");
    await ensureColumn("model_profiles", "date_of_birth TEXT");
    await ensureColumn("model_profiles", "country TEXT");
    await ensureColumn("model_profiles", "state TEXT");
    await ensureColumn("model_profiles", "phone TEXT");
    await ensureColumn("model_profiles", "email TEXT");
    await ensureColumn("model_profiles", "emergency_name TEXT");
    await ensureColumn("model_profiles", "emergency_phone TEXT");
    await ensureColumn("model_profiles", "age_truth_ack INTEGER DEFAULT 0");
    await ensureColumn("model_profiles", "headshot_path TEXT");
    await ensureColumn("model_profiles", "created_at DATETIME DEFAULT CURRENT_TIMESTAMP");
    await ensureColumn("model_profiles", "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP");

    // ---- Compliance documents ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS compliance_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        doc_type TEXT NOT NULL,
        filename TEXT NOT NULL,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    // ---- Model photos ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS model_photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        caption TEXT,
        is_primary INTEGER DEFAULT 0,
        priority INTEGER DEFAULT 0,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    await ensureColumn("model_photos", "caption TEXT");
    await ensureColumn("model_photos", "is_primary INTEGER DEFAULT 0");
    await ensureColumn("model_photos", "priority INTEGER DEFAULT 0");
    await ensureColumn("model_photos", "uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP");

    // ---- Master releases ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS master_releases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        signed_name TEXT NOT NULL,
        signed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        user_agent TEXT,
        signature_id INTEGER,
        signature_method TEXT,
        signature_png TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    await ensureColumn("master_releases", "signed_at DATETIME DEFAULT CURRENT_TIMESTAMP");
    await ensureColumn("master_releases", "ip_address TEXT");
    await ensureColumn("master_releases", "user_agent TEXT");
    await ensureColumn("master_releases", "signature_id INTEGER");
    await ensureColumn("master_releases", "signature_method TEXT");
    await ensureColumn("master_releases", "signature_png TEXT");

    // ---- Document Requests ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS document_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        doc_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',  -- pending | completed | void
        requested_by_user_id INTEGER,
        note TEXT,
        requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME,
        voided_at DATETIME,
        executed_document_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    await dbRun(`CREATE INDEX IF NOT EXISTS idx_docreq_user ON document_requests(user_id);`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_docreq_type ON document_requests(doc_type);`);
    await dbRun(`CREATE INDEX IF NOT EXISTS idx_docreq_status ON document_requests(status);`);

    await dbRun(`
      CREATE UNIQUE INDEX IF NOT EXISTS ux_docreq_one_pending
      ON document_requests(user_id, doc_type)
      WHERE status='pending'
    `);

    // ---- Signatures ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        method TEXT NOT NULL,
        typed_name TEXT,
        typed_style TEXT,
        signature_png TEXT NOT NULL,
        initials_png TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        user_agent TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    // ---- Consent policies ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS consent_policies (
        user_id INTEGER PRIMARY KEY,
        sti_testing_routine INTEGER DEFAULT 0,
        sti_disclosure_truth INTEGER DEFAULT 0,
        sti_notes TEXT,
        consent_allows_kissing INTEGER DEFAULT 0,
        consent_allows_nudity INTEGER DEFAULT 0,
        consent_allows_rough INTEGER DEFAULT 0,
        consent_allows_choking INTEGER DEFAULT 0,
        consent_hard_limits TEXT,
        consent_soft_limits TEXT,
        policy_no_substances INTEGER DEFAULT 0,
        policy_safe_word INTEGER DEFAULT 0,
        policy_breaks INTEGER DEFAULT 0,
        policy_reporting INTEGER DEFAULT 0,
        policy_understand_no_guaranteed_removal INTEGER DEFAULT 0,
        policy_internal_requests INTEGER DEFAULT 0,
        policy_removal_notes TEXT,
        contractor_acknowledge INTEGER DEFAULT 0,
        contractor_signature TEXT,
        consent_json TEXT,
        consent_version TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    await ensureColumn("consent_policies", "consent_json TEXT");
    await ensureColumn("consent_policies", "consent_version TEXT");
    await ensureColumn("consent_policies", "updated_at DATETIME");

    // ---- Scenes ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS scenes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        shoot_date TEXT,
        video_ref TEXT,
        booking_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await ensureColumn("scenes", "booking_id INTEGER");
    await ensureColumn("scenes", "code TEXT");
    await ensureColumn("scenes", "status TEXT");
    await ensureColumn("scenes", "storage_note TEXT");

    await dbRun(`
      CREATE TABLE IF NOT EXISTS scene_models (
        scene_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        PRIMARY KEY (scene_id, user_id),
        FOREIGN KEY(scene_id) REFERENCES scenes(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    // ---- Bookings ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS booking_profiles (
        user_id INTEGER PRIMARY KEY,
        legal_name TEXT,
        aliases TEXT,
        preferred_name TEXT,
        date_of_birth TEXT,
        country TEXT,
        state TEXT,
        phone TEXT,
        email TEXT,
        emergency_name TEXT,
        emergency_phone TEXT,
        portfolio_url TEXT,
        bio TEXT,
        experience_level TEXT,
        synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        shoot_date TEXT,
        location TEXT,
        status TEXT NOT NULL DEFAULT 'draft',
        compensation TEXT,
        notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS booking_models (
        booking_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role_label TEXT,
        PRIMARY KEY (booking_id, user_id),
        FOREIGN KEY(booking_id) REFERENCES bookings(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
      )
    `);

    // ---- Audit + Packages ----
    await dbRun(`
      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER,
        actor_username TEXT,
        actor_role TEXT,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        details_json TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await dbRun(`
      CREATE TABLE IF NOT EXISTS booking_packages (
        booking_id INTEGER PRIMARY KEY,
        package_filename TEXT,
        package_hash TEXT,
        generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        generated_by_user_id INTEGER,
        details_json TEXT,
        FOREIGN KEY(booking_id) REFERENCES bookings(id)
      )
    `);

    // ---- Model Applications + Invites ----
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
        status TEXT DEFAULT 'pending',
        headshot_filename TEXT,
        photos_json TEXT
      )
    `);

    await ensureColumn("model_applications", "onboarded_user_id INTEGER");
    await ensureColumn("model_applications", "onboarded_at TEXT");

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

    console.log("DB: Schema ready / migrations complete. (canonical db.js)");
    console.log(`DB: Using sqlite file at: ${dbPath}`);
  })();

  return _initPromise;
}

module.exports = {
  db,
  dbRun,
  dbGet,
  dbAll,
  ensureColumn,
  initDb,
};
