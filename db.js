const sqlite3 = require("sqlite3").verbose();
const path = require("path");

// Create / open database.sqlite in this folder
const db = new sqlite3.Database(path.join(__dirname, "database.sqlite"));

// ----------------------
// Promisified helpers
// ----------------------
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function (err, row) {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, function (err, rows) {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

// Add column if it doesn't exist (safe migration)
async function ensureColumn(tableName, columnDef) {
  const [columnName] = columnDef.split(/\s+/);
  const cols = await dbAll(`PRAGMA table_info(${tableName});`);
  const exists = cols.some((c) => c.name === columnName);
  if (!exists) {
    console.log(`DB MIGRATION: Adding column ${columnName} to ${tableName}`);
    await dbRun(`ALTER TABLE ${tableName} ADD COLUMN ${columnDef};`);
  }
}

// ----------------------
// Schema bootstrap + migrations
// ----------------------
db.serialize(() => {
  (async () => {
    try {
      // ---- Existing feature table (keep) ----
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
      // IMPORTANT: We do NOT use CHECK constraints here because older DBs may conflict.
      // We rely on app logic for role/status values.
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

      // Migrate older users tables (yours had role CHECK + email NOT NULL)
      await ensureColumn("users", "status TEXT NOT NULL DEFAULT 'pending'");
      await ensureColumn("users", "email_verified INTEGER DEFAULT 0");
      await ensureColumn("users", "verification_token TEXT");
      await ensureColumn("users", "is_paid_member INTEGER DEFAULT 0");
      // Some older DBs might not have email column (or it differs). Ensure it's present.
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

      // Migrate legacy model_profiles (in case it exists but missing columns)
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

      // Migrate legacy model_photos (this fixes your "no such column: priority")
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
          FOREIGN KEY(user_id) REFERENCES users(id)
        )
      `);

      // Migrate legacy master_releases (this fixes your "no column named ip_address")
      await ensureColumn("master_releases", "signed_at DATETIME DEFAULT CURRENT_TIMESTAMP");
      await ensureColumn("master_releases", "ip_address TEXT");
      await ensureColumn("master_releases", "user_agent TEXT");

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
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY(user_id) REFERENCES users(id)
        )
      `);

      await ensureColumn("consent_policies", "created_at DATETIME DEFAULT CURRENT_TIMESTAMP");

      // ---- Scenes ----
      await dbRun(`
        CREATE TABLE IF NOT EXISTS scenes (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          title TEXT NOT NULL,
          description TEXT,
          shoot_date TEXT,
          video_ref TEXT,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);

      await dbRun(`
        CREATE TABLE IF NOT EXISTS scene_models (
          scene_id INTEGER NOT NULL,
          user_id INTEGER NOT NULL,
          PRIMARY KEY (scene_id, user_id),
          FOREIGN KEY(scene_id) REFERENCES scenes(id),
          FOREIGN KEY(user_id) REFERENCES users(id)
        )
      `);

      console.log("DB: Schema ready / migrations complete.");
    } catch (err) {
      console.error("DB: Schema/migration error:", err);
    }
  })();
});

// VERY IMPORTANT: export the db object itself
module.exports = db;
