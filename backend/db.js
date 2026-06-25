const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.join(__dirname, "emails.db");
const db = new sqlite3.Database(dbPath);

// Initialize DB schema
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS emails (
      id TEXT PRIMARY KEY,
      recipient_email TEXT NOT NULL,
      subject TEXT NOT NULL,
      status TEXT NOT NULL,
      sent_at INTEGER NOT NULL,
      opened_at INTEGER,
      clicked_at INTEGER,
      error_message TEXT,
      is_bot_open INTEGER DEFAULT 0,
      open_user_agent TEXT,
      open_ip TEXT
    )
  `);

  // migrations for existing databases
  db.run("ALTER TABLE emails ADD COLUMN is_bot_open INTEGER DEFAULT 0", () => {});
  db.run("ALTER TABLE emails ADD COLUMN open_user_agent TEXT", () => {});
  db.run("ALTER TABLE emails ADD COLUMN open_ip TEXT", () => {});
});

module.exports = {
  db,
  
  saveEmail(emailRecord) {
    return new Promise((resolve, reject) => {
      const { id, recipient_email, subject, status, sent_at, error_message } = emailRecord;
      db.run(
        `INSERT INTO emails (id, recipient_email, subject, status, sent_at, error_message)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [id, recipient_email, subject, status, sent_at, error_message],
        function (err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });
  },
  
  getEmailById(id) {
    return new Promise((resolve, reject) => {
      db.get("SELECT * FROM emails WHERE id = ?", [id], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  },
  
  markOpened(id, isBotOpen = 0, ip = null, userAgent = null) {
    return new Promise((resolve, reject) => {
      const now = Date.now();
      db.run(
        `UPDATE emails 
         SET opened_at = ?, is_bot_open = ?, open_ip = ?, open_user_agent = ?
         WHERE id = ? AND (opened_at IS NULL OR (is_bot_open = 1 AND ? = 0))`,
        [now, isBotOpen, ip, userAgent, id, isBotOpen],
        function (err) {
          if (err) reject(err);
          else resolve(this.changes);
        }
      );
    });
  },

  markEmailOpened(id, isBotOpen = 0, ip = null, userAgent = null) {
    return this.markOpened(id, isBotOpen, ip, userAgent);
  },

  markClicked(id) {
    return new Promise((resolve, reject) => {
      const now = Date.now();
      db.run(
        `UPDATE emails SET clicked_at = ? WHERE id = ? AND clicked_at IS NULL`,
        [now, id],
        function (err) {
          if (err) reject(err);
          else resolve(this.changes);
        }
      );
    });
  },

  markEmailClicked(id) {
    return this.markClicked(id);
  },

  getEmails(search = "", filterStatus = "") {
    return new Promise((resolve, reject) => {
      let query = "SELECT * FROM emails WHERE 1=1";
      const params = [];
      
      if (search) {
        query += " AND (recipient_email LIKE ? OR subject LIKE ?)";
        params.push(`%${search}%`, `%${search}%`);
      }
      
      if (filterStatus) {
        if (filterStatus === "Opened") {
          query += " AND opened_at IS NOT NULL AND (is_bot_open = 0 OR is_bot_open IS NULL)";
        } else if (filterStatus === "OpenedBot") {
          query += " AND opened_at IS NOT NULL AND is_bot_open = 1";
        } else if (filterStatus === "Clicked") {
          query += " AND clicked_at IS NOT NULL";
        } else {
          query += " AND status = ?";
          params.push(filterStatus);
        }
      }
      
      query += " ORDER BY sent_at DESC";
      
      db.all(query, params, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });
  },

  getHistory(search = "", filterStatus = "") {
    return this.getEmails(search, filterStatus);
  },

  getStats() {
    return new Promise((resolve, reject) => {
      db.get(
        `SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN status = 'Sent' THEN 1 ELSE 0 END) as sent,
          SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) as failed,
          SUM(CASE WHEN opened_at IS NOT NULL AND (is_bot_open = 0 OR is_bot_open IS NULL) THEN 1 ELSE 0 END) as opened,
          SUM(CASE WHEN clicked_at IS NOT NULL THEN 1 ELSE 0 END) as clicked
         FROM emails`,
        (err, row) => {
          if (err) reject(err);
          else {
            // Fill null fields with 0
            const stats = {
              total: row.total || 0,
              sent: row.sent || 0,
              failed: row.failed || 0,
              opened: row.opened || 0,
              clicked: row.clicked || 0
            };
            resolve(stats);
          }
        }
      );
    });
  }
};
