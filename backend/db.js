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
      error_message TEXT
    )
  `);
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
  
  markOpened(id) {
    return new Promise((resolve, reject) => {
      const now = Date.now();
      db.run(
        `UPDATE emails SET opened_at = ? WHERE id = ? AND opened_at IS NULL`,
        [now, id],
        function (err) {
          if (err) reject(err);
          else resolve(this.changes);
        }
      );
    });
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
          query += " AND opened_at IS NOT NULL";
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

  getStats() {
    return new Promise((resolve, reject) => {
      db.get(
        `SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN status = 'Sent' THEN 1 ELSE 0 END) as sent,
          SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) as failed,
          SUM(CASE WHEN opened_at IS NOT NULL THEN 1 ELSE 0 END) as opened,
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
