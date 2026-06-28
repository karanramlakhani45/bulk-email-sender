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
      open_ip TEXT,
      open_classification_reason TEXT
    )
  `);

  // migrations for existing databases
  db.run("ALTER TABLE emails ADD COLUMN is_bot_open INTEGER DEFAULT 0", () => {});
  db.run("ALTER TABLE emails ADD COLUMN open_user_agent TEXT", () => {});
  db.run("ALTER TABLE emails ADD COLUMN open_ip TEXT", () => {});
  db.run("ALTER TABLE emails ADD COLUMN open_classification_reason TEXT", () => {});
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
  
  markOpened(id, isBotOpen = 0, ip = null, userAgent = null, classificationReason = null) {
    return new Promise(async (resolve, reject) => {
      try {
        const email = await this.getEmailById(id);
        if (!email) {
          return resolve(0);
        }

        const now = Date.now();
        const statusVal = isBotOpen ? "Opened (Bot)" : "Opened (Human)";
        
        // Check if the update would be applied based on the WHERE conditions
        const wouldUpdate = !email.opened_at || 
                            (email.is_bot_open === 1 && (isBotOpen === 0 || isBotOpen === 2)) ||
                            (email.is_bot_open === 2 && isBotOpen === 0);

        console.log(`[DEBUG DB] Before Update for email: ${id}`, {
          opened_at: email.opened_at,
          status: email.status,
          is_bot_open: email.is_bot_open,
          open_ip: email.open_ip,
          open_user_agent: email.open_user_agent,
          open_classification_reason: email.open_classification_reason
        });

        if (wouldUpdate) {
          console.log("[STATUS UPDATE]", {
              emailId: id,
              oldStatus: email.status,
              newStatus: statusVal,
              userAgent: userAgent,
              ip: ip,
              sentAt: email.sent_at,
              openedAt: now,
              classification: isBotOpen ? "Opened (Bot)" : "Opened (Human)",
              sourceFile: "db.js",
              stack: new Error().stack
          });

          db.run(
            `UPDATE emails 
             SET opened_at = ?, status = ?, is_bot_open = ?, open_ip = ?, open_user_agent = ?, open_classification_reason = ?
             WHERE id = ? AND (
               opened_at IS NULL OR 
               (is_bot_open = 1 AND ? IN (0, 2)) OR 
               (is_bot_open = 2 AND ? = 0)
             )`,
            [now, statusVal, isBotOpen, ip, userAgent, classificationReason, id, isBotOpen, isBotOpen],
            function (err) {
              if (err) {
                reject(err);
              } else {
                const changes = this.changes;
                db.get("SELECT * FROM emails WHERE id = ?", [id], (err, row) => {
                  if (row) {
                    console.log(`[DEBUG DB] After Update for email: ${id}`, {
                      opened_at: row.opened_at,
                      status: row.status,
                      is_bot_open: row.is_bot_open,
                      open_ip: row.open_ip,
                      open_user_agent: row.open_user_agent,
                      open_classification_reason: row.open_classification_reason,
                      changes: changes
                    });
                  }
                  resolve(changes);
                });
              }
            }
          );
        } else {
          console.log(`[DEBUG DB] No update needed for email: ${id}. wouldUpdate was false.`);
          resolve(0);
        }
      } catch (err) {
        reject(err);
      }
    });
  },

  markEmailOpened(id, isBotOpen = 0, ip = null, userAgent = null, classificationReason = null) {
    return this.markOpened(id, isBotOpen, ip, userAgent, classificationReason);
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

  getEmails(search = "", filterStatus = "", page = null, limit = null) {
    return new Promise((resolve, reject) => {
      let baseQuery = "FROM emails WHERE 1=1";
      const params = [];
      
      if (search) {
        baseQuery += " AND (recipient_email LIKE ? OR subject LIKE ?)";
        params.push(`%${search}%`, `%${search}%`);
      }
      
      if (filterStatus) {
        if (filterStatus === "Opened") {
          baseQuery += " AND opened_at IS NOT NULL AND (is_bot_open = 0 OR is_bot_open IS NULL)";
        } else if (filterStatus === "Clicked") {
          baseQuery += " AND clicked_at IS NOT NULL";
        } else if (filterStatus === "Sent") {
          baseQuery += " AND (status = 'Sent' OR (opened_at IS NOT NULL AND is_bot_open IN (1, 2) AND clicked_at IS NULL))";
        } else {
          baseQuery += " AND status = ?";
          params.push(filterStatus);
        }
      }

      // 1. Get total records count for these query parameters
      const countQuery = `SELECT COUNT(*) as count ${baseQuery}`;
      db.get(countQuery, params, (err, countRow) => {
        if (err) return reject(err);
        
        const total = countRow ? countRow.count : 0;
        
        // 2. Query paginated records
        let selectQuery = `SELECT * ${baseQuery} ORDER BY sent_at DESC`;
        const selectParams = [...params];
        
        if (page !== null && limit !== null) {
          selectQuery += " LIMIT ? OFFSET ?";
          const offset = (page - 1) * limit;
          selectParams.push(limit, offset);
        }
        
        db.all(selectQuery, selectParams, (err, rows) => {
          if (err) reject(err);
          else resolve({ history: rows, total });
        });
      });
    });
  },

  getHistory(search = "", filterStatus = "", page = null, limit = null) {
    return this.getEmails(search, filterStatus, page, limit);
  },

  getStats() {
    return new Promise((resolve, reject) => {
      db.get(
        `SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN status != 'Failed' THEN 1 ELSE 0 END) as sent,
          SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END) as failed,
          SUM(CASE WHEN (opened_at IS NOT NULL AND (is_bot_open = 0 OR is_bot_open IS NULL)) OR clicked_at IS NOT NULL THEN 1 ELSE 0 END) as opened,
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
