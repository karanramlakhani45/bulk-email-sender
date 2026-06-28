const sqlite3 = require("sqlite3").verbose();
const path = require("path");

// Simulates classifyRequest
function classifyRequest(userAgent, ip, elapsedSeconds, hasPrefetched = false) {
  const uaLower = (userAgent || "").toLowerCase();
  
  // Clean IPv6 prefix
  const cleanIp = (ip || "").replace(/^::ffff:/, "");
  
  const isGoogleIP = cleanIp.startsWith("66.249.") || cleanIp.startsWith("209.85.");
  const isGoogleProxyUA = uaLower.includes("googleimageproxy") || uaLower.includes("via ggpht.com");
  
  const isYahooProxy = uaLower.includes("yahoomailproxy");
  
  const isMicrosoftProxy = uaLower.includes("microsoft office") || 
                           uaLower.includes("microsoft exchange") || 
                           uaLower.includes("outlook-express") || 
                           uaLower.includes("officeactualimageproxy");

  const isProxySign = isGoogleProxyUA || isGoogleIP || isYahooProxy || isMicrosoftProxy;

  // Bot signatures
  const isGoogleScanner = uaLower.includes("google-publisher-anonymizer") || 
                          uaLower.includes("google-apps-script") || 
                          uaLower.includes("googlebot");
  const isOutlookSafeLinks = uaLower.includes("safelinks");
  const isDefender = uaLower.includes("msip") || uaLower.includes("microsoft defender") || uaLower.includes("defender");
  const isBarracuda = uaLower.includes("barracuda");
  const isMimecast = uaLower.includes("mimecast");
  const isProofpoint = uaLower.includes("proofpoint");
  const isGenericScanner = uaLower.includes("crawler") || uaLower.includes("spider") || uaLower.includes("bot") || uaLower.includes("scanner");

  const isBotSignature = isProxySign || isGoogleScanner || isOutlookSafeLinks || isDefender || isBarracuda || isMimecast || isProofpoint || isGenericScanner;

  // Real browser check
  const isBrowser = uaLower.includes("mozilla") || 
                    uaLower.includes("chrome") || 
                    uaLower.includes("safari") || 
                    uaLower.includes("firefox") || 
                    uaLower.includes("applewebkit") || 
                    uaLower.includes("opera") || 
                    uaLower.includes("edge");

  let isBotOpen = 1;
  let reason = "";
  let matchedRule = "";

  if (elapsedSeconds <= 60) {
    reason = `Request received within strict 60-second anti-prefetch window (${elapsedSeconds.toFixed(2)}s)`;
    if (isGoogleProxyUA || isGoogleIP) {
      isBotOpen = 2; // Gmail Proxy
      reason = `Gmail Image Proxy prefetch within 60-second window (${elapsedSeconds.toFixed(2)}s)`;
      matchedRule = "Anti-prefetch window & Google Image Proxy";
    } else if (isYahooProxy) {
      isBotOpen = 1;
      reason = `Yahoo Image Proxy prefetch within 60-second window (${elapsedSeconds.toFixed(2)}s)`;
      matchedRule = "Anti-prefetch window & Yahoo Proxy";
    } else if (isMicrosoftProxy) {
      isBotOpen = 1;
      reason = `Microsoft Image Proxy prefetch within 60-second window (${elapsedSeconds.toFixed(2)}s)`;
      matchedRule = "Anti-prefetch window & Microsoft Proxy";
    } else if (isGoogleScanner) {
      matchedRule = "Anti-prefetch window & Google Scanner";
      reason = "Google Security Scanner scan within 60s";
    } else if (isOutlookSafeLinks) {
      matchedRule = "Anti-prefetch window & Outlook SafeLinks";
      reason = "Outlook SafeLinks prefetch within 60s";
    } else if (isDefender) {
      matchedRule = "Anti-prefetch window & Microsoft Defender";
      reason = "Microsoft Defender scan within 60s";
    } else if (isBarracuda) {
      matchedRule = "Anti-prefetch window & Barracuda";
      reason = "Barracuda scan within 60s";
    } else if (isMimecast) {
      matchedRule = "Anti-prefetch window & Mimecast";
      reason = "Mimecast scan within 60s";
    } else if (isProofpoint) {
      matchedRule = "Anti-prefetch window & Proofpoint";
      reason = "Proofpoint scan within 60s";
    } else if (isGenericScanner) {
      matchedRule = "Anti-prefetch window & Generic Scanner";
      reason = "Generic crawler/bot scan within 60s";
    } else {
      matchedRule = "Anti-prefetch window (Generic)";
    }
  } else {
    if (isGoogleProxyUA || isGoogleIP) {
      if (hasPrefetched || elapsedSeconds > 300) {
        isBotOpen = 0;
        reason = `Gmail Image Proxy open (human verified via ${hasPrefetched ? 'subsequent view' : 'delay: ' + elapsedSeconds.toFixed(0) + 's'})`;
        matchedRule = "Google Image Proxy human open";
      } else {
        isBotOpen = 2;
        reason = `Gmail Image Proxy suspicious/prefetch open (${elapsedSeconds.toFixed(2)}s)`;
        matchedRule = "Google Image Proxy suspected scanner/late prefetch";
      }
    } else if (isYahooProxy || isMicrosoftProxy) {
      const type = isYahooProxy ? "Yahoo" : "Microsoft";
      if (hasPrefetched || elapsedSeconds > 300) {
        isBotOpen = 0;
        reason = `${type} Image Proxy open (human verified via ${hasPrefetched ? 'subsequent view' : 'delay: ' + elapsedSeconds.toFixed(0) + 's'})`;
        matchedRule = `${type} Image Proxy human open`;
      } else {
        isBotOpen = 1;
        reason = `${type} Image Proxy suspicious/prefetch open (${elapsedSeconds.toFixed(2)}s)`;
        matchedRule = `${type} Image Proxy suspected scanner/late prefetch`;
      }
    } else if (isGoogleScanner) {
      isBotOpen = 1;
      reason = "Google Security Scanner signature matched";
      matchedRule = "Google Security Scanner outside prefetch window";
    } else if (isOutlookSafeLinks) {
      isBotOpen = 1;
      reason = "Outlook SafeLinks signature matched";
      matchedRule = "Outlook SafeLinks outside prefetch window";
    } else if (isDefender) {
      isBotOpen = 1;
      reason = "Microsoft Defender signature matched";
      matchedRule = "Microsoft Defender outside prefetch window";
    } else if (isBarracuda) {
      isBotOpen = 1;
      reason = "Barracuda signature matched";
      matchedRule = "Barracuda outside prefetch window";
    } else if (isMimecast) {
      isBotOpen = 1;
      reason = "Mimecast signature matched";
      matchedRule = "Mimecast outside prefetch window";
    } else if (isProofpoint) {
      isBotOpen = 1;
      reason = "Proofpoint signature matched";
      matchedRule = "Proofpoint outside prefetch window";
    } else if (isGenericScanner) {
      isBotOpen = 1;
      reason = "Generic crawler/bot/scanner signature matched";
      matchedRule = "Generic crawler/bot/scanner outside prefetch window";
    } else if (isBrowser) {
      isBotOpen = 0;
      reason = "Legitimate open from client browser outside prefetch window";
      matchedRule = "Real Browser UA outside prefetch window";
    } else {
      isBotOpen = 1;
      reason = `Non-browser User-Agent detected: "${userAgent}"`;
      matchedRule = "Non-browser UA outside prefetch window";
    }
  }

  return { isBotOpen, reason };
}

function mapRow(row) {
  const isBotOpen = row.is_bot_open === 1 || row.is_bot_open === 2;
  
  let userStatus = "Sent";
  if (row.status === "Failed") {
    userStatus = "Failed";
  } else if (row.clicked_at) {
    userStatus = "Clicked";
  } else if (row.opened_at && !isBotOpen) {
    userStatus = "Opened (Human)";
  }

  return {
    id: row.id,
    recipient_email: row.recipient_email,
    subject: row.subject,
    status: userStatus,
    sent_at: row.sent_at,
    opened_at: (row.opened_at && !isBotOpen) ? row.opened_at : null,
    clicked_at: row.clicked_at,
    error_message: row.error_message
  };
}

async function simulate() {
  const dbPath = path.join(__dirname, "emails.db");
  const sqliteDb = new sqlite3.Database(dbPath);
  
  const runQuery = (sql, params) => new Promise((res, rej) => sqliteDb.run(sql, params, (e) => e ? rej(e) : res()));
  const getQuery = (sql, params) => new Promise((res, rej) => sqliteDb.get(sql, params, (e, r) => e ? rej(e) : res(r)));

  const emailId = "test-investigation-1";
  await runQuery("DELETE FROM emails WHERE id = ?", [emailId]);

  console.log("\n=== 1. EMAIL INITIAL SEND STATE ===");
  const sentAt = Date.now();
  await runQuery(
    "INSERT INTO emails (id, recipient_email, subject, status, sent_at) VALUES (?, ?, ?, ?, ?)",
    [emailId, "recipient@test.com", "Test Subject", "Sent", sentAt]
  );
  
  let row = await getQuery("SELECT * FROM emails WHERE id = ?", [emailId]);
  console.log("Raw SQLite Row immediately after send:", row);
  console.log("Mapped /api/history response immediately after send:", mapRow(row));

  console.log("\n=== 2. AFTER A BOT REQUEST (Gmail Proxy prefetch at 5 seconds) ===");
  const botUa = "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0 (via ggpht.com GoogleImageProxy)";
  const botIp = "66.249.92.14";
  const botDelay = 5;
  const botResult = classifyRequest(botUa, botIp, botDelay, false);
  console.log("Classifier classification for bot request:", botResult);

  const botTime = sentAt + (botDelay * 1000);
  const botStatusVal = botResult.isBotOpen ? "Opened (Bot)" : "Opened (Human)";
  
  // Use the exact SQL logic from db.js markOpened:
  await runQuery(
    `UPDATE emails 
     SET opened_at = ?, status = ?, is_bot_open = ?, open_ip = ?, open_user_agent = ?, open_classification_reason = ?
     WHERE id = ? AND (
       opened_at IS NULL OR 
       (is_bot_open = 1 AND ? IN (0, 2)) OR 
       (is_bot_open = 2 AND ? = 0)
     )`,
    [botTime, botStatusVal, botResult.isBotOpen, botIp, botUa, botResult.reason, emailId, botResult.isBotOpen, botResult.isBotOpen]
  );

  row = await getQuery("SELECT * FROM emails WHERE id = ?", [emailId]);
  console.log("Raw SQLite Row after bot request:", row);
  console.log("Mapped /api/history response after bot request:", mapRow(row));

  console.log("\n=== 3. AFTER A REAL HUMAN OPEN (Real Browser load at 120 seconds) ===");
  const humanUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
  const humanIp = "182.64.95.12";
  const humanDelay = 120;
  const humanResult = classifyRequest(humanUa, humanIp, humanDelay, row.opened_at !== null);
  console.log("Classifier classification for human request:", humanResult);

  const humanTime = sentAt + (humanDelay * 1000);
  const humanStatusVal = humanResult.isBotOpen ? "Opened (Bot)" : "Opened (Human)";

  // Check wouldUpdate logic:
  const wouldUpdate = !row.opened_at || 
                      (row.is_bot_open === 1 && (humanResult.isBotOpen === 0 || humanResult.isBotOpen === 2)) ||
                      (row.is_bot_open === 2 && humanResult.isBotOpen === 0);
  console.log(`wouldUpdate check in db.js: ${wouldUpdate}`);

  if (wouldUpdate) {
    await runQuery(
      `UPDATE emails 
       SET opened_at = ?, status = ?, is_bot_open = ?, open_ip = ?, open_user_agent = ?, open_classification_reason = ?
       WHERE id = ? AND (
         opened_at IS NULL OR 
         (is_bot_open = 1 AND ? IN (0, 2)) OR 
         (is_bot_open = 2 AND ? = 0)
       )`,
      [humanTime, humanStatusVal, humanResult.isBotOpen, humanIp, humanUa, humanResult.reason, emailId, humanResult.isBotOpen, humanResult.isBotOpen]
    );
  }

  row = await getQuery("SELECT * FROM emails WHERE id = ?", [emailId]);
  console.log("Raw SQLite Row after real human open:", row);
  console.log("Mapped /api/history response after real human open:", mapRow(row));

  console.log("\n=== 4. AFTER A SUBSEQUENT GMAIL PROXY REQUEST (delayed open at 180 seconds) ===");
  // Reset row to state after bot request (Gmail prefetch)
  await runQuery("DELETE FROM emails WHERE id = ?", [emailId]);
  await runQuery(
    "INSERT INTO emails (id, recipient_email, subject, status, sent_at) VALUES (?, ?, ?, ?, ?)",
    [emailId, "recipient@test.com", "Test Subject", "Sent", sentAt]
  );
  // Re-apply prefetch
  await runQuery(
    `UPDATE emails 
     SET opened_at = ?, status = ?, is_bot_open = ?, open_ip = ?, open_user_agent = ?, open_classification_reason = ?
     WHERE id = ?`,
    [sentAt + 5000, "Opened (Bot)", 2, botIp, botUa, "Gmail Image Proxy prefetch", emailId]
  );

  row = await getQuery("SELECT * FROM emails WHERE id = ?", [emailId]);
  console.log("Raw SQLite Row after prefetch:", row);

  // Now run delayed proxy request
  const proxyOpenUa = "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko Firefox/11.0 (via ggpht.com GoogleImageProxy)";
  const proxyOpenIp = "66.249.92.15";
  const proxyOpenDelay = 180;
  const proxyOpenResult = classifyRequest(proxyOpenUa, proxyOpenIp, proxyOpenDelay, row.opened_at !== null);
  console.log("Classifier classification for delayed proxy request:", proxyOpenResult);

  const proxyOpenTime = sentAt + (proxyOpenDelay * 1000);
  const proxyOpenStatusVal = proxyOpenResult.isBotOpen ? "Opened (Bot)" : "Opened (Human)";

  const wouldUpdateProxy = !row.opened_at || 
                           (row.is_bot_open === 1 && (proxyOpenResult.isBotOpen === 0 || proxyOpenResult.isBotOpen === 2)) ||
                           (row.is_bot_open === 2 && proxyOpenResult.isBotOpen === 0);
  console.log(`wouldUpdate check in db.js for proxy open: ${wouldUpdateProxy}`);

  if (wouldUpdateProxy) {
    await runQuery(
      `UPDATE emails 
       SET opened_at = ?, status = ?, is_bot_open = ?, open_ip = ?, open_user_agent = ?, open_classification_reason = ?
       WHERE id = ? AND (
         opened_at IS NULL OR 
         (is_bot_open = 1 AND ? IN (0, 2)) OR 
         (is_bot_open = 2 AND ? = 0)
       )`,
      [proxyOpenTime, proxyOpenStatusVal, proxyOpenResult.isBotOpen, proxyOpenIp, proxyOpenUa, proxyOpenResult.reason, emailId, proxyOpenResult.isBotOpen, proxyOpenResult.isBotOpen]
    );
  }

  row = await getQuery("SELECT * FROM emails WHERE id = ?", [emailId]);
  console.log("Raw SQLite Row after delayed proxy open:", row);
  console.log("Mapped /api/history response after delayed proxy open:", mapRow(row));

  // Clean up
  await runQuery("DELETE FROM emails WHERE id = ?", [emailId]);
  sqliteDb.close();
}

simulate().catch(console.error);
