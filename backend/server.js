const express = require("express");
const nodemailer = require("nodemailer");
const MailComposer = require("nodemailer/lib/mail-composer");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const crypto = require("crypto");
const path = require("path");
const db = require("./db");
require("dotenv").config();

const app = express();

app.set("trust proxy", 1);

// Custom Request Logging Middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on("finish", () => {
    const duration = Date.now() - start;
    console.log(`[API Log] ${req.method} ${req.originalUrl} - Status: ${res.statusCode} - Time: ${duration}ms`);
  });
  next();
});

// Token Encryption/Decryption System using crypto
const SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET || "fallback-secret-for-jwt-signing-and-encrypting-12345678";
const ENCRYPTION_KEY = crypto.createHash("sha256").update(SECRET).digest();
const IV_LENGTH = 16;

function encryptToken(payload) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(JSON.stringify(payload), "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function decryptToken(token) {
  try {
    const parts = token.split(":");
    if (parts.length !== 2) return null;
    const iv = Buffer.from(parts[0], "hex");
    const encryptedText = Buffer.from(parts[1], "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return JSON.parse(decrypted);
  } catch (err) {
    return null;
  }
}

function generateToken(user) {
  const payload = {
    user: {
      id: user.id,
      displayName: user.displayName,
      emails: user.emails,
      photos: user.photos,
      accessToken: user.accessToken
    },
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days validity
  };
  return encryptToken(payload);
}

// Check Authorization headers or fall back to cookies
function getUserFromRequest(req) {
  if (req.user) {
    return req.user;
  }
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    const decrypted = decryptToken(token);
    if (decrypted && decrypted.expiresAt > Date.now()) {
      return decrypted.user;
    }
  }
  return null;
}

function getBackendOrigin(req) {
  if (process.env.PUBLIC_APP_URL) {
    return process.env.PUBLIC_APP_URL;
  }
  
  const isProd = process.env.NODE_ENV === "production";
  
  if (isProd) {
    // 1. Try request host first (force HTTPS in production)
    if (req) {
      const host = req.get("host");
      if (!host.includes("localhost") && !host.includes("127.0.0.1")) {
        return `https://${host}`;
      }
    }

    // 2. Try CALLBACK_URL fallback
    if (process.env.CALLBACK_URL) {
      try {
        const origin = new URL(process.env.CALLBACK_URL).origin;
        if (!origin.includes("localhost") && !origin.includes("127.0.0.1")) {
          return origin.replace(/^http:/, "https:");
        }
      } catch (e) {}
    }
  } else {
    // In development/local env
    if (req) {
      return `${req.protocol}://${req.get("host")}`;
    }
    
    if (process.env.CALLBACK_URL) {
      try {
        return new URL(process.env.CALLBACK_URL).origin;
      } catch (e) {}
    }
  }
  
  return "http://localhost:5000";
}

function rewriteLinks(html, emailId, backendUrl) {
  if (!html) return "";
  return html.replace(/href="([^"]*)"/gi, (match, url) => {
    if (url.startsWith("http://") || url.startsWith("https://")) {
      return `href="${backendUrl}/track/click/${emailId}?url=${encodeURIComponent(url)}"`;
    }
    return match;
  });
}

const allowedOrigins = [
  "https://bulk-email-sender-ashy.vercel.app",
  "http://localhost:5000",
  "http://localhost:3000",
  "http://127.0.0.1:5500",
  "http://127.0.0.1:5000",
  "http://localhost:8080"
];

if (process.env.FRONTEND_URL) {
  allowedOrigins.push(process.env.FRONTEND_URL);
}

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    const isLocalhost = origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:");
    const isVercel = origin.endsWith(".vercel.app");
    if (allowedOrigins.indexOf(origin) !== -1 || isLocalhost || isVercel) {
      callback(null, true);
    } else {
      console.warn(`[CORS Blocked] Origin: ${origin}`);
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, "../frontend")));

const isProd = process.env.NODE_ENV === "production";
app.use(session({
  secret: process.env.SESSION_SECRET || "fallback-session-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProd,
    sameSite: isProd ? "none" : "lax"
  }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

console.log("CLIENT_ID:", process.env.CLIENT_ID);
console.log("CALLBACK_URL:", process.env.CALLBACK_URL);
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL || "/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      profile.accessToken = accessToken;
      return done(null, profile);
    }
  )
);

app.get(
  "/auth/google",
  (req, res, next) => {
    const redirectUri = req.query.redirect_uri || "https://bulk-email-sender-ashy.vercel.app/dashboard.html";
    const state = Buffer.from(JSON.stringify({ redirectUri })).toString("base64");
    
    passport.authenticate("google", {
      scope: [
        "profile",
        "email",
        "https://www.googleapis.com/auth/gmail.send"
      ],
      prompt: "select_account",
      state: state
    })(req, res, next);
  }
);

app.get(
  "/auth/google/callback",
  (req, res, next) => {
    let failureRedirect = "https://bulk-email-sender-ashy.vercel.app/index.html";
    if (req.query.state) {
      try {
        const decodedState = JSON.parse(Buffer.from(req.query.state, "base64").toString("utf-8"));
        if (decodedState.redirectUri) {
          const parsed = new URL(decodedState.redirectUri);
          failureRedirect = `${parsed.origin}/index.html?error=auth_failed`;
        }
      } catch (e) {}
    }
    passport.authenticate("google", {
      failureRedirect: failureRedirect
    })(req, res, next);
  },
  (req, res) => {
    let redirectUri = "https://bulk-email-sender-ashy.vercel.app/dashboard.html";
    if (req.query.state) {
      try {
        const decodedState = JSON.parse(Buffer.from(req.query.state, "base64").toString("utf-8"));
        if (decodedState.redirectUri) {
          redirectUri = decodedState.redirectUri;
        }
      } catch (err) {
        console.error("Failed to parse state parameter", err);
      }
    }
    
    if (!req.user) {
      const parsed = new URL(redirectUri);
      return res.redirect(`${parsed.origin}/index.html?error=no_user`);
    }

    const token = generateToken(req.user);
    res.redirect(`${redirectUri}?token=${token}`);
  }
);

app.get("/user", (req, res) => {
  const user = getUserFromRequest(req);
  res.json({
    loggedIn: !!user,
    user: user || null
  });
});

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) { return next(err); }
    req.session.destroy(() => {
      res.clearCookie("connect.sid", {
        secure: true,
        sameSite: "none"
      });
      res.json({ success: true });
    });
  });
});

// Classification helper function
// Classification helper function
function classifyRequest(userAgent, ip, elapsedSeconds) {
  const uaLower = (userAgent || "").toLowerCase();
  const isGoogleIP = (ip || "").startsWith("66.249.") || (ip || "").startsWith("209.85.");
  const isGoogleProxyUA = uaLower.includes("googleimageproxy");

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

  const isBotSignature = isGoogleProxyUA || isGoogleIP || isGoogleScanner || isOutlookSafeLinks || isDefender || isBarracuda || isMimecast || isProofpoint || isGenericScanner;

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

  // 1. Strict timing check (Never classify as Human if within 60 seconds of delivery)
  if (elapsedSeconds <= 60) {
    reason = `Request received within strict 60-second anti-prefetch window (${elapsedSeconds.toFixed(2)}s)`;
    if (isGoogleProxyUA || isGoogleIP) {
      isBotOpen = 2; // Gmail Proxy
      reason = `Gmail Image Proxy prefetch within 60-second window (${elapsedSeconds.toFixed(2)}s)`;
      matchedRule = "Anti-prefetch window & Google Image Proxy";
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
    // 2. Delayed requests (> 60 seconds)
    if (isGoogleProxyUA || isGoogleIP) {
      isBotOpen = 2;
      reason = `Gmail Image Proxy/Infrastructure routing (${isGoogleIP ? 'IP: ' + ip : 'UA: ' + userAgent})`;
      matchedRule = "Google Image Proxy outside prefetch window";
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
    } else if (isBrowser && !isBotSignature) {
      isBotOpen = 0;
      reason = "Legitimate open from client browser outside prefetch window";
      matchedRule = "Real Browser UA outside prefetch window";
    } else {
      isBotOpen = 1;
      reason = `Non-browser User-Agent detected: "${userAgent}"`;
      matchedRule = "Non-browser UA outside prefetch window";
    }
  }

  const classification = isBotOpen === 2 ? "Gmail Proxy" : (isBotOpen === 1 ? "Bot" : "Human");

  console.log(`\n[CLASSIFIER DECISION]
Elapsed: ${elapsedSeconds.toFixed(2)}s
UA: ${userAgent}
IP: ${ip}
Matched rule: ${matchedRule}
Final classification: ${classification}\n`);

  return { isBotOpen, reason };
}

// Open tracking pixel endpoint
app.get("/track/open/:emailId", async (req, res) => {
  console.log("[TRACK OPEN]", req.originalUrl, req.headers["user-agent"]);
  const { emailId } = req.params;
  const ip = req.ip || req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const userAgent = req.headers["user-agent"] || "unknown";
  const referer = req.headers["referer"] || "none";
  const timestamp = new Date().toISOString();

  console.log(`[DEBUG TRACK] Open request received.
  - Email ID: ${emailId}
  - Request time: ${timestamp}
  - IP: ${ip}
  - User-Agent: ${userAgent}`);

  try {
    const email = await db.getEmailById(emailId);
    if (!email) {
      console.warn(`[Tracking Log] Email not found: ${emailId}`);
      console.log(`\n[TRACKING]
Email ID: ${emailId}
Sent Time: N/A
Open Time: ${timestamp}
Delay: N/A
User-Agent: ${userAgent}
IP: ${ip}
Classification: Email Not Found
Reason: Database record does not exist for this ID\n`);
    } else {
      console.log(`[Tracking Log] Email found: ${emailId}`);
      
      const elapsedSeconds = (Date.now() - email.sent_at) / 1000;
      const { isBotOpen, reason } = classifyRequest(userAgent, ip, elapsedSeconds);
      
      const classification = isBotOpen === 2 ? "Opened (Gmail Proxy)" : (isBotOpen === 1 ? "Opened (Bot)" : "Opened (Human)");

      console.log(`[DEBUG TRACK] Classifier Result:
      - Email ID: ${emailId}
      - elapsedSeconds: ${elapsedSeconds.toFixed(2)}s
      - isBotOpen: ${isBotOpen}
      - classification: ${classification}
      - reason: ${reason}`);

      // Record in DB (including classification reason)
      // This is the ONLY place that initiates open updates, which delegates database status modification to db.markEmailOpened
      const changes = await db.markEmailOpened(emailId, isBotOpen, ip, userAgent, reason);

      // Standard Audit Log Block
      console.log(`\n[TRACKING]
Email ID: ${emailId}
Sent Time: ${new Date(email.sent_at).toISOString()}
Open Time: ${timestamp}
Delay: ${elapsedSeconds.toFixed(2)}s
User-Agent: ${userAgent}
IP: ${ip}
Classification: ${classification}
Reason: ${reason}\n`);

      if (changes > 0) {
        console.log(`[Tracking Log] Open recorded successfully. Classification: ${classification}`);
      } else {
        console.log(`[Tracking Log] Open tracking request processed. No DB changes (already human-opened or ignored bot).`);
      }
    }
  } catch (err) {
    console.error(`[Tracking Log] Error handling open tracking for ${emailId}:`, err);
  }

  const pixel = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=",
    "base64"
  );
  res.writeHead(200, {
    "Content-Type": "image/png",
    "Content-Length": pixel.length,
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0"
  });
  res.end(pixel);
});

// Click tracking redirect endpoint
app.get("/track/click/:emailId", async (req, res) => {
  const { emailId } = req.params;
  const { url } = req.query;
  const ip = req.ip || req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const userAgent = req.headers["user-agent"] || "unknown";

  console.log(`[Tracking Log] Click tracking request received for email ID: ${emailId}, target: ${url}`);
  
  if (!url) {
    console.warn(`[Tracking Log] Click tracking request failed: Missing target URL`);
    return res.status(400).send("Missing target URL");
  }

  try {
    const changes = await db.markClicked(emailId);
    console.log(`[Tracking Log] Click marked. Changes: ${changes}`);
    
    const openChanges = await db.markEmailOpened(emailId, 0, ip, userAgent, "Click event verified human open");
    console.log(`[Tracking Log] Human open verification from click. Open Changes: ${openChanges}`);
  } catch (err) {
    console.error(`[Tracking Log] Error marking link clicked/opened for ${emailId}:`, err);
  }

  res.redirect(url);
});

// History and Stats APIs
app.get("/api/history", async (req, res) => {
  const user = getUserFromRequest(req);
  if (!user) {
    console.warn(`[API Log] Unauthorized history access attempt`);
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }

  const { search, status } = req.query;
  const page = req.query.page ? parseInt(req.query.page, 10) : null;
  const limit = req.query.limit ? parseInt(req.query.limit, 10) : null;

  console.log(`[API Log] History request received. Search: "${search || ""}", Status: "${status || ""}", Page: ${page}, Limit: ${limit}`);
  try {
    const result = await db.getEmails(search, status, page, limit);
    const isPersistent = !!process.env.PERSISTENT_STORAGE;
    
    const simplifiedHistory = result.history.map(row => {
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
    });

    console.log(`[DEBUG API] /api/history response:`, JSON.stringify(simplifiedHistory, null, 2));

    res.json({ 
      success: true, 
      history: simplifiedHistory, 
      total: result.total,
      persistent: isPersistent,
      page,
      limit
    });
  } catch (err) {
    console.error(`[API Log] Error fetching email history:`, err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get("/api/stats", async (req, res) => {
  const user = getUserFromRequest(req);
  if (!user) {
    console.warn(`[API Log] Unauthorized stats access attempt`);
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }

  console.log(`[API Log] Stats request received`);
  try {
    const stats = await db.getStats();
    res.json(stats);
  } catch (err) {
    console.error(`[API Log] Error fetching email stats:`, err);
    res.status(500).json({ success: false, error: err.message });
  }
});

const upload = multer({ dest: "uploads/" });

app.post(
  "/send-emails",
  upload.single("attachment"),
  async (req, res) => {
    try {
      const user = getUserFromRequest(req);

      if (!user) {
        return res.json({
          success: false,
          message: "Not Logged In"
        });
      }

      const emails = JSON.parse(req.body.emails);
      const subject = req.body.subject;
      const message = req.body.message;

      const sent = [];
      const failed = [];

      // Send emails in parallel using Gmail HTTP API
      const emailPromises = emails.map(async (email) => {
        const emailId = crypto.randomBytes(16).toString("hex");
        const backendOrigin = getBackendOrigin(req);
        
        // Rewrite links for click tracking
        let trackedMessage = rewriteLinks(message, emailId, backendOrigin);
        
        // Append open tracking pixel
        const trackingPixelTag = `<img src="${backendOrigin}/track/open/${emailId}" width="1" height="1" style="display:none;" />`;
        trackedMessage += trackingPixelTag;

        console.log(`[EMAIL GENERATION PIPELINE]
  - emailId: ${emailId}
  - recipient: ${email}
  - backendOrigin: ${backendOrigin}
  - trackingPixelTag: ${trackingPixelTag}
  - isPointingToLocalhost: ${backendOrigin.includes("localhost") || backendOrigin.includes("127.0.0.1")}
  - trackingPixelInjected: ${trackedMessage.includes(trackingPixelTag)}
  - finalHTML: \n${trackedMessage}\n`);

        const mailOptions = {
          from: user.emails[0].value,
          to: email,
          subject,
          html: trackedMessage
        };

        if (req.file) {
          mailOptions.attachments = [
            {
              filename: req.file.originalname,
              path: req.file.path
            }
          ];
        }

        try {
          const composer = new MailComposer(mailOptions);
          const mimeBuffer = await new Promise((resolve, reject) => {
            composer.compile().build((err, msg) => {
              if (err) reject(err);
              else resolve(msg);
            });
          });

          const encodedMessage = Buffer.from(mimeBuffer)
            .toString("base64")
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

          const response = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${user.accessToken}`,
              "Content-Type": "application/json"
            },
            body: JSON.stringify({
              raw: encodedMessage
            })
          });

          const data = await response.json();
          if (!response.ok) {
            throw new Error(data.error?.message || "Failed to send via Gmail API");
          }

          sent.push(email);

          // Save sent log in SQLite DB
          await db.saveEmail({
            id: emailId,
            recipient_email: email,
            subject: subject,
            status: "Sent",
            sent_at: Date.now(),
            error_message: null
          });
        } catch (err) {
          console.error(`Failed sending to ${email}:`, err);
          failed.push({ email, error: err.message });

          // Save failed log in SQLite DB
          await db.saveEmail({
            id: emailId,
            recipient_email: email,
            subject: subject,
            status: "Failed",
            sent_at: Date.now(),
            error_message: err.message
          });
        }
      });

      await Promise.all(emailPromises);

      // Cleanup uploaded file from server storage
      if (req.file) {
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting file:", err);
        });
      }

      res.json({
        success: failed.length === 0,
        sentCount: sent.length,
        failedCount: failed.length,
        failedList: failed
      });

    } catch (error) {

      console.error(error);

      // Cleanup file if an error occurs
      if (req.file) {
        fs.unlink(req.file.path, () => {});
      }

      res.json({
        success: false,
        error: error.message
      });

    }
  }
);

app.listen(process.env.PORT || 5000, () => {
  console.log("Server Running");
});