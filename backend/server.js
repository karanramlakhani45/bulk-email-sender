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
  
  // Fallback to request host only in development
  if (!isProd && req) {
    return `${req.protocol}://${req.get("host")}`;
  }
  
  // If in production, fallback to request host only if not localhost/127.0.0.1
  if (isProd && req) {
    const host = req.get("host");
    if (!host.includes("localhost") && !host.includes("127.0.0.1")) {
      return `${req.protocol}://${host}`;
    }
  }
  
  if (process.env.CALLBACK_URL) {
    try {
      const origin = new URL(process.env.CALLBACK_URL).origin;
      const isLocal = origin.includes("localhost") || origin.includes("127.0.0.1");
      if (!isProd || !isLocal) {
        return origin;
      }
    } catch (e) {}
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

// Open tracking pixel endpoint
app.get("/track/open/:emailId", async (req, res) => {
  const { emailId } = req.params;
  const ip = req.ip || req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const userAgent = req.headers["user-agent"] || "unknown";

  console.log(`[Tracking Log] Open request received for email ID: ${emailId} | IP: ${ip} | User-Agent: ${userAgent}`);

  try {
    const email = await db.getEmailById(emailId);
    if (!email) {
      console.warn(`[Tracking Log] Email not found: ${emailId}`);
    } else {
      console.log(`[Tracking Log] Email found: ${emailId}`);
      const isGoogleProxy = /googleimageproxy/i.test(userAgent);
      const elapsedSeconds = (Date.now() - email.sent_at) / 1000;

      if (isGoogleProxy && elapsedSeconds <= 10) {
        console.log(`[Tracking Log] GoogleImageProxy prefetch detected for email ID: ${emailId} after ${elapsedSeconds.toFixed(2)}s. Skipping database update.`);
      } else {
        const changes = await db.markOpened(emailId);
        console.log(`[Tracking Log] Open recorded successfully for email ID: ${emailId}. Changes: ${changes} | Elapsed: ${elapsedSeconds.toFixed(2)}s`);
      }
    }
  } catch (err) {
    console.error(`[Tracking Log] Error handling open tracking for ${emailId}:`, err);
  }

  const pixel = Buffer.from(
    "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",
    "base64"
  );
  res.writeHead(200, {
    "Content-Type": "image/gif",
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
  console.log(`[Tracking Log] Click tracking request received for email ID: ${emailId}, target: ${url}`);
  
  if (!url) {
    console.warn(`[Tracking Log] Click tracking request failed: Missing target URL`);
    return res.status(400).send("Missing target URL");
  }

  try {
    const changes = await db.markClicked(emailId);
    console.log(`[Tracking Log] Click marked. Changes: ${changes}`);
  } catch (err) {
    console.error(`[Tracking Log] Error marking link clicked for ${emailId}:`, err);
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
  console.log(`[API Log] History request received. Search: "${search || ""}", Status: "${status || ""}"`);
  try {
    const history = await db.getEmails(search, status);
    res.json({ success: true, history });
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
        trackedMessage += `<img src="${backendOrigin}/track/open/${emailId}" width="1" height="1" style="display:none;" />`;

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