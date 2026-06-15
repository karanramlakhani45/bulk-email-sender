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
require("dotenv").config();

const app = express();

app.set("trust proxy", 1);

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

const allowedOrigins = [
  "https://bulk-email-sender-ashy.vercel.app",
  "http://localhost:5000",
  "http://localhost:3000",
  "http://127.0.0.1:5500",
  "http://127.0.0.1:5000",
  "http://localhost:8080"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    const isLocalhost = origin.startsWith("http://localhost:") || origin.startsWith("http://127.0.0.1:");
    if (allowedOrigins.indexOf(origin) !== -1 || isLocalhost) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || "fallback-session-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    sameSite: "none"
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
        const mailOptions = {
          from: user.emails[0].value,
          to: email,
          subject,
          html: message
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
        } catch (err) {
          console.error(`Failed sending to ${email}:`, err);
          failed.push({ email, error: err.message });
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