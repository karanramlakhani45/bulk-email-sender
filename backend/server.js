const express = require("express");
const nodemailer = require("nodemailer");
const MailComposer = require("nodemailer/lib/mail-composer");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
require("dotenv").config();

const app = express();

app.set("trust proxy", 1);

app.use(cors({
  origin: "https://bulk-email-sender-ashy.vercel.app",
  credentials: true
}));

app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
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
      callbackURL:
        "https://bulk-email-sender-uaig.onrender.com/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      profile.accessToken = accessToken;
      return done(null, profile);
    }
  )
);

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: [
      "profile",
      "email",
      "https://www.googleapis.com/auth/gmail.send"
    ],
    prompt: "select_account"
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/"
  }),
  (req, res) => {
    res.redirect(
      "https://bulk-email-sender-ashy.vercel.app/dashboard.html"
    );
  }
);

app.get("/user", (req, res) => {
  res.json({
    loggedIn: !!req.user,
    user: req.user || null
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

      if (!req.user) {
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
          from: req.user.emails[0].value,
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
              "Authorization": `Bearer ${req.user.accessToken}`,
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