const express = require("express");
const nodemailer = require("nodemailer");
const cors = require("cors");
const multer = require("multer");
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
    ]
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

      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          type: "OAuth2",
          user: req.user.emails[0].value,
          clientId: process.env.CLIENT_ID,
          clientSecret: process.env.CLIENT_SECRET,
          accessToken: req.user.accessToken
        }
      });

      for (const email of emails) {

        const mailOptions = {
          from: req.user.emails[0].value,
          to: email,
          subject,
          text: message
        };

        if (req.file) {
          mailOptions.attachments = [
            {
              filename: req.file.originalname,
              path: req.file.path
            }
          ];
        }

        await transporter.sendMail(mailOptions);
      }

      res.json({
        success: true
      });

    } catch (error) {

      console.error(error);

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