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
const { google } = require("googleapis");
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

async function logTokenInfo(accessToken, context = "") {
  try {
    if (!accessToken) {
      console.log(`[Google TokenInfo - ${context}] Access Token is empty/missing`);
      return null;
    }
    const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?access_token=${accessToken}`);
    const data = await response.json();
    if (!response.ok) {
      console.error(`[Google TokenInfo - ${context}] Error response:`, JSON.stringify(data, null, 2));
      return null;
    }
    console.log(`[Google TokenInfo - ${context}] Info:`, JSON.stringify(data, null, 2));
    return data;
  } catch (err) {
    console.error(`[Google TokenInfo - ${context}] Failed to query tokeninfo:`, err.message);
    return null;
  }
}

async function refreshGoogleAccessToken(refreshToken) {
  try {
    if (!refreshToken) {
      console.error("[refreshGoogleAccessToken] Cannot refresh: Refresh token is missing!");
      return null;
    }
    console.log("[refreshGoogleAccessToken] Querying Google OAuth token endpoint to refresh access token...");
    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        refresh_token: refreshToken,
        grant_type: "refresh_token"
      })
    });

    const data = await response.json();
    if (!response.ok) {
      console.error("[refreshGoogleAccessToken] Google OAuth token endpoint error response:", JSON.stringify(data, null, 2));
      return null;
    }

    console.log("[refreshGoogleAccessToken] Successfully refreshed Google access token!", {
      expires_in: data.expires_in,
      scope: data.scope
    });

    return {
      accessToken: data.access_token,
      expiresIn: data.expires_in
    };
  } catch (err) {
    console.error("[refreshGoogleAccessToken] Exception during refresh request:", err);
    return null;
  }
}

function getGmailClient(user, res = null) {
  if (!user || !user.accessToken) {
    throw new Error("Cannot initialize Gmail client: user is not authenticated or access token is missing.");
  }
  
  const oauth2Client = new google.auth.OAuth2(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
    process.env.CALLBACK_URL
  );
  
  oauth2Client.setCredentials({
    access_token: user.accessToken,
    refresh_token: user.refreshToken
  });

  oauth2Client.on("tokens", (tokens) => {
    console.log("[Gmail Client] Google OAuth2 client automatically refreshed tokens:", JSON.stringify(tokens));
    if (tokens.access_token) {
      user.accessToken = tokens.access_token;
      if (tokens.expiry_date) {
        user.googleExpiresAt = tokens.expiry_date;
      }
      
      // Update JWT token and send it back to client via header
      if (res && !res.headersSent) {
        const payload = {
          user: user,
          expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000
        };
        const newToken = encryptToken(payload);
        console.log("[Gmail Client] Attaching automatically refreshed Bearer token to X-New-Token header");
        res.setHeader("X-New-Token", newToken);
      }
    }
  });

  console.log(`[Gmail client initialized] Gmail API client successfully created for user: ${user.emails?.[0]?.value || user.displayName}`);
  return google.gmail({ version: "v1", auth: oauth2Client });
}

async function validateTokenScopes(accessToken) {
  try {
    if (!accessToken) {
      return { valid: false, error: "Access token is empty/missing" };
    }
    const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?access_token=${accessToken}`);
    const data = await response.json();
    if (!response.ok) {
      console.error("[Token Scope Validation] Token info request failed:", JSON.stringify(data));
      return { valid: false, error: data.error_description || "Invalid token" };
    }
    
    const scopes = data.scope ? data.scope.split(" ") : [];
    const hasGmailSend = scopes.includes("https://www.googleapis.com/auth/gmail.send");
    
    console.log("[Token Scope Validation] Token details:", {
      expires_in: data.expires_in,
      scopes: scopes,
      hasGmailSend: hasGmailSend
    });
    
    if (!hasGmailSend) {
      return { valid: false, error: "Missing required scope: gmail.send", scopes };
    }
    
    return { valid: true, scopes, expiresIn: data.expires_in };
  } catch (err) {
    console.error("[Token Scope Validation] Exception:", err.message);
    return { valid: false, error: err.message };
  }
}

async function checkMailServiceStatus(gmailClient) {
  try {
    console.log("[Gmail Readiness Check] Querying Gmail user profile to verify service is enabled...");
    const res = await gmailClient.users.getProfile({ userId: "me" });
    console.log("[Mail service enabled] Mail service verification succeeded for user:", res.data.emailAddress);
    return { enabled: true, profile: res.data };
  } catch (err) {
    console.error("[Gmail Readiness Check] Mail service is NOT enabled or verification failed:", err.message);
    return { enabled: false, error: err.message };
  }
}

function generateToken(user) {
  const payload = {
    user: {
      id: user.id,
      displayName: user.displayName,
      emails: user.emails,
      photos: user.photos,
      accessToken: user.accessToken,
      refreshToken: user.refreshToken,
      googleExpiresAt: user.googleExpiresAt,
      scopes: user.scopes
    },
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 // 7 days validity
  };
  return encryptToken(payload);
}

// Check Authorization headers or fall back to cookies. Support token refreshing.
async function getUserFromRequest(req, res) {
  const authHeader = req.headers.authorization;
  console.log(`[getUserFromRequest] Headers authorization: ${authHeader ? "Present" : "Missing"}`);
  console.log(`[getUserFromRequest] Session user:`, req.user ? JSON.stringify({ ...req.user, accessToken: req.user.accessToken ? `${req.user.accessToken.substring(0, 10)}...` : null }, null, 2) : "None");

  let user = null;
  let isFromToken = false;
  let decryptedPayload = null;

  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    const decrypted = decryptToken(token);
    console.log(`[getUserFromRequest] Decrypted JWT payload:`, decrypted ? JSON.stringify({ ...decrypted, user: { ...decrypted.user, accessToken: decrypted.user.accessToken ? `${decrypted.user.accessToken.substring(0, 10)}...` : null } }, null, 2) : "Decryption failed");
    if (decrypted && decrypted.expiresAt > Date.now()) {
      user = decrypted.user;
      isFromToken = true;
      decryptedPayload = decrypted;
    }
  }

  // Fallback to session if no valid Bearer token
  if (!user && req.user) {
    user = req.user;
    isFromToken = false;
  }

  if (user) {
    console.log(`[Tokens loaded] Tokens loaded successfully for user: ${user.emails?.[0]?.value || user.displayName}`);
    // Check if Google Access Token is expired or about to expire in 5 minutes
    const bufferTime = 5 * 60 * 1000; // 5 minutes
    const now = Date.now();
    let isExpired = user.googleExpiresAt && (user.googleExpiresAt - bufferTime < now);

    console.log(`[getUserFromRequest] User identified: ${user.emails?.[0]?.value || user.displayName}`);
    console.log(`- Google Access Token Expiration: ${user.googleExpiresAt ? new Date(user.googleExpiresAt).toISOString() : "Unknown"}`);
    console.log(`- Is Expired/Expiring Soon: ${isExpired ? "Yes" : "No"}`);

    // Before every verify, dynamically check token validity and scopes via tokeninfo endpoint
    let tokenStatus = await validateTokenScopes(user.accessToken);
    if (!tokenStatus.valid) {
      console.warn(`[getUserFromRequest] Active token is invalid or lacks gmail.send (${tokenStatus.error}). Forcing refresh...`);
      isExpired = true; // force refresh
    }

    if (isExpired && user.refreshToken) {
      console.log(`- Access Token is expired or lacks scopes. Refreshing using Refresh Token...`);
      const refreshResult = await refreshGoogleAccessToken(user.refreshToken);
      if (refreshResult) {
        user.accessToken = refreshResult.accessToken;
        user.googleExpiresAt = Date.now() + refreshResult.expiresIn * 1000;
        console.log(`- Google Access Token refreshed successfully. New expiry: ${new Date(user.googleExpiresAt).toISOString()}`);

        // Revalidate refreshed token
        tokenStatus = await validateTokenScopes(user.accessToken);

        // Update the source
        if (isFromToken && res && decryptedPayload) {
          decryptedPayload.user = user;
          const newToken = encryptToken(decryptedPayload);
          console.log("- Attaching new Bearer token to response header X-New-Token");
          res.setHeader("X-New-Token", newToken);
        } else if (req.user) {
          req.user.accessToken = user.accessToken;
          req.user.googleExpiresAt = user.googleExpiresAt;
        }
      } else {
        console.warn(`- Failed to refresh Google Access Token.`);
      }
    } else if (isExpired && !user.refreshToken) {
      console.warn(`- Access Token needs refresh but no Refresh Token was found in user object!`);
    }

    // If scopes validation still fails after refresh check, return null (destroying stale credentials)
    if (!tokenStatus.valid) {
      console.error(`[getUserFromRequest] Stale/invalid credentials detected for user ${user.emails?.[0]?.value || user.displayName}. Scope validation failed: ${tokenStatus.error}. Rejecting session to force re-consent.`);
      return null;
    }

    return user;
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
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: ["X-New-Token"]
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
    (accessToken, refreshToken, params, profile, done) => {
      console.log("\n[OAuth Callback Executing]");
      console.log("- Access Token:", accessToken ? `${accessToken.substring(0, 10)}...` : "None");
      console.log("- Refresh Token:", refreshToken ? "Present" : "Missing/Null");
      console.log("- Params (Scopes, expiration, etc):", JSON.stringify(params, null, 2));
      console.log("- Profile ID:", profile.id);
      console.log("- Profile Name:", profile.displayName);

      // Attach token details to profile object
      profile.accessToken = accessToken;
      profile.refreshToken = refreshToken; // can be undefined/null if offline access not prompted or user already consented
      profile.googleExpiresAt = params.expires_in ? (Date.now() + params.expires_in * 1000) : null;
      profile.scopes = params.scope ? params.scope.split(" ") : [];

      console.log("\n[OAuth callback completed]");
      console.log("- Profile ID:", profile.id);
      console.log("- Profile Name:", profile.displayName);
      console.log("- Requested Scopes (App Config):", [
        "profile",
        "email",
        "https://www.googleapis.com/auth/gmail.send"
      ]);
      console.log("- Granted Scopes (Google Response):", profile.scopes);
      console.log("- Access Token:", accessToken ? `${accessToken.substring(0, 10)}...` : "None");
      console.log("- Refresh Token availability:", refreshToken ? "Present" : "Missing/Null");
      console.log("- Token Expiry Time:", profile.googleExpiresAt ? new Date(profile.googleExpiresAt).toISOString() : "None");
      console.log("");

      return done(null, profile);
    }
  )
);

const authRouter = express.Router();

authRouter.get(
  "/google",
  (req, res, next) => {
    const redirectUri = req.query.redirect_uri || "https://bulk-email-sender-ashy.vercel.app/dashboard.html";
    const state = Buffer.from(JSON.stringify({ redirectUri })).toString("base64");
    
    console.log(`[OAuth Initiate /auth/google] Redirect URI: ${redirectUri}`);
    passport.authenticate("google", {
      scope: [
        "profile",
        "email",
        "https://www.googleapis.com/auth/gmail.send"
      ],
      accessType: "offline",
      prompt: "select_account consent",
      state: state
    })(req, res, next);
  }
);

authRouter.get(
  "/google/callback",
  (req, res, next) => {
    console.log(`[OAuth Callback Route] Hit /auth/google/callback. Query state: ${req.query.state ? "Present" : "Missing"}`);
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
      console.error("[OAuth Callback Route] Authentication completed but no req.user present in request.");
      const parsed = new URL(redirectUri);
      return res.redirect(`${parsed.origin}/index.html?error=no_user`);
    }

    console.log(`[OAuth Callback Route] User authenticated: ${req.user.emails?.[0]?.value || req.user.displayName}`);
    console.log(`[OAuth callback completed] OAuth callback completed successfully for user: ${req.user.emails?.[0]?.value || req.user.displayName}`);
    console.log(`- Scope:`, req.user.scopes);
    console.log(`- Google Access Token:`, req.user.accessToken ? `${req.user.accessToken.substring(0, 10)}...` : "None");
    console.log(`- Google Refresh Token:`, req.user.refreshToken ? "Present" : "Missing");

    const token = generateToken(req.user);
    console.log(`[OAuth Callback Route] Generated JWT. Redirecting user to: ${redirectUri}`);
    res.redirect(`${redirectUri}?token=${token}`);
  }
);

authRouter.get("/me", async (req, res) => {
  const user = await getUserFromRequest(req, res);
  let mailServiceEnabled = false;
  let gmailProfile = null;
  
  if (user) {
    try {
      const gmailClient = getGmailClient(user, res);
      const status = await checkMailServiceStatus(gmailClient);
      mailServiceEnabled = status.enabled;
      gmailProfile = status.profile;
    } catch (err) {
      console.error("[Auth Me] Failed to verify Gmail service status:", err.message);
    }
  }

  res.json({
    loggedIn: !!user,
    user: user || null,
    mailServiceEnabled,
    gmailProfile
  });
});

authRouter.post("/logout", (req, res, next) => {
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

// Mount the OAuth router
app.use("/auth", authRouter);

// Backward compatibility aliases
app.get("/user", async (req, res) => {
  const user = await getUserFromRequest(req, res);
  let mailServiceEnabled = false;
  let gmailProfile = null;
  
  if (user) {
    try {
      const gmailClient = getGmailClient(user, res);
      const status = await checkMailServiceStatus(gmailClient);
      mailServiceEnabled = status.enabled;
      gmailProfile = status.profile;
    } catch (err) {
      console.error("[User Endpoint] Failed to verify Gmail service status:", err.message);
    }
  }

  res.json({
    loggedIn: !!user,
    user: user || null,
    mailServiceEnabled,
    gmailProfile
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

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

function classifyRequest(userAgent, ip, elapsedSeconds, hasPrefetched = false) {
  const uaLower = (userAgent || "").toLowerCase();
  
  // Strip IPv6 prefix for mapped IPv4 addresses to ensure range checks work
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

  // 1. Strict timing check (Never classify as Human if within 60 seconds of delivery)
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
    // 2. Delayed requests (> 60 seconds)
    if (isGoogleProxyUA || isGoogleIP) {
      // Gmail heuristic: if we already saw an open OR it is delayed > 5 mins (300s)
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

  const classification = isBotOpen === 2 ? "Gmail Proxy" : (isBotOpen === 1 ? "Bot" : "Human");

  console.log(`\n[CLASSIFIER DECISION]
Elapsed: ${elapsedSeconds.toFixed(2)}s
UA: ${userAgent}
IP: ${ip} (clean: ${cleanIp})
Matched rule: ${matchedRule}
Final classification: ${classification}\n`);

  return { isBotOpen, reason };
}

// Open tracking pixel endpoint
app.get("/track/open/:emailId", async (req, res) => {
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
      const hasPrefetched = email.opened_at !== null;
      const { isBotOpen, reason } = classifyRequest(userAgent, ip, elapsedSeconds, hasPrefetched);
      
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
    const changes = await db.markEmailClicked(emailId);
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
  const user = await getUserFromRequest(req, res);
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
  const user = await getUserFromRequest(req, res);
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
      const user = await getUserFromRequest(req, res);

      if (!user) {
        console.warn("[Gmail Send Campaign] Sending blocked: Not Logged In");
        return res.json({
          success: false,
          message: "Not Logged In"
        });
      }

      // 1. Load Tokens Info
      console.log(`\n[Gmail Send Campaign] User initiating email sending: ${user.emails?.[0]?.value || user.displayName}`);
      console.log(`[Tokens Loaded] Loaded tokens for user: ${user.emails?.[0]?.value || user.displayName}`);
      console.log(`- Access Token: ${user.accessToken ? `${user.accessToken.substring(0, 10)}...` : "None"}`);
      console.log(`- Refresh Token: ${user.refreshToken ? "Present" : "Missing"}`);
      await logTokenInfo(user.accessToken, "Before Campaign Send");

      // 2. Initialize Gmail client
      let gmailClient;
      try {
        gmailClient = getGmailClient(user, res);
      } catch (err) {
        console.error(`[Gmail Send Campaign] Sending blocked: Gmail client initialization failed: ${err.message}`);
        return res.json({
          success: false,
          error: `Gmail client initialization failed: ${err.message}`
        });
      }

      // 3. Verify Gmail Mail Service Status
      const serviceStatus = await checkMailServiceStatus(gmailClient);
      if (!serviceStatus.enabled) {
        console.error(`[Gmail Send Campaign] Sending blocked: Mail service not enabled. Reason: ${serviceStatus.error}`);
        return res.json({
          success: false,
          error: `Mail service not enabled: ${serviceStatus.error}`
        });
      }

      const emails = JSON.parse(req.body.emails);
      const subject = req.body.subject;
      const message = req.body.message;

      const sent = [];
      const failed = [];

      // Send emails in parallel using Gmail API Client
      const emailPromises = emails.map(async (email) => {
        const emailId = crypto.randomBytes(16).toString("hex");
        const backendOrigin = getBackendOrigin(req);
        
        // Rewrite links for click tracking
        let trackedMessage = rewriteLinks(message, emailId, backendOrigin);
        
        // Append open tracking pixel
        const trackingPixelTag = `<img src="${backendOrigin}/track/open/${emailId}" width="1" height="1" style="display:none;" />`;
        trackedMessage += trackingPixelTag;

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

          console.log(`[sendEmail() entered] Attempting to send email to ${email}`);
          
          const response = await gmailClient.users.messages.send({
            userId: "me",
            requestBody: {
              raw: encodedMessage
            }
          });

          console.log(`[Gmail Send API Call] Success response ID: ${response.data.id} for recipient: ${email}`);
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
          console.error(`[Gmail API error details] Failed sending to ${email}:`, {
            message: err.message,
            code: err.code,
            errors: err.errors,
            status: err.status,
            stack: err.stack
          });
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