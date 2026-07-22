# 📧 Bulk Email Sender

A full-stack Bulk Email Sender web application that allows authenticated users to send personalized emails to multiple recipients using CSV uploads. The application supports Google OAuth authentication, email templates, campaign history, email tracking, click tracking, and campaign statistics.

---

## 🚀 Features

### Authentication
- Google OAuth Login
- Secure user authentication
- Session management

### Bulk Email Sending
- Upload CSV files
- Automatic email column detection
- Dynamic template variables
- Personalized emails for every recipient
- HTML email support

### Email Tracking
- Open tracking using tracking pixels
- Click tracking
- Bot and security scanner detection
- Gmail Proxy detection
- Outlook SafeLinks detection
- Barracuda detection
- Proofpoint detection
- Mimecast detection

### Campaign History
- Email history
- Search emails
- Filter by status
- Pagination
- Campaign statistics
- Sent time
- Opened time
- Status tracking

### Dashboard
- Total Emails
- Sent Emails
- Failed Emails
- Open Rate
- Click Rate

### Security
- Google OAuth
- Environment Variables
- Bot Detection
- Spam Protection
- Input Validation

---

# 🛠 Tech Stack

## Frontend
- HTML5
- CSS3
- JavaScript

## Backend
- Node.js
- Express.js

## Database
- SQLite3

## Authentication
- Google OAuth 2.0
- Passport.js

## Email
- Nodemailer

---

# 📁 Project Structure

```
bulk-email-sender/

│
├── backend/
│   ├── server.js
│   ├── db.js
│   ├── package.json
│   ├── emails.db
│   └── .env
│
├── frontend/
│   ├── index.html
│   ├── dashboard.html
│   ├── history.html
│   ├── dashboard.js
│   ├── history.js
│   ├── styles.css
│   └── .env
│
├── uploads/
├── package.json
└── README.md
```

---

# ⚙ Installation

Clone the repository

```bash
git clone https://github.com/your-username/bulk-email-sender.git
```

Move into the project

```bash
cd bulk-email-sender
```

Install dependencies

```bash
npm install
```

Install backend dependencies

```bash
cd backend
npm install
```

Start the server

```bash
npm start
```

---

# 🔑 Environment Variables

Backend `.env`

```env
CLIENT_ID=YOUR_GOOGLE_CLIENT_ID

CLIENT_SECRET=YOUR_GOOGLE_CLIENT_SECRET

SESSION_SECRET=YOUR_SESSION_SECRET

EMAIL_USER=YOUR_EMAIL

EMAIL_PASS=YOUR_APP_PASSWORD

BASE_URL=https://your-render-url.onrender.com
```

---

# 📤 CSV Format

Example

| Name | Email |
|------|-------|
| John | john@gmail.com |
| Alice | alice@gmail.com |

Template Variables

```
{{Name}}

{{Email}}
```

---

# 📊 Email Status

| Status | Meaning |
|----------|----------------|
| Sent | Email delivered successfully |
| Opened (Human) | Opened by a real user |
| Clicked | User clicked a tracked link |
| Failed | Email sending failed |

---

# 📈 Dashboard Metrics

- Total Emails
- Sent Emails
- Failed Emails
- Open Rate
- Click Rate

---

# 📧 Email Tracking

The application uses a tracking pixel to detect email opens.

Supported detection includes:

- Google Image Proxy
- Outlook SafeLinks
- Microsoft Defender
- Barracuda
- Proofpoint
- Mimecast
- Generic security scanners

Bot opens are excluded from open rate calculations.

---

# 🔒 Security

- Google OAuth Authentication
- Environment Variables
- Secure Sessions
- Bot Detection
- Click Tracking
- Open Tracking

---

# ☁ Deployment

Backend

- Render

Frontend

- Render Static Site

Database

- SQLite

---

# 📸 Screenshots

Add screenshots of:

- Login Page
- Dashboard
- Bulk Email Sender
- History Page
- Campaign Statistics

---

# 👨‍💻 Future Improvements

- User Management
- Email Templates
- Scheduled Campaigns
- Attachments
- Campaign Analytics
- Export Reports
- Multi-user Support
- PostgreSQL Support

---

# 📜 License

This project is developed for educational and learning purposes.

---

# 👤 Author

**Karan Ramlakhani**

GitHub: https://github.com/karanramlakhani45
