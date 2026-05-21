/**
 * server.js — Production-grade Express backend for portfolio admin auth
 *
 * SETUP:
 *   npm install express express-session express-rate-limit csurf helmet
 *                bcrypt dotenv connect-sqlite3
 *   node server.js
 *
 * ENV (.env file):
 *   ADMIN_PASSWORD_HASH=<bcrypt hash of your password>
 *   SESSION_SECRET=<64-char random string>
 *   PORT=3000
 *   NODE_ENV=production
 *
 * GENERATE HASH:
 *   node -e "require('bcrypt').hash('your_password',12).then(console.log)"
 */

'use strict';

require('dotenv').config();

const express    = require('express');
const session    = require('express-session');
const rateLimit  = require('express-rate-limit');
const helmet     = require('helmet');
const bcrypt     = require('bcrypt');
const path       = require('path');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

/* ─── SECURITY HEADERS ────────────────────────────────────────── */
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc:  ["'self'"],
            scriptSrc:   ["'self'", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
            styleSrc:    ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
            fontSrc:     ["'self'", "fonts.gstatic.com"],
            imgSrc:      ["'self'", "data:", "blob:", "images.unsplash.com"],
            connectSrc:  ["'self'"],
            frameSrc:    ["'none'"],
            objectSrc:   ["'none'"],
        },
    },
    hsts: isProd ? { maxAge: 31536000, includeSubDomains: true, preload: true } : false,
}));

/* ─── BODY PARSING ────────────────────────────────────────────── */
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

/* ─── SESSION ─────────────────────────────────────────────────── */
app.use(session({
    secret: process.env.SESSION_SECRET || (() => { throw new Error('SESSION_SECRET env var required'); })(),
    name:   '__Host-sid',          // __Host- prefix prevents subdomain abuse
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly:  true,           // JS cannot read this cookie
        secure:    isProd,         // HTTPS only in production
        sameSite:  'strict',       // CSRF mitigation
        maxAge:    2 * 60 * 60 * 1000, // 2 hour session
    },
}));

/* ─── CSRF PROTECTION ─────────────────────────────────────────── */
// Double-submit cookie pattern (stateless, no external library needed)
function generateCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}

function csrfMiddleware(req, res, next) {
    // Provide a fresh token on GET requests
    if (req.method === 'GET') {
        if (!req.session.csrfToken) {
            req.session.csrfToken = generateCsrfToken();
        }
        res.locals.csrfToken = req.session.csrfToken;
        return next();
    }
    // Validate on POST/PUT/DELETE
    const token = req.headers['x-csrf-token'] || req.body._csrf;
    if (!token || !req.session.csrfToken || !crypto.timingSafeEqual(
        Buffer.from(token), Buffer.from(req.session.csrfToken)
    )) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    // Rotate token after use
    req.session.csrfToken = generateCsrfToken();
    next();
}

/* ─── RATE LIMITER ────────────────────────────────────────────── */
const loginLimiter = rateLimit({
    windowMs:         15 * 60 * 1000, // 15 minutes
    max:              5,               // 5 attempts per window
    standardHeaders:  true,
    legacyHeaders:    false,
    skipSuccessfulRequests: true,
    handler: (req, res) => {
        // Generic error — don't reveal lockout details
        res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
    },
});

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,  // 1 minute
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
});

/* ─── AUTH MIDDLEWARE ─────────────────────────────────────────── */
function requireAuth(req, res, next) {
    if (req.session && req.session.adminAuthenticated) return next();
    return res.status(401).json({ error: 'Unauthorized' });
}

/* ─── INPUT SANITIZATION ──────────────────────────────────────── */
function sanitizeString(val, maxLen = 500) {
    if (typeof val !== 'string') return '';
    return val.trim().slice(0, maxLen)
        .replace(/[<>]/g, '')    // strip angle brackets
        .replace(/javascript:/gi, ''); // strip JS proto URLs
}

function sanitizeUrl(val) {
    const s = sanitizeString(val, 2000);
    if (!s) return '#';
    if (s === '#') return '#';
    if (s.startsWith('mailto:') || s.startsWith('https://') || s.startsWith('http://')) return s;
    return 'https://' + s;
}

/* ─── ROUTES ──────────────────────────────────────────────────── */

// Serve static files (the HTML portfolio)
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: isProd ? '1d' : 0,
    etag: true,
}));

// GET /admin/csrf — fetch CSRF token before login form
app.get('/admin/csrf', csrfMiddleware, (req, res) => {
    res.json({ token: res.locals.csrfToken });
});

// POST /admin/auth — authenticate admin
app.post('/admin/auth', loginLimiter, csrfMiddleware, async (req, res) => {
    const { password } = req.body;

    // Input validation
    if (!password || typeof password !== 'string' || password.length > 256) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    const hash = process.env.ADMIN_PASSWORD_HASH;
    if (!hash) {
        console.error('ADMIN_PASSWORD_HASH env var not set');
        return res.status(500).json({ error: 'Server configuration error' });
    }

    // bcrypt comparison (timing-safe)
    const match = await bcrypt.compare(password, hash).catch(() => false);

    if (match) {
        // Regenerate session ID after auth (session fixation protection)
        req.session.regenerate(err => {
            if (err) return res.status(500).json({ error: 'Session error' });
            req.session.adminAuthenticated = true;
            req.session.csrfToken = generateCsrfToken();
            return res.json({ ok: true, csrfToken: req.session.csrfToken });
        });
    } else {
        // Generic error — don't reveal whether user/pass was wrong
        return res.status(401).json({ error: 'Authentication failed' });
    }
});

// POST /admin/logout
app.post('/admin/logout', requireAuth, (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('__Host-sid');
        res.json({ ok: true });
    });
});

// GET /admin/settings — load settings (requires auth)
app.get('/admin/settings', requireAuth, apiLimiter, (req, res) => {
    // In a real app, load from a database here.
    // For demo: return a placeholder. You'd query SQLite/Postgres.
    res.json({ message: 'Settings endpoint — connect your DB here' });
});

// PUT /admin/settings — save settings (requires auth + CSRF)
app.put('/admin/settings', requireAuth, apiLimiter, csrfMiddleware, (req, res) => {
    const { key, value } = req.body;

    // Whitelist valid setting keys
    const allowedKeys = [
        'as_badge','as_hero_title','as_nav_name','as_email',
        'as_insta','as_whatsapp','as_twitter',
        'as_about_p1','as_about_p2',
        'as_stat1_val','as_stat1_lbl','as_stat2_val','as_stat2_lbl','as_stat3_val','as_stat3_lbl',
        'as_value_heading','as_value_subtext',
        'as_hire_heading','as_hire_desc',
        'as_portfolio_heading','as_portfolio','as_accent_color','as_particles',
    ];

    if (!allowedKeys.includes(key)) {
        return res.status(400).json({ error: 'Unknown setting key' });
    }

    // Sanitize value
    const safe = sanitizeString(String(value), 50000);

    // TODO: persist to database
    console.log(`Admin saved: ${key} = ${safe.slice(0, 80)}...`);

    res.json({ ok: true });
});

/* ─── ERROR HANDLING ──────────────────────────────────────────── */
// Generic error handler — never expose stack traces to client
app.use((err, req, res, _next) => {
    console.error('Unhandled error:', err.message);
    res.status(500).json({ error: 'An unexpected error occurred' });
});

// 404
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

/* ─── START ───────────────────────────────────────────────────── */
app.listen(PORT, () => {
    console.log(`Portfolio server running on port ${PORT} (${isProd ? 'production' : 'development'})`);
    if (!isProd) {
        console.log('⚠️  Development mode: cookies are not Secure');
    }
});

module.exports = app;
