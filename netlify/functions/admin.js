const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const SESSION_SECRET = process.env.SESSION_SECRET || ADMIN_PASSWORD_HASH || ADMIN_PASSWORD || 'dev-session-secret';
const IS_PRODUCTION = process.env.CONTEXT === 'production' || process.env.NODE_ENV === 'production';

function securityHeaders(headers = {}) {
  const baseHeaders = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cache-Control': 'no-store',
    ...headers
  };

  if (IS_PRODUCTION) {
    baseHeaders['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  }

  return baseHeaders;
}

function redirect(location) {
  return {
    statusCode: 303,
    headers: securityHeaders({ Location: location }),
    body: ''
  };
}

function safeCompare(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  if (first.length !== second.length) return false;
  return crypto.timingSafeEqual(first, second);
}

function base64UrlDecode(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function parseCookies(event) {
  const cookieHeader = event.headers.cookie || event.headers.Cookie || '';
  return Object.fromEntries(
    cookieHeader
      .split(';')
      .map((cookie) => cookie.trim())
      .filter(Boolean)
      .map((cookie) => {
        const [key, ...value] = cookie.split('=');
        return [key, decodeURIComponent(value.join('='))];
      })
  );
}

function isAdmin(event) {
  const token = parseCookies(event).admin_session;
  if (!token || !token.includes('.')) return false;

  const [payload, signature] = token.split('.');
  if (!safeCompare(signature, sign(payload))) return false;

  try {
    const session = JSON.parse(base64UrlDecode(payload));
    return session.username === ADMIN_USERNAME && session.exp > Date.now();
  } catch (_error) {
    return false;
  }
}

async function readAdminPage() {
  const candidates = [
    path.join(process.cwd(), 'front-end', 'admin.html'),
    path.join(__dirname, '..', '..', 'front-end', 'admin.html')
  ];

  for (const filePath of candidates) {
    try {
      return await fs.readFile(filePath, 'utf8');
    } catch (_error) {
      // Try the next bundled path.
    }
  }

  throw new Error('Page admin introuvable dans le bundle Netlify.');
}

exports.handler = async (event) => {
  try {
    if (event.httpMethod !== 'GET') {
      return {
        statusCode: 405,
        headers: securityHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }),
        body: 'Methode non autorisee.'
      };
    }

    if (!isAdmin(event)) return redirect('/admin/login');

    return {
      statusCode: 200,
      headers: securityHeaders({ 'Content-Type': 'text/html; charset=utf-8', 'X-Robots-Tag': 'noindex' }),
      body: await readAdminPage()
    };
  } catch (error) {
    console.error(error);
    return {
      statusCode: 500,
      headers: securityHeaders({ 'Content-Type': 'text/plain; charset=utf-8' }),
      body: 'Impossible de charger le tableau de bord.'
    };
  }
};
