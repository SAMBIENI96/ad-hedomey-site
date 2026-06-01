const crypto = require('crypto');
const { getStore } = require('@netlify/blobs');

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const SESSION_SECRET = process.env.SESSION_SECRET || ADMIN_PASSWORD_HASH || ADMIN_PASSWORD || 'dev-session-secret';
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 1000 * 60 * 60 * 8);
const MAX_BODY_SIZE = Number(process.env.MAX_BODY_SIZE || 50 * 1024 * 1024);
const LOGIN_WINDOW_MS = Number(process.env.LOGIN_WINDOW_MS || 1000 * 60 * 15);
const LOGIN_MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 5);
const IS_PRODUCTION = process.env.CONTEXT === 'production' || process.env.NODE_ENV === 'production';

const allowedAudioExtensions = new Set(['.mp3', '.m4a', '.wav', '.ogg', '.webm', '.aac']);
const allowedImageExtensions = new Set(['.jpg', '.jpeg', '.png', '.webp', '.gif', '.avif']);
const allowedThemes = new Set(['Foi', 'Prière', 'Saint-Esprit', 'Mission', 'Enseignement']);
const allowedSubjects = new Set(['prière', 'témoignage', 'information', 'autre']);
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const dataStore = getStore('ad-hedomey-data');
const mediaStore = getStore('ad-hedomey-media');

function securityHeaders(headers = {}) {
  const baseHeaders = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    ...headers
  };

  if (IS_PRODUCTION) {
    baseHeaders['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  }

  return baseHeaders;
}

function json(statusCode, payload, headers = {}) {
  return {
    statusCode,
    headers: securityHeaders({ 'Content-Type': 'application/json; charset=utf-8', ...headers }),
    body: JSON.stringify(payload)
  };
}

function redirect(location, headers = {}) {
  return {
    statusCode: 303,
    headers: securityHeaders({ Location: location, ...headers }),
    body: ''
  };
}

function redirectOrJson(event, payload, redirectPath = '/merci') {
  if ((event.headers.accept || '').includes('application/json')) {
    return json(payload.ok ? 200 : 400, payload);
  }

  return redirect(redirectPath);
}

function createPasswordHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function safeCompare(a, b) {
  const first = Buffer.from(String(a));
  const second = Buffer.from(String(b));

  if (first.length !== second.length) return false;
  return crypto.timingSafeEqual(first, second);
}

function verifyPasswordHash(password, storedHash) {
  const [algorithm, salt, hash] = String(storedHash).split('$');

  if (algorithm !== 'scrypt' || !salt || !hash) return false;

  const calculatedHash = crypto.scryptSync(password, salt, 64).toString('hex');
  return safeCompare(calculatedHash, hash);
}

function verifyAdminPassword(password) {
  if (ADMIN_PASSWORD_HASH) {
    return verifyPasswordHash(password, ADMIN_PASSWORD_HASH);
  }

  return safeCompare(password, ADMIN_PASSWORD);
}

function productionConfigError() {
  if (!IS_PRODUCTION) return '';

  if (ADMIN_USERNAME === 'admin') return 'ADMIN_USERNAME doit être changé en production.';
  if (!ADMIN_PASSWORD_HASH && ADMIN_PASSWORD === 'admin123') return 'ADMIN_PASSWORD_HASH ou ADMIN_PASSWORD doit être changé en production.';
  if (!SESSION_SECRET || SESSION_SECRET === 'dev-session-secret' || SESSION_SECRET.length < 32) return 'SESSION_SECRET doit contenir au moins 32 caractères en production.';

  return '';
}

function base64UrlEncode(value) {
  return Buffer.from(value).toString('base64url');
}

function base64UrlDecode(value) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url');
}

function createSessionCookie(username) {
  const payload = base64UrlEncode(JSON.stringify({ username, exp: Date.now() + SESSION_TTL_MS }));
  const signature = sign(payload);
  return `admin_session=${payload}.${signature}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}${IS_PRODUCTION ? '; Secure' : ''}`;
}

function clearSessionCookie() {
  return `admin_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax${IS_PRODUCTION ? '; Secure' : ''}`;
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

function requireAdmin(event) {
  if (isAdmin(event)) return null;

  if ((event.headers.accept || '').includes('application/json')) {
    return json(401, { ok: false, message: 'Connexion administrateur requise.' });
  }

  return redirect('/admin/login');
}

function clientIp(event) {
  return String(
    event.headers['x-nf-client-connection-ip'] ||
    event.headers['client-ip'] ||
    event.headers['x-forwarded-for'] ||
    'unknown'
  ).split(',')[0].trim();
}

async function readLoginAttempt(event) {
  const key = `login-attempt-${crypto.createHash('sha256').update(clientIp(event)).digest('hex')}`;
  const attempt = await dataStore.get(key, { type: 'json' });
  return { key, attempt: attempt || null };
}

async function isLoginBlocked(event) {
  const { key, attempt } = await readLoginAttempt(event);
  if (!attempt) return false;

  if (attempt.resetAt <= Date.now()) {
    await dataStore.delete(key);
    return false;
  }

  return attempt.count >= LOGIN_MAX_ATTEMPTS;
}

async function recordLoginFailure(event) {
  const { key, attempt } = await readLoginAttempt(event);
  const now = Date.now();

  if (!attempt || attempt.resetAt <= now) {
    await dataStore.set(key, JSON.stringify({ count: 1, resetAt: now + LOGIN_WINDOW_MS }));
    return;
  }

  await dataStore.set(key, JSON.stringify({ count: attempt.count + 1, resetAt: attempt.resetAt }));
}

async function clearLoginFailures(event) {
  const { key } = await readLoginAttempt(event);
  await dataStore.delete(key);
}

async function readJson(key) {
  const value = await dataStore.get(key, { type: 'json' });
  return Array.isArray(value) ? value : [];
}

async function writeJson(key, items) {
  await dataStore.set(key, JSON.stringify(items));
}

async function appendJson(key, entry) {
  const items = await readJson(key);
  const item = {
    id: crypto.randomUUID(),
    ...entry,
    createdAt: new Date().toISOString()
  };
  items.push(item);
  await writeJson(key, items);
  return item;
}

async function deleteJsonEntry(key, id) {
  const items = await readJson(key);
  await writeJson(key, items.filter((item) => item.id !== id));
}

function readBody(event) {
  const raw = event.isBase64Encoded ? Buffer.from(event.body || '', 'base64').toString('utf8') : (event.body || '');
  const contentType = event.headers['content-type'] || event.headers['Content-Type'] || '';

  if (contentType.includes('application/json')) {
    return JSON.parse(raw || '{}');
  }

  return Object.fromEntries(new URLSearchParams(raw).entries());
}

function parseMultipart(event) {
  const contentType = event.headers['content-type'] || event.headers['Content-Type'] || '';
  const boundaryMatch = contentType.match(/boundary=(?:(?:"([^"]+)")|([^;]+))/i);

  if (!boundaryMatch) throw new Error('Boundary multipart manquant.');

  const bodyBuffer = event.isBase64Encoded ? Buffer.from(event.body || '', 'base64') : Buffer.from(event.body || '', 'utf8');
  if (bodyBuffer.length > MAX_BODY_SIZE) throw new Error('Fichier trop volumineux.');

  const boundary = boundaryMatch[1] || boundaryMatch[2];
  const body = bodyBuffer.toString('latin1');
  const parts = body.split(`--${boundary}`).slice(1, -1);
  const fields = {};
  const files = {};

  for (let part of parts) {
    part = part.replace(/^\r\n/, '').replace(/\r\n$/, '');
    const separatorIndex = part.indexOf('\r\n\r\n');
    if (separatorIndex === -1) continue;

    const rawHeaders = part.slice(0, separatorIndex);
    let content = part.slice(separatorIndex + 4).replace(/\r\n$/, '');
    const nameMatch = rawHeaders.match(/name="([^"]+)"/i);
    if (!nameMatch) continue;

    const name = nameMatch[1];
    const filenameMatch = rawHeaders.match(/filename="([^"]*)"/i);
    const typeMatch = rawHeaders.match(/Content-Type:\s*([^\r\n]+)/i);

    if (filenameMatch && filenameMatch[1]) {
      files[name] = {
        filename: filenameMatch[1],
        contentType: typeMatch ? typeMatch[1].trim() : 'application/octet-stream',
        buffer: Buffer.from(content, 'latin1')
      };
    } else {
      fields[name] = Buffer.from(content, 'latin1').toString('utf8').trim();
    }
  }

  return { fields, files };
}

function parseRequestFields(event) {
  const contentType = event.headers['content-type'] || event.headers['Content-Type'] || '';

  if (contentType.includes('multipart/form-data')) {
    return parseMultipart(event);
  }

  return { fields: readBody(event), files: {} };
}

function sanitizeFileName(fileName) {
  return String(fileName || 'file').replace(/[^a-zA-Z0-9._-]/g, '-');
}

async function saveUpload(publicDir, file) {
  if (!file || !file.buffer || file.buffer.length === 0) throw new Error('Fichier vide.');

  const fileName = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}-${sanitizeFileName(file.filename)}`;
  const key = `${publicDir}/${fileName}`;
  await mediaStore.set(key, file.buffer, { metadata: { contentType: file.contentType } });
  return { fileName, publicPath: `/uploads/${key}` };
}

async function deleteUploadedFile(publicPath) {
  if (!publicPath || !publicPath.startsWith('/uploads/')) return;
  await mediaStore.delete(publicPath.replace('/uploads/', ''));
}

function truncate(value, maxLength) {
  return String(value || '').trim().slice(0, maxLength);
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function isValidUrl(value) {
  if (!value) return true;

  try {
    const url = new URL(value);
    return url.protocol === 'https:' || (!IS_PRODUCTION && url.protocol === 'http:');
  } catch (_error) {
    return false;
  }
}

function routePath(event) {
  const path = event.path || '';
  const marker = '/api';
  const index = path.indexOf(marker);
  return index >= 0 ? path.slice(index + marker.length) || '/' : `/${event.pathParameters?.splat || ''}`;
}

async function handleContact(event) {
  const { name, email, subject, message } = readBody(event);
  const cleanName = truncate(name, 120);
  const cleanEmail = normalizeEmail(email);
  const cleanSubject = truncate(subject, 80);
  const cleanMessage = truncate(message, 5000);

  if (!cleanName || !cleanEmail || !cleanSubject || !cleanMessage || !emailPattern.test(cleanEmail) || !allowedSubjects.has(cleanSubject)) {
    return redirectOrJson(event, { ok: false, message: 'Le formulaire contient une information invalide.' }, '/contact?erreur=formulaire');
  }

  await appendJson('messages', { name: cleanName, email: cleanEmail, subject: cleanSubject, message: cleanMessage });
  return redirectOrJson(event, { ok: true, message: 'Votre message a bien ete envoye.' });
}

async function handleNewsletter(event) {
  const { email } = readBody(event);
  const cleanEmail = normalizeEmail(email);

  if (!cleanEmail || !emailPattern.test(cleanEmail)) {
    return redirectOrJson(event, { ok: false, message: 'Merci de renseigner une adresse e-mail valide.' }, '/?erreur=newsletter');
  }

  await appendJson('newsletter', { email: cleanEmail });
  return redirectOrJson(event, { ok: true, message: 'Votre inscription a bien ete prise en compte.' });
}

async function handleAdminLogin(event) {
  const configError = productionConfigError();
  if (configError) return redirect(`/admin/login?erreur=${encodeURIComponent(configError)}`);

  if (await isLoginBlocked(event)) return redirect('/admin/login?erreur=limite');

  const { username, password } = readBody(event);

  if (username !== ADMIN_USERNAME || !verifyAdminPassword(password)) {
    await recordLoginFailure(event);
    return redirect('/admin/login?erreur=connexion');
  }

  await clearLoginFailures(event);
  return redirect('/admin', { 'Set-Cookie': createSessionCookie(ADMIN_USERNAME) });
}

function handleAdminLogout() {
  return redirect('/admin/login', { 'Set-Cookie': clearSessionCookie() });
}

async function handleAdminData(event) {
  const denied = requireAdmin(event);
  if (denied) return denied;

  const [messages, newsletter, sermons] = await Promise.all([
    readJson('messages'),
    readJson('newsletter'),
    readJson('sermons')
  ]);

  return json(200, {
    ok: true,
    messages: messages.slice().reverse(),
    newsletter: newsletter.slice().reverse(),
    sermons: sermons.slice().reverse()
  });
}

async function handleAdminDelete(event, key) {
  const denied = requireAdmin(event);
  if (denied) return denied;

  const { id } = readBody(event);
  if (!id) return json(400, { ok: false, message: 'Identifiant manquant.' });

  await deleteJsonEntry(key, id);
  return json(200, { ok: true });
}

async function handleSermons() {
  const sermons = await readJson('sermons');
  return json(200, { ok: true, sermons: sermons.slice().reverse() });
}

async function handleAdminCreateSermon(event) {
  const denied = requireAdmin(event);
  if (denied) return denied;

  const { fields, files } = parseRequestFields(event);
  const title = truncate(fields.title, 160);
  const speaker = truncate(fields.speaker, 120);
  const theme = truncate(fields.theme, 60);
  const date = truncate(fields.date, 20);
  const description = truncate(fields.description, 6000);
  const audioUrl = truncate(fields.audioUrl, 1000);
  const imageUrl = truncate(fields.imageUrl, 1000);
  let audioPath = audioUrl;
  let imagePath = imageUrl;
  let audioFileName = '';
  let imageFileName = '';

  if (!title || !speaker || !theme || !date) return json(400, { ok: false, message: 'Titre, prédicateur, thème et date sont obligatoires.' });
  if (!allowedThemes.has(theme)) return json(400, { ok: false, message: 'Thème invalide.' });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return json(400, { ok: false, message: 'Date invalide.' });
  if (!isValidUrl(audioUrl) || !isValidUrl(imageUrl)) return json(400, { ok: false, message: 'Les liens externes doivent être en HTTPS.' });

  if (files.audio && files.audio.buffer.length > 0) {
    const ext = `.${files.audio.filename.split('.').pop().toLowerCase()}`;
    if (!allowedAudioExtensions.has(ext) || !files.audio.contentType.startsWith('audio/')) return json(400, { ok: false, message: 'Format audio non accepté.' });
    const upload = await saveUpload('audio', files.audio);
    audioPath = upload.publicPath;
    audioFileName = upload.fileName;
  }

  if (files.image && files.image.buffer.length > 0) {
    const ext = `.${files.image.filename.split('.').pop().toLowerCase()}`;
    if (!allowedImageExtensions.has(ext) || !files.image.contentType.startsWith('image/')) return json(400, { ok: false, message: 'Format image non accepté.' });
    const upload = await saveUpload('images', files.image);
    imagePath = upload.publicPath;
    imageFileName = upload.fileName;
  }

  const sermon = await appendJson('sermons', { title, speaker, theme, date, description, audioPath, audioFileName, imagePath, imageFileName });
  return json(200, { ok: true, sermon, message: 'La prédication a bien été publiée.' });
}

async function handleAdminDeleteSermon(event) {
  const denied = requireAdmin(event);
  if (denied) return denied;

  const { id } = readBody(event);
  const sermons = await readJson('sermons');
  const sermon = sermons.find((item) => item.id === id);
  if (!sermon) return json(404, { ok: false, message: 'Prédication introuvable.' });

  await deleteJsonEntry('sermons', id);
  await deleteUploadedFile(sermon.audioPath);
  await deleteUploadedFile(sermon.imagePath);
  return json(200, { ok: true });
}

exports.handler = async (event) => {
  try {
    if (!['GET', 'POST'].includes(event.httpMethod)) return json(405, { ok: false, message: 'Méthode non autorisée.' });

    const path = routePath(event);

    if (event.httpMethod === 'GET' && path === '/health') return json(200, { ok: true, service: 'AD Hedomey Netlify backend' });
    if (event.httpMethod === 'GET' && path === '/sermons') return await handleSermons();
    if (event.httpMethod === 'POST' && path === '/contact') return await handleContact(event);
    if (event.httpMethod === 'POST' && path === '/newsletter') return await handleNewsletter(event);
    if (event.httpMethod === 'POST' && path === '/admin/login') return await handleAdminLogin(event);
    if (event.httpMethod === 'POST' && path === '/admin/logout') return handleAdminLogout();
    if (event.httpMethod === 'GET' && path === '/admin/data') return await handleAdminData(event);
    if (event.httpMethod === 'POST' && path === '/admin/sermons') return await handleAdminCreateSermon(event);
    if (event.httpMethod === 'POST' && path === '/admin/sermons/delete') return await handleAdminDeleteSermon(event);
    if (event.httpMethod === 'POST' && path === '/admin/messages/delete') return await handleAdminDelete(event, 'messages');
    if (event.httpMethod === 'POST' && path === '/admin/newsletter/delete') return await handleAdminDelete(event, 'newsletter');

    return json(404, { ok: false, message: 'Route API introuvable.' });
  } catch (error) {
    console.error(error);
    return json(500, { ok: false, message: 'Une erreur serveur est survenue.' });
  }
};

exports.createPasswordHash = createPasswordHash;
