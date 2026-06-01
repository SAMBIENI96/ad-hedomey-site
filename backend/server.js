const http = require('http');
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');
const { URLSearchParams } = require('url');

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PRODUCTION = NODE_ENV === 'production';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || '';
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 1000 * 60 * 60 * 8);
const MAX_BODY_SIZE = Number(process.env.MAX_BODY_SIZE || 50 * 1024 * 1024);
const LOGIN_WINDOW_MS = Number(process.env.LOGIN_WINDOW_MS || 1000 * 60 * 15);
const LOGIN_MAX_ATTEMPTS = Number(process.env.LOGIN_MAX_ATTEMPTS || 5);
const rootDir = path.resolve(__dirname, '..');
const frontEndDir = path.join(rootDir, 'front-end');
const dataDir = path.join(__dirname, 'data');
const uploadsDir = path.join(rootDir, 'uploads');
const audioUploadDir = path.join(uploadsDir, 'audio');
const imageUploadDir = path.join(uploadsDir, 'images');
const sessions = new Map();
const loginAttempts = new Map();

if (process.argv[2] === '--hash-password') {
  const password = process.argv[3];
  if (!password) {
    console.error('Usage: node backend/server.js --hash-password "votre_mot_de_passe"');
    process.exit(1);
  }
  console.log(createPasswordHash(password));
  process.exit(0);
}

const routes = {
  '/': path.join(rootDir, 'index.html'),
  '/index.html': path.join(rootDir, 'index.html'),
  '/predications': path.join(frontEndDir, 'predication.html'),
  '/predication-detail': path.join(frontEndDir, 'predication-detail.html'),
  '/apropos': path.join(frontEndDir, 'apropos.html'),
  '/contact': path.join(frontEndDir, 'contact.html'),
  '/merci': path.join(frontEndDir, 'merci.html')
};

const allowedAudioExtensions = new Set(['.mp3', '.m4a', '.wav', '.ogg', '.webm', '.aac']);
const allowedImageExtensions = new Set(['.jpg', '.jpeg', '.png', '.webp', '.gif', '.avif']);
const allowedThemes = new Set(['Foi', 'Prière', 'Saint-Esprit', 'Mission', 'Enseignement']);
const allowedSubjects = new Set(['prière', 'témoignage', 'information', 'autre']);
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.avif': 'image/avif',
  '.ico': 'image/x-icon',
  '.mp3': 'audio/mpeg',
  '.m4a': 'audio/mp4',
  '.wav': 'audio/wav',
  '.ogg': 'audio/ogg',
  '.webm': 'audio/webm',
  '.aac': 'audio/aac'
};

function securityHeaders(extraHeaders = {}) {
  const headers = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Cross-Origin-Resource-Policy': 'same-origin',
    ...extraHeaders
  };

  if (IS_PRODUCTION) {
    headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  }

  return headers;
}

function send(res, statusCode, body, contentType = 'text/plain; charset=utf-8', headers = {}) {
  res.writeHead(statusCode, securityHeaders({ 'Content-Type': contentType, ...headers }));
  res.end(body);
}

function sendJson(res, statusCode, payload) {
  send(res, statusCode, JSON.stringify(payload), 'application/json; charset=utf-8');
}

function redirect(res, location, headers = {}) {
  res.writeHead(303, securityHeaders({ Location: location, ...headers }));
  res.end();
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

function requireProductionConfig() {
  if (!IS_PRODUCTION) return;

  const usesDefaultUsername = ADMIN_USERNAME === 'admin';
  const usesDefaultPassword = !ADMIN_PASSWORD_HASH && ADMIN_PASSWORD === 'admin123';

  if (usesDefaultUsername || usesDefaultPassword) {
    console.error('Production bloquée: définissez ADMIN_USERNAME et ADMIN_PASSWORD_HASH ou ADMIN_PASSWORD avant de démarrer.');
    process.exit(1);
  }
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

function truncate(value, maxLength) {
  return String(value || '').trim().slice(0, maxLength);
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

async function sendFile(res, filePath, statusCode = 200) {
  const content = await fs.readFile(filePath);
  const type = mimeTypes[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
  const cacheHeader = filePath.startsWith(uploadsDir) ? 'public, max-age=31536000, immutable' : 'no-store';
  res.writeHead(statusCode, securityHeaders({ 'Content-Type': type, 'Cache-Control': cacheHeader }));
  res.end(content);
}

async function readJson(fileName) {
  try {
    const filePath = path.join(dataDir, fileName);
    const content = await fs.readFile(filePath, 'utf8');
    const items = JSON.parse(content);
    return Array.isArray(items) ? items : [];
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

async function writeJson(fileName, items) {
  await fs.mkdir(dataDir, { recursive: true });
  const filePath = path.join(dataDir, fileName);
  await fs.writeFile(filePath, JSON.stringify(items, null, 2), 'utf8');
}

async function appendJson(fileName, entry) {
  const items = await readJson(fileName);
  const item = {
    id: crypto.randomUUID(),
    ...entry,
    createdAt: new Date().toISOString()
  };
  items.push(item);
  await writeJson(fileName, items);
  return item;
}

async function deleteJsonEntry(fileName, id) {
  const items = await readJson(fileName);
  const filtered = items.filter((item) => item.id !== id);
  await writeJson(fileName, filtered);
}

function wantsJson(req) {
  return req.headers.accept && req.headers.accept.includes('application/json');
}

function redirectOrJson(req, res, payload, redirectPath = '/merci') {
  if (wantsJson(req)) {
    return sendJson(res, payload.ok ? 200 : 400, payload);
  }

  return redirect(res, redirectPath);
}

function parseCookies(req) {
  const cookieHeader = req.headers.cookie || '';
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

function getSessionToken(req) {
  return parseCookies(req).admin_session;
}

function isAdmin(req) {
  const token = getSessionToken(req);
  if (!token) return false;

  const session = sessions.get(token);

  if (!session) return false;

  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return false;
  }

  session.expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(token, session);
  return true;
}

function requireAdmin(req, res) {
  if (isAdmin(req)) return true;

  if (wantsJson(req)) {
    sendJson(res, 401, { ok: false, message: 'Connexion administrateur requise.' });
  } else {
    redirect(res, '/admin/login');
  }

  return false;
}

function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
}

function isLoginBlocked(req) {
  const key = clientIp(req);
  const attempt = loginAttempts.get(key);

  if (!attempt) return false;

  if (attempt.resetAt <= Date.now()) {
    loginAttempts.delete(key);
    return false;
  }

  return attempt.count >= LOGIN_MAX_ATTEMPTS;
}

function recordLoginFailure(req) {
  const key = clientIp(req);
  const current = loginAttempts.get(key);
  const now = Date.now();

  if (!current || current.resetAt <= now) {
    loginAttempts.set(key, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    return;
  }

  current.count += 1;
  loginAttempts.set(key, current);
}

function clearLoginFailures(req) {
  loginAttempts.delete(clientIp(req));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';

    req.on('data', (chunk) => {
      body += chunk.toString();
      if (body.length > 1_000_000) {
        req.destroy();
        reject(new Error('Requete trop volumineuse.'));
      }
    });

    req.on('end', () => {
      const contentType = req.headers['content-type'] || '';

      if (contentType.includes('application/json')) {
        try {
          return resolve(JSON.parse(body || '{}'));
        } catch (error) {
          return reject(error);
        }
      }

      const params = new URLSearchParams(body);
      return resolve(Object.fromEntries(params.entries()));
    });

    req.on('error', reject);
  });
}

function readRawBody(req, limit = MAX_BODY_SIZE) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        req.destroy();
        reject(new Error('Fichier trop volumineux.'));
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function parseMultipart(req) {
  const contentType = req.headers['content-type'] || '';
  const boundaryMatch = contentType.match(/boundary=(?:(?:"([^"]+)")|([^;]+))/i);

  if (!boundaryMatch) {
    throw new Error('Boundary multipart manquant.');
  }

  const boundary = boundaryMatch[1] || boundaryMatch[2];
  const rawBody = await readRawBody(req);
  const body = rawBody.toString('latin1');
  const parts = body.split(`--${boundary}`).slice(1, -1);
  const fields = {};
  const files = {};

  for (let part of parts) {
    part = part.replace(/^\r\n/, '').replace(/\r\n$/, '');
    const separatorIndex = part.indexOf('\r\n\r\n');
    if (separatorIndex === -1) continue;

    const rawHeaders = part.slice(0, separatorIndex);
    let content = part.slice(separatorIndex + 4);
    content = content.replace(/\r\n$/, '');

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

function sanitizeFileName(fileName) {
  return path.basename(fileName).replace(/[^a-zA-Z0-9._-]/g, '-');
}

async function saveUpload(uploadDir, publicDir, file) {
  if (!file || !file.buffer || file.buffer.length === 0) {
    throw new Error('Fichier vide.');
  }

  await fs.mkdir(uploadDir, { recursive: true });
  const fileName = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}-${sanitizeFileName(file.filename)}`;
  await fs.writeFile(path.join(uploadDir, fileName), file.buffer);
  return {
    fileName,
    publicPath: `${publicDir}/${fileName}`
  };
}

async function deleteUploadedFile(publicPath) {
  if (!publicPath || !publicPath.startsWith('/uploads/')) return;

  const uploadPath = path.join(rootDir, publicPath);
  const relativeToUploads = path.relative(uploadsDir, uploadPath);

  if (relativeToUploads && !relativeToUploads.startsWith('..') && !path.isAbsolute(relativeToUploads)) {
    await fs.rm(uploadPath, { force: true });
  }
}

async function parseRequestFields(req) {
  const contentType = req.headers['content-type'] || '';

  if (contentType.includes('multipart/form-data')) {
    return await parseMultipart(req);
  }

  return { fields: await readBody(req), files: {} };
}

async function handleContact(req, res) {
  const { name, email, subject, message } = await readBody(req);
  const cleanName = truncate(name, 120);
  const cleanEmail = normalizeEmail(email);
  const cleanSubject = truncate(subject, 80);
  const cleanMessage = truncate(message, 5000);

  if (!cleanName || !cleanEmail || !cleanSubject || !cleanMessage) {
    return redirectOrJson(req, res, {
      ok: false,
      message: 'Merci de remplir tous les champs du formulaire.'
    }, '/contact?erreur=formulaire');
  }

  if (!emailPattern.test(cleanEmail) || !allowedSubjects.has(cleanSubject)) {
    return redirectOrJson(req, res, {
      ok: false,
      message: 'Le formulaire contient une information invalide.'
    }, '/contact?erreur=formulaire');
  }

  await appendJson('messages.json', {
    name: cleanName,
    email: cleanEmail,
    subject: cleanSubject,
    message: cleanMessage
  });

  return redirectOrJson(req, res, {
    ok: true,
    message: 'Votre message a bien ete envoye.'
  });
}

async function handleNewsletter(req, res) {
  const { email } = await readBody(req);
  const cleanEmail = normalizeEmail(email);

  if (!cleanEmail || !emailPattern.test(cleanEmail)) {
    return redirectOrJson(req, res, {
      ok: false,
      message: 'Merci de renseigner votre adresse e-mail.'
    }, '/?erreur=newsletter');
  }

  await appendJson('newsletter.json', {
    email: cleanEmail
  });

  return redirectOrJson(req, res, {
    ok: true,
    message: 'Votre inscription a bien ete prise en compte.'
  });
}

async function handleAdminLogin(req, res) {
  if (isLoginBlocked(req)) {
    return redirect(res, '/admin/login?erreur=limite');
  }

  const { username, password } = await readBody(req);

  if (username !== ADMIN_USERNAME || !verifyAdminPassword(password)) {
    recordLoginFailure(req);
    return redirect(res, '/admin/login?erreur=connexion');
  }

  clearLoginFailures(req);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    username: ADMIN_USERNAME,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS
  });

  return redirect(res, '/admin', {
    'Set-Cookie': `admin_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}${IS_PRODUCTION ? '; Secure' : ''}`
  });
}

function handleAdminLogout(req, res) {
  const token = getSessionToken(req);
  if (token) sessions.delete(token);

  return redirect(res, '/admin/login', {
    'Set-Cookie': `admin_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax${IS_PRODUCTION ? '; Secure' : ''}`
  });
}

async function handleAdminData(req, res) {
  if (!requireAdmin(req, res)) return;

  const [messages, newsletter, sermons] = await Promise.all([
    readJson('messages.json'),
    readJson('newsletter.json'),
    readJson('sermons.json')
  ]);

  return sendJson(res, 200, {
    ok: true,
    messages: messages.slice().reverse(),
    newsletter: newsletter.slice().reverse(),
    sermons: sermons.slice().reverse()
  });
}

async function handleAdminDelete(req, res, fileName) {
  if (!requireAdmin(req, res)) return;

  const { id } = await readBody(req);

  if (!id) {
    return sendJson(res, 400, { ok: false, message: 'Identifiant manquant.' });
  }

  await deleteJsonEntry(fileName, id);
  return sendJson(res, 200, { ok: true });
}

async function handleSermons(_req, res) {
  const sermons = await readJson('sermons.json');
  return sendJson(res, 200, {
    ok: true,
    sermons: sermons.slice().reverse()
  });
}

async function handleAdminCreateSermon(req, res) {
  if (!requireAdmin(req, res)) return;

  const { fields, files } = await parseRequestFields(req);
  const title = truncate(fields.title, 160);
  const speaker = truncate(fields.speaker, 120);
  const theme = truncate(fields.theme, 60);
  const date = truncate(fields.date, 20);
  const description = truncate(fields.description, 6000);
  const audioUrl = truncate(fields.audioUrl, 1000);
  const imageUrl = truncate(fields.imageUrl, 1000);
  const audioFile = files.audio;
  const imageFile = files.image;
  let audioPath = audioUrl;
  let audioFileName = '';
  let imagePath = imageUrl;
  let imageFileName = '';

  if (!title || !speaker || !theme || !date) {
    return sendJson(res, 400, {
      ok: false,
      message: 'Titre, prédicateur, thème et date sont obligatoires.'
    });
  }

  if (!allowedThemes.has(theme)) {
    return sendJson(res, 400, {
      ok: false,
      message: 'Thème invalide.'
    });
  }

  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return sendJson(res, 400, {
      ok: false,
      message: 'Date invalide.'
    });
  }

  if (!isValidUrl(audioUrl) || !isValidUrl(imageUrl)) {
    return sendJson(res, 400, {
      ok: false,
      message: 'Les liens externes doivent être en HTTPS.'
    });
  }

  if (audioFile && audioFile.buffer.length > 0) {
    const ext = path.extname(audioFile.filename).toLowerCase();

    if (!allowedAudioExtensions.has(ext) || !audioFile.contentType.startsWith('audio/')) {
      return sendJson(res, 400, {
        ok: false,
        message: 'Format audio non accepté. Utilisez mp3, m4a, wav, ogg, webm ou aac.'
      });
    }

    const upload = await saveUpload(audioUploadDir, '/uploads/audio', audioFile);
    audioFileName = upload.fileName;
    audioPath = upload.publicPath;
  }

  if (imageFile && imageFile.buffer.length > 0) {
    const ext = path.extname(imageFile.filename).toLowerCase();

    if (!allowedImageExtensions.has(ext) || !imageFile.contentType.startsWith('image/')) {
      return sendJson(res, 400, {
        ok: false,
        message: 'Format image non accepté. Utilisez jpg, png, webp, gif ou avif.'
      });
    }

    const upload = await saveUpload(imageUploadDir, '/uploads/images', imageFile);
    imageFileName = upload.fileName;
    imagePath = upload.publicPath;
  }

  const sermon = await appendJson('sermons.json', {
    title,
    speaker,
    theme,
    date,
    description,
    audioPath,
    audioFileName,
    imagePath,
    imageFileName
  });

  return sendJson(res, 200, {
    ok: true,
    sermon,
    message: 'La prédication a bien été publiée.'
  });
}

async function handleAdminDeleteSermon(req, res) {
  if (!requireAdmin(req, res)) return;

  const { id } = await readBody(req);
  const sermons = await readJson('sermons.json');
  const sermon = sermons.find((item) => item.id === id);

  if (!sermon) {
    return sendJson(res, 404, { ok: false, message: 'Prédication introuvable.' });
  }

  await deleteJsonEntry('sermons.json', id);

  await deleteUploadedFile(sermon.audioPath);
  await deleteUploadedFile(sermon.imagePath);

  return sendJson(res, 200, { ok: true });
}

async function serveStaticPath(pathname, res) {
  const decodedPath = decodeURIComponent(pathname);
  const filePath = path.normalize(path.join(rootDir, decodedPath));
  const relativeToFrontEnd = path.relative(frontEndDir, filePath);
  const relativeToUploads = path.relative(uploadsDir, filePath);
  const isFrontEndFile = relativeToFrontEnd && !relativeToFrontEnd.startsWith('..') && !path.isAbsolute(relativeToFrontEnd);
  const isUploadsFile = relativeToUploads && !relativeToUploads.startsWith('..') && !path.isAbsolute(relativeToUploads);
  const isHomeFile = filePath === path.join(rootDir, 'index.html');

  if (!filePath.startsWith(rootDir) || (!isFrontEndFile && !isUploadsFile && !isHomeFile)) {
    return false;
  }

  try {
    const stats = await fs.stat(filePath);
    if (!stats.isFile()) return false;
    await sendFile(res, filePath);
    return true;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return false;
  }
}

const server = http.createServer(async (req, res) => {
  try {
    if (!['GET', 'POST'].includes(req.method)) {
      return sendJson(res, 405, { ok: false, message: 'Méthode non autorisée.' });
    }

    const requestUrl = new URL(req.url, `http://${req.headers.host}`);
    const pathname = requestUrl.pathname;

    if (req.method === 'GET' && pathname === '/api/health') {
      return sendJson(res, 200, { ok: true, service: 'AD Hedomey backend' });
    }

    if (req.method === 'GET' && pathname === '/api/sermons') {
      return await handleSermons(req, res);
    }

    if (req.method === 'POST' && pathname === '/api/contact') {
      return await handleContact(req, res);
    }

    if (req.method === 'POST' && pathname === '/api/newsletter') {
      return await handleNewsletter(req, res);
    }

    if (req.method === 'GET' && pathname === '/admin/login') {
      if (isAdmin(req)) return redirect(res, '/admin');
      return await sendFile(res, path.join(frontEndDir, 'admin-login.html'));
    }

    if (req.method === 'POST' && (pathname === '/admin/login' || pathname === '/api/admin/login')) {
      return await handleAdminLogin(req, res);
    }

    if (req.method === 'POST' && (pathname === '/admin/logout' || pathname === '/api/admin/logout')) {
      return handleAdminLogout(req, res);
    }

    if (req.method === 'GET' && pathname === '/admin') {
      if (!requireAdmin(req, res)) return;
      return await sendFile(res, path.join(frontEndDir, 'admin.html'));
    }

    if (req.method === 'GET' && pathname === '/api/admin/data') {
      return await handleAdminData(req, res);
    }

    if (req.method === 'POST' && pathname === '/api/admin/sermons') {
      return await handleAdminCreateSermon(req, res);
    }

    if (req.method === 'POST' && pathname === '/api/admin/sermons/delete') {
      return await handleAdminDeleteSermon(req, res);
    }

    if (req.method === 'POST' && pathname === '/api/admin/messages/delete') {
      return await handleAdminDelete(req, res, 'messages.json');
    }

    if (req.method === 'POST' && pathname === '/api/admin/newsletter/delete') {
      return await handleAdminDelete(req, res, 'newsletter.json');
    }

    if (req.method === 'GET' && routes[pathname]) {
      return await sendFile(res, routes[pathname]);
    }

    if (req.method === 'GET' && await serveStaticPath(pathname, res)) {
      return;
    }

    return await sendFile(res, path.join(frontEndDir, '404.html'), 404);
  } catch (error) {
    console.error(error);
    return sendJson(res, 500, {
      ok: false,
      message: 'Une erreur serveur est survenue.'
    });
  }
});

requireProductionConfig();

server.listen(PORT, () => {
  console.log(`Serveur AD Hedomey lance sur http://localhost:${PORT}`);
  console.log(`Admin: http://localhost:${PORT}/admin`);
  console.log(`Mode: ${NODE_ENV}`);
});
