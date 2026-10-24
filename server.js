import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  consumeRecoveryCode,
  createRecoveryCodes,
  decryptTotpSecret,
  encryptTotpSecret,
  hashPassword,
  matchingTotpCounter,
  parseEncryptionKey,
  randomTotpSecret,
  verifyPassword,
} from './server/auth-core.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_ROOT = path.join(ROOT, 'public');
let AUTH_FILE = path.join(ROOT, '.radar-auth.json');
const SESSION_COOKIE = 'radar_session';
const CHALLENGE_COOKIE = 'radar_challenge';
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_BODY_BYTES = 16 * 1024;
const FAILURE_LIMIT = 6;
const FAILURE_WINDOW_MS = 15 * 60 * 1000;
const MIME_TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.json', 'application/json; charset=utf-8'],
  ['.png', 'image/png'],
  ['.svg', 'image/svg+xml'],
]);

const failures = new Map();
const challenges = new Map();
const sessions = new Map();
let authRecord;
let encryptionKey;
let totpSecret = null;
let verificationInProgress = false;

async function loadEnvFile() {
  let contents;
  try {
    contents = await readFile(path.join(ROOT, '.env'), 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  for (const line of contents.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match || process.env[match[1]] !== undefined) continue;
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    process.env[match[1]] = value;
  }
}

async function persistAuthRecord(record) {
  const temporaryFile = `${AUTH_FILE}.tmp`;
  await writeFile(temporaryFile, `${JSON.stringify(record, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'w' });
  await rename(temporaryFile, AUTH_FILE);
  authRecord = record;
}

async function initializeAuth() {
  AUTH_FILE = path.resolve(process.env.RADAR_AUTH_FILE || AUTH_FILE);
  encryptionKey = parseEncryptionKey(process.env.RADAR_ENCRYPTION_KEY);
  try {
    authRecord = JSON.parse(await readFile(AUTH_FILE, 'utf8'));
    if (typeof authRecord.username !== 'string'
      || typeof authRecord.passwordSalt !== 'string'
      || typeof authRecord.passwordHash !== 'string'
      || !Array.isArray(authRecord.recoveryHashes)
      || (authRecord.lastTotpCounter !== undefined && !/^\d+$/.test(authRecord.lastTotpCounter))) {
      throw new Error('Файл .radar-auth.json имеет неверную структуру.');
    }
    if (authRecord.totpSecret) totpSecret = decryptTotpSecret(authRecord.totpSecret, encryptionKey);
    return;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const username = process.env.RADAR_ADMIN_USERNAME?.trim();
  const password = process.env.RADAR_ADMIN_PASSWORD;
  if (!username || username.length > 64 || !/^[A-Za-z0-9._@-]{3,64}$/.test(username)) {
    throw new Error('Задайте RADAR_ADMIN_USERNAME (3–64 символа: латиница, цифры, . _ @ -) в .env.');
  }
  const passwordCredentials = hashPassword(password);
  await persistAuthRecord({
    username,
    ...{ passwordSalt: passwordCredentials.salt, passwordHash: passwordCredentials.hash },
    totpSecret: null,
    recoveryHashes: [],
  });
  console.log('Создана первая учётная запись. При первом входе потребуется привязать приложение-аутентификатор.');
}

function getCookies(request) {
  const cookies = new Map();
  for (const part of (request.headers.cookie || '').split(';')) {
    const separator = part.indexOf('=');
    if (separator > 0) {
      try {
        cookies.set(part.slice(0, separator).trim(), decodeURIComponent(part.slice(separator + 1).trim()));
      } catch {
        continue;
      }
    }
  }
  return cookies;
}

function setCookie(response, name, value, maxAge, secure) {
  const attributes = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAge}`,
  ];
  if (secure) attributes.push('Secure');
  const existing = response.getHeader('Set-Cookie');
  response.setHeader('Set-Cookie', [
    ...(Array.isArray(existing) ? existing : existing ? [existing] : []),
    attributes.join('; '),
  ]);
}

function clearCookie(response, name, secure) {
  setCookie(response, name, '', 0, secure);
}

function sendJson(response, status, body, headers = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  response.end(JSON.stringify(body));
}

function requestIsSameOrigin(request) {
  const origin = request.headers.origin;
  const host = request.headers.host;
  if (typeof origin !== 'string' || typeof host !== 'string') return false;
  try {
    const parsed = new URL(origin);
    return ['http:', 'https:'].includes(parsed.protocol) && parsed.host === host;
  } catch {
    return false;
  }
}

async function readJsonBody(request) {
  if (!request.headers['content-type']?.toLowerCase().startsWith('application/json')) {
    throw Object.assign(new Error('Ожидается JSON-запрос.'), { statusCode: 415 });
  }
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw Object.assign(new Error('Слишком большой запрос.'), { statusCode: 413 });
    chunks.push(chunk);
  }
  let body;
  try {
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw Object.assign(new Error('Некорректный JSON.'), { statusCode: 400 });
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw Object.assign(new Error('Ожидается JSON-объект.'), { statusCode: 400 });
  }
  return body;
}

function getClientAddress(request) {
  return request.socket.remoteAddress || 'unknown';
}

function isRateLimited(keys, now = Date.now()) {
  let limited = false;
  for (const key of keys) {
    const entry = failures.get(key);
    if (!entry || entry.resetAt <= now) {
      failures.delete(key);
      continue;
    }
    if (entry.count >= FAILURE_LIMIT) limited = true;
  }
  return limited;
}

function recordFailure(keys, now = Date.now()) {
  for (const key of keys) {
    const entry = failures.get(key);
    if (!entry || entry.resetAt <= now) {
      failures.set(key, { count: 1, resetAt: now + FAILURE_WINDOW_MS });
    } else {
      entry.count += 1;
    }
  }
  while (failures.size > 10_000) failures.delete(failures.keys().next().value);
}

function clearFailures(keys) {
  keys.forEach((key) => failures.delete(key));
}

function getActiveSession(request) {
  const id = getCookies(request).get(SESSION_COOKIE);
  const session = id ? sessions.get(id) : null;
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(id);
    return null;
  }
  return { id, session };
}

function cleanExpiredState() {
  const now = Date.now();
  for (const [id, challenge] of challenges) {
    if (challenge.expiresAt <= now) challenges.delete(id);
  }
  for (const [id, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(id);
  }
  for (const [key, failure] of failures) {
    if (failure.resetAt <= now) failures.delete(key);
  }
}

async function handleLogin(request, response, secureCookies) {
  if (!requestIsSameOrigin(request)) return sendJson(response, 403, { error: 'Запрос отклонён.' });
  const { username, password } = await readJsonBody(request);
  const normalizedUsername = typeof username === 'string' ? username.trim() : '';
  const address = getClientAddress(request);
  const keys = [`ip:${address}`, `user:${normalizedUsername.toLowerCase()}`];
  if (isRateLimited(keys)) {
    return sendJson(response, 429, { error: 'Слишком много попыток. Попробуйте позже.' });
  }
  if (normalizedUsername !== authRecord.username || !verifyPassword(password, authRecord.passwordSalt, authRecord.passwordHash)) {
    recordFailure(keys);
    return sendJson(response, 401, { error: 'Неверный логин или пароль.' });
  }
  clearFailures(keys);

  const challengeId = randomBytes(32).toString('base64url');
  const challenge = { expiresAt: Date.now() + CHALLENGE_TTL_MS, secret: null };
  let result;
  if (totpSecret) {
    challenge.stage = 'totp';
    result = { stage: 'totp' };
  } else {
    challenge.stage = 'setup';
    challenge.secret = randomTotpSecret();
    const label = encodeURIComponent(`Radar4Promote:${authRecord.username}`);
    const issuer = encodeURIComponent('Radar4Promote');
    const otpauthUrl = `otpauth://totp/${label}?secret=${challenge.secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    const QRCode = (await import('qrcode')).default;
    result = {
      stage: 'setup',
      secret: challenge.secret,
      qrDataUrl: await QRCode.toDataURL(otpauthUrl, { errorCorrectionLevel: 'M', margin: 2, width: 220 }),
    };
  }
  const activeSession = getActiveSession(request);
  if (activeSession) sessions.delete(activeSession.id);
  clearCookie(response, SESSION_COOKIE, secureCookies);
  challenges.set(challengeId, challenge);
  setCookie(response, CHALLENGE_COOKIE, challengeId, CHALLENGE_TTL_MS / 1000, secureCookies);
  return sendJson(response, 200, result);
}

async function handleVerify(request, response, secureCookies) {
  if (!requestIsSameOrigin(request)) return sendJson(response, 403, { error: 'Запрос отклонён.' });
  const body = await readJsonBody(request);
  const code = typeof body.code === 'string' ? body.code.trim() : '';
  const challengeId = getCookies(request).get(CHALLENGE_COOKIE);
  const challenge = challengeId ? challenges.get(challengeId) : null;
  if (!challenge || challenge.expiresAt <= Date.now()) {
    if (challengeId) challenges.delete(challengeId);
    clearCookie(response, CHALLENGE_COOKIE, secureCookies);
    return sendJson(response, 401, { error: 'Сеанс входа истёк. Начните вход заново.' });
  }
  if (challenge.stage === 'setup' && totpSecret) {
    challenges.delete(challengeId);
    clearCookie(response, CHALLENGE_COOKIE, secureCookies);
    return sendJson(response, 409, { error: 'Настройка уже завершена в другом сеансе. Войдите повторно с кодом приложения.' });
  }

  const address = getClientAddress(request);
  const keys = [`ip:${address}`, `verify:${challengeId}`, `mfa-user:${authRecord.username}`];
  if (isRateLimited(keys)) {
    return sendJson(response, 429, { error: 'Слишком много попыток. Начните вход позже.' });
  }

  if (verificationInProgress) {
    return sendJson(response, 409, { error: 'Подтверждение уже выполняется. Повторите попытку.' });
  }
  verificationInProgress = true;
  try {
    let recoveryIndex = -1;
    let matchedCounter = matchingTotpCounter(challenge.stage === 'setup' ? challenge.secret : totpSecret, code);
    if (challenge.stage === 'totp' && matchedCounter !== null
      && BigInt(matchedCounter) <= BigInt(authRecord.lastTotpCounter || '-1')) {
      matchedCounter = null;
    }
    const verified = matchedCounter !== null;
    if (!verified && challenge.stage === 'totp') {
      recoveryIndex = consumeRecoveryCode(code, authRecord.recoveryHashes);
    }
    if (!verified && recoveryIndex < 0) {
      recordFailure(keys);
      return sendJson(response, 401, { error: 'Неверный код. Проверьте время на устройстве и попробуйте ещё раз.' });
    }
    clearFailures(keys);

    let recoveryCodes = null;
    if (challenge.stage === 'setup') {
      const generated = createRecoveryCodes();
      recoveryCodes = generated.codes;
      await persistAuthRecord({
        ...authRecord,
        totpSecret: encryptTotpSecret(challenge.secret, encryptionKey),
        recoveryHashes: generated.hashes,
        lastTotpCounter: matchedCounter,
      });
      totpSecret = challenge.secret;
    } else if (verified) {
      await persistAuthRecord({ ...authRecord, lastTotpCounter: matchedCounter });
    } else if (recoveryIndex >= 0) {
      const updatedHashes = [...authRecord.recoveryHashes];
      updatedHashes.splice(recoveryIndex, 1);
      await persistAuthRecord({ ...authRecord, recoveryHashes: updatedHashes });
    }

    challenges.delete(challengeId);
    clearCookie(response, CHALLENGE_COOKIE, secureCookies);
    const sessionId = randomBytes(32).toString('base64url');
    sessions.set(sessionId, { expiresAt: Date.now() + SESSION_TTL_MS });
    setCookie(response, SESSION_COOKIE, sessionId, SESSION_TTL_MS / 1000, secureCookies);
    return sendJson(response, 200, {
      authenticated: true,
      recoveryCodes,
      recoveryCodesRemaining: authRecord.recoveryHashes.length,
    });
  } finally {
    verificationInProgress = false;
  }
}

function publicPath(pathname) {
  return ['/login.html', '/auth.js', '/css/auth.css', '/assets/rostelecom-logo.png'].includes(pathname);
}

function isAllowedAsset(pathname) {
  return pathname === '/index.html'
    || pathname === '/assets/rostelecom-logo.png'
    || ['/css/', '/js/', '/data/'].some((prefix) => pathname.startsWith(prefix));
}

async function serveAsset(response, pathname, headOnly = false) {
  if (!isAllowedAsset(pathname) && !publicPath(pathname)) {
    response.writeHead(404, { 'Cache-Control': 'no-store' });
    response.end('Not found');
    return;
  }
  if (pathname.split('/').some((part) => part === '..' || part.startsWith('.'))) {
    response.writeHead(404, { 'Cache-Control': 'no-store' });
    response.end('Not found');
    return;
  }
  const filePath = path.resolve(PUBLIC_ROOT, `.${pathname}`);
  const allowedRoot = path.resolve(PUBLIC_ROOT);
  if (!filePath.startsWith(`${allowedRoot}${path.sep}`)) {
    response.writeHead(404);
    response.end('Not found');
    return;
  }
  let contents;
  try {
    contents = await readFile(filePath);
  } catch (error) {
    if (error.code !== 'ENOENT' && error.code !== 'EISDIR') throw error;
    response.writeHead(404, { 'Cache-Control': 'no-store' });
    response.end('Not found');
    return;
  }
  const extension = path.extname(filePath).toLowerCase();
  response.writeHead(200, {
    'Content-Type': MIME_TYPES.get(extension) || 'application/octet-stream',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': [
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "script-src 'self' https://unpkg.com https://cdn.jsdelivr.net",
      "style-src 'self' 'unsafe-inline' https://unpkg.com",
      "img-src 'self' data: blob: https://tile.openstreetmap.org https://unpkg.com",
      "connect-src 'self' https://api.openstreetmap.org https://photon.komoot.io",
      "font-src 'self' data:",
    ].join('; '),
  });
  response.end(headOnly ? undefined : contents);
}

async function handleRequest(request, response, secureCookies) {
  cleanExpiredState();
  const url = new URL(request.url, 'http://localhost');
  let pathname;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    response.writeHead(400);
    response.end('Bad request');
    return;
  }

  if (request.method === 'GET' && pathname === '/api/auth/status') {
    return sendJson(response, 200, { authenticated: Boolean(getActiveSession(request)) });
  }
  if (request.method === 'POST' && pathname === '/api/auth/login') {
    return handleLogin(request, response, secureCookies);
  }
  if (request.method === 'POST' && pathname === '/api/auth/verify') {
    return handleVerify(request, response, secureCookies);
  }
  if (request.method === 'POST' && pathname === '/api/auth/logout') {
    if (!requestIsSameOrigin(request)) return sendJson(response, 403, { error: 'Запрос отклонён.' });
    const activeSession = getActiveSession(request);
    if (activeSession) sessions.delete(activeSession.id);
    clearCookie(response, SESSION_COOKIE, secureCookies);
    return sendJson(response, 200, { authenticated: false });
  }
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, { Allow: 'GET, HEAD, POST' });
    response.end('Method not allowed');
    return;
  }

  if (pathname === '/') pathname = '/index.html';
  if (!publicPath(pathname) && !getActiveSession(request)) {
    if (pathname === '/index.html') {
      response.writeHead(302, { Location: '/login.html', 'Cache-Control': 'no-store' });
      response.end();
      return;
    }
    return sendJson(response, 401, { error: 'Требуется вход.' });
  }
  return serveAsset(response, pathname, request.method === 'HEAD');
}

export function createHttpServer(secureCookies = false) {
  return createServer((request, response) => {
    handleRequest(request, response, secureCookies).catch((error) => {
      if (!error.statusCode || error.statusCode >= 500) console.error(`[server] ${error.message}`);
      if (!response.headersSent) {
        sendJson(response, error.statusCode || 500, {
          error: error.statusCode ? error.message : 'Внутренняя ошибка сервера.',
        });
      } else {
        response.destroy();
      }
    });
  });
}

export async function prepareAuthServer() {
  await loadEnvFile();
  await initializeAuth();
}

async function start() {
  await prepareAuthServer();
  const host = process.env.RADAR_HOST || '127.0.0.1';
  const secureCookies = process.env.RADAR_SECURE_COOKIES === 'true';
  const port = Number(process.env.PORT || 8000);
  const isLocal = ['127.0.0.1', 'localhost', '::1'].includes(host);
  if (!isLocal && !secureCookies) {
    throw new Error('Для сетевого интерфейса укажите RADAR_SECURE_COOKIES=true и используйте HTTPS.');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT должен быть в диапазоне 1–65535.');
  const server = createHttpServer(secureCookies);
  server.listen(port, host, () => {
    console.log(`Radar4Promote защищён 2FA: http://${host}:${port}/`);
    console.log('Для использования вне этого компьютера настройте HTTPS reverse proxy и secure cookies.');
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  start().catch((error) => {
    console.error(`[startup] ${error.message}`);
    process.exitCode = 1;
  });
}
