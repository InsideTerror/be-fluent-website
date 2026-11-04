// Shared helpers for the API routes. Files starting with "_" are not
// exposed as endpoints by Vercel.
//
// Required environment variables (Vercel → Project → Settings → Environment Variables):
//   ADMIN_USERS                          logins for admin.befluent.hu, as JSON:
//                                        {"eszter":"password1","zalán":"password2"}
//   KV_REST_API_URL, KV_REST_API_TOKEN   added automatically by the Upstash Redis
//                                        integration (UPSTASH_REDIS_REST_* also work)
import crypto from 'node:crypto';

const REVIEWS_KEY = 'reviews';
const SESSION_COOKIE = 'bf_admin';
const SESSION_HOURS = 12;

// ---------- Redis (Upstash REST API, no npm package needed) ----------
async function redis(command) {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) throw new Error('Redis is not configured');
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify(command),
  });
  const data = await res.json();
  if (!res.ok || data.error) throw new Error(data.error || 'Redis error ' + res.status);
  return data.result;
}

export async function loadReviews() {
  const raw = await redis(['GET', REVIEWS_KEY]);
  return raw ? JSON.parse(raw) : [];
}

export async function saveReviews(reviews) {
  await redis(['SET', REVIEWS_KEY, JSON.stringify(reviews)]);
}

// Login throttling: max 5 failed attempts per IP per 15 minutes
const MAX_FAILS = 5;
const FAIL_WINDOW_SEC = 15 * 60;

function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
}

export async function isLockedOut(req) {
  const count = await redis(['GET', 'loginfail:' + clientIp(req)]);
  return Number(count || 0) >= MAX_FAILS;
}

export async function recordFailedLogin(req) {
  const key = 'loginfail:' + clientIp(req);
  await redis(['INCR', key]);
  await redis(['EXPIRE', key, FAIL_WINDOW_SEC]);
}

// ---------- Review validation ----------
function cleanText(value, maxLen) {
  return String(value == null ? '' : value).trim().slice(0, maxLen);
}

export function sanitizeReviews(input) {
  if (!Array.isArray(input)) throw new Error('Expected a list of reviews');
  return input.slice(0, 200).map(function (r) {
    const review = {
      id: cleanText(r.id, 40) || crypto.randomUUID(),
      name: cleanText(r.name, 80),
      detail: cleanText(r.detail, 120),
      text: cleanText(r.text, 2000),
      rating: Math.max(0, Math.min(5, parseInt(r.rating, 10) || 0)),
      visible: r.visible !== false,
    };
    if (!review.name || !review.text) throw new Error('Every review needs a name and text');
    return review;
  });
}

// ---------- Auth (signed session cookie) ----------
// Case- and accent-insensitive, so "Zalán", "zalán" and "zalan" are the same user
function normalizeUser(name) {
  return String(name == null ? '' : name).trim().toLowerCase()
    .normalize('NFD').replace(/[̀-ͯ]/g, '');
}

function adminUsers() {
  let users;
  try {
    users = JSON.parse(process.env.ADMIN_USERS || '{}');
  } catch (e) {
    throw new Error('ADMIN_USERS is not valid JSON');
  }
  const entries = Object.entries(users)
    .map(function ([name, pass]) { return [normalizeUser(name), String(pass)]; })
    .filter(function ([name, pass]) { return name && pass; });
  if (!entries.length) throw new Error('ADMIN_USERS is not set');
  return entries;
}

function sessionKey() {
  // Derived from the credentials, so changing any password logs everyone out
  return crypto.createHash('sha256').update('bf-session:' + process.env.ADMIN_USERS).digest();
}

function sign(payload) {
  return crypto.createHmac('sha256', sessionKey()).update(payload).digest('base64url');
}

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

export function checkCredentials(user, pass) {
  // Check every account fully so timing doesn't reveal which part was wrong
  const name = normalizeUser(user);
  let ok = false;
  for (const [u, p] of adminUsers()) {
    const userOk = safeEqual(name, u);
    const passOk = safeEqual(pass, p);
    if (userOk && passOk) ok = true;
  }
  return ok;
}

export function setSessionCookie(res) {
  const exp = Date.now() + SESSION_HOURS * 3600 * 1000;
  const payload = Buffer.from(JSON.stringify({ exp })).toString('base64url');
  const token = payload + '.' + sign(payload);
  res.setHeader('Set-Cookie', SESSION_COOKIE + '=' + token +
    '; Path=/api/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=' + SESSION_HOURS * 3600);
}

export function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', SESSION_COOKIE + '=; Path=/api/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
}

export function isAuthenticated(req) {
  adminUsers(); // throws if logins aren't configured
  const cookies = String(req.headers.cookie || '').split(';');
  for (const c of cookies) {
    const [name, value] = c.trim().split('=');
    if (name !== SESSION_COOKIE || !value) continue;
    const [payload, sig] = value.split('.');
    if (!payload || !sig || !safeEqual(sig, sign(payload))) return false;
    try {
      return JSON.parse(Buffer.from(payload, 'base64url').toString()).exp > Date.now();
    } catch (e) {
      return false;
    }
  }
  return false;
}

// Admin writes must be JSON — together with SameSite=Strict this blocks CSRF
export function isJsonRequest(req) {
  return String(req.headers['content-type'] || '').indexOf('application/json') === 0;
}
