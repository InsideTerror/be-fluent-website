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

// ---------- Pending (visitor-submitted) reviews ----------
// Kept in a separate hash so the admin's "replace whole list" save can never
// overwrite a submission that arrived after the dashboard was loaded.
const PENDING_KEY = 'pending_reviews';
const MAX_PENDING = 100;

export async function addPendingReview(review) {
  const count = Number(await redis(['HLEN', PENDING_KEY]) || 0);
  if (count >= MAX_PENDING) throw new Error('PENDING_FULL');
  await redis(['HSET', PENDING_KEY, review.id, JSON.stringify(review)]);
}

export async function loadPendingReviews() {
  const flat = (await redis(['HGETALL', PENDING_KEY])) || [];
  const list = [];
  for (let i = 1; i < flat.length; i += 2) {
    try { list.push(JSON.parse(flat[i])); } catch (e) { /* skip corrupt entry */ }
  }
  return list.sort(function (a, b) { return String(b.submittedAt).localeCompare(String(a.submittedAt)); });
}

// Removes and returns a pending review (null if it no longer exists).
// HDEL returns 1 only for the caller that actually deleted it, so two admins
// approving at the same moment can't add the same review twice.
export async function takePendingReview(id) {
  const raw = await redis(['HGET', PENDING_KEY, String(id)]);
  if (!raw) return null;
  const removed = await redis(['HDEL', PENDING_KEY, String(id)]);
  return removed ? JSON.parse(raw) : null;
}

// Submission throttling: max 3 reviews per IP per hour
const MAX_SUBMISSIONS = 3;
const SUBMIT_WINDOW_SEC = 60 * 60;

export async function tooManySubmissions(req) {
  const key = 'reviewsubmit:' + clientIp(req);
  const count = await redis(['INCR', key]);
  if (Number(count) === 1) await redis(['EXPIRE', key, SUBMIT_WINDOW_SEC]);
  return Number(count) > MAX_SUBMISSIONS;
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

// A review sent in by a visitor through the public form
export function sanitizeSubmission(body) {
  const b = body || {};
  const review = {
    id: crypto.randomUUID(),
    name: cleanText(b.name, 80),
    detail: cleanText(b.detail, 120),
    text: cleanText(b.text, 2000),
    rating: parseInt(b.rating, 10),
    submittedAt: new Date().toISOString(),
  };
  if (!review.name) throw new Error('Kérjük, add meg a neved.');
  if (review.text.length < 20) throw new Error('A vélemény legalább 20 karakter legyen.');
  if (!(review.rating >= 1 && review.rating <= 5)) throw new Error('Kérjük, válassz 1–5 csillagot.');
  return review;
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
