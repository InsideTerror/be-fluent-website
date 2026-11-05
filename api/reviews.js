// Public endpoint used by index.html.
//   GET          → only the visible (approved) reviews.
//   POST {review} → a visitor submits a review; it waits for admin approval.
import { loadReviews, isJsonRequest, sanitizeSubmission, tooManySubmissions,
  addPendingReview } from './_lib.js';

export default async function handler(req, res) {
  if (req.method === 'POST') return submit(req, res);
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
  try {
    const reviews = (await loadReviews())
      .filter(function (r) { return r.visible; })
      .map(function (r) { return { name: r.name, detail: r.detail, text: r.text, rating: r.rating }; });
    // Cached at Vercel's edge for a minute, so edits show up quickly
    res.setHeader('Cache-Control', 'public, s-maxage=60, stale-while-revalidate=300');
    return res.status(200).json({ reviews });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ reviews: [] });
  }
}

async function submit(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (!isJsonRequest(req)) return res.status(415).json({ error: 'JSON expected' });
  const body = req.body || {};

  // Honeypot: real visitors never fill this hidden field. Pretend success.
  if (body.website) return res.status(200).json({ ok: true });

  let review;
  try {
    review = sanitizeSubmission(body);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  try {
    if (await tooManySubmissions(req)) {
      return res.status(429).json({ error: 'Túl sok beküldés. Kérjük, próbáld újra később.' });
    }
    await addPendingReview(review);
    return res.status(200).json({ ok: true });
  } catch (e) {
    if (e.message === 'PENDING_FULL') {
      return res.status(503).json({ error: 'Jelenleg nem fogadunk új véleményt. Kérjük, próbáld újra később.' });
    }
    console.error(e);
    return res.status(500).json({ error: 'Szerverhiba, kérjük, próbáld újra később.' });
  }
}
