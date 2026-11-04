// GET → all reviews (including hidden ones).  PUT [reviews] → replaces the full list.
import { isAuthenticated, isJsonRequest, loadReviews, saveReviews, sanitizeReviews } from '../_lib.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (!isAuthenticated(req)) return res.status(401).json({ error: 'Nincs bejelentkezve.' });

    if (req.method === 'GET') {
      return res.status(200).json({ reviews: await loadReviews() });
    }
    if (req.method === 'PUT') {
      if (!isJsonRequest(req)) return res.status(415).json({ error: 'JSON expected' });
      let reviews;
      try {
        reviews = sanitizeReviews((req.body || {}).reviews);
      } catch (e) {
        return res.status(400).json({ error: e.message });
      }
      await saveReviews(reviews);
      return res.status(200).json({ reviews });
    }
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Szerverhiba: ' + e.message });
  }
}
