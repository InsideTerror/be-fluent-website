// Public endpoint used by index.html: returns only the visible reviews.
import { loadReviews } from './_lib.js';

export default async function handler(req, res) {
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
