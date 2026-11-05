// Visitor-submitted reviews waiting for approval.
//   GET                               → { pending }
//   POST {id, action:"approve"|"reject"} → { reviews, pending }
import { isAuthenticated, isJsonRequest, loadReviews, saveReviews,
  loadPendingReviews, takePendingReview, addPendingReview } from '../_lib.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    if (!isAuthenticated(req)) return res.status(401).json({ error: 'Nincs bejelentkezve.' });

    if (req.method === 'GET') {
      return res.status(200).json({ pending: await loadPendingReviews() });
    }
    if (req.method === 'POST') {
      if (!isJsonRequest(req)) return res.status(415).json({ error: 'JSON expected' });
      const { id, action } = req.body || {};
      if (!id || (action !== 'approve' && action !== 'reject')) {
        return res.status(400).json({ error: 'Érvénytelen kérés.' });
      }

      const review = await takePendingReview(id);
      if (!review) {
        return res.status(404).json({ error: 'Ez a vélemény már nincs a várólistán (talán egy másik admin kezelte).' });
      }

      let reviews;
      try {
        reviews = await loadReviews();
        if (action === 'approve') {
          reviews = [{
            id: review.id,
            name: review.name,
            detail: review.detail || '',
            text: review.text,
            rating: review.rating,
            visible: true,
          }].concat(reviews);
          await saveReviews(reviews);
        }
      } catch (e) {
        // Put it back in the queue so a failed save doesn't lose the review
        await addPendingReview(review).catch(function () {});
        throw e;
      }
      return res.status(200).json({ reviews, pending: await loadPendingReviews() });
    }
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Szerverhiba: ' + e.message });
  }
}
