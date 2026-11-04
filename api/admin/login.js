// POST {user, password} → sets session cookie.  DELETE → logs out.
import { checkCredentials, setSessionCookie, clearSessionCookie, isLockedOut,
  recordFailedLogin, isJsonRequest } from '../_lib.js';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method === 'DELETE') {
    clearSessionCookie(res);
    return res.status(200).json({ ok: true });
  }
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!isJsonRequest(req)) return res.status(415).json({ error: 'JSON expected' });

  try {
    if (await isLockedOut(req)) {
      return res.status(429).json({ error: 'Túl sok sikertelen próbálkozás. Próbáld újra 15 perc múlva.' });
    }
    const body = req.body || {};
    if (!checkCredentials(body.user, body.password)) {
      await recordFailedLogin(req);
      return res.status(401).json({ error: 'Hibás felhasználónév vagy jelszó.' });
    }
    setSessionCookie(res);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Szerverhiba: ' + e.message });
  }
}
