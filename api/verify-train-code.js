const crypto = require('node:crypto');

module.exports = function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method not allowed.' });
  }

  const expected = process.env.NOVA_TRAIN_ACCESS_CODE;
  if (!expected) {
    return res.status(503).json({
      ok: false,
      error: 'Access verification is not configured yet. Please try again later.'
    });
  }

  const submitted = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
  if (!submitted || submitted.length > 128) {
    return res.status(400).json({ ok: false, error: 'Enter a valid access code.' });
  }

  const a = Buffer.from(submitted, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  const matches = a.length === b.length && crypto.timingSafeEqual(a, b);

  if (!matches) {
    return res.status(401).json({ ok: false, error: 'That code is not valid.' });
  }

  return res.status(200).json({ ok: true });
};
