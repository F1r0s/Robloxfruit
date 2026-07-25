/**
 * Cloudflare Turnstile — Server-Side Validation
 * Vercel Serverless Function: /api/submit
 *
 * Environment variable required:
 *   TURNSTILE_SECRET  →  your Cloudflare Turnstile Secret Key
 *
 * Set it via CLI:  vercel env add TURNSTILE_SECRET
 */
export default async function handler(req, res) {
  // Only allow POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Read token from JSON body
  const token = req.body?.token || req.body?.['cf-turnstile-response'];

  // Read visitor IP (Vercel sets x-forwarded-for)
  const ip =
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    '';

  // Guard: token must be present
  if (!token) {
    return res.status(403).json({ success: false, error: 'Missing CAPTCHA token' });
  }

  // Guard: secret must be set in environment
  const secret = process.env.TURNSTILE_SECRET;
  if (!secret) {
    console.error('[Turnstile] TURNSTILE_SECRET env variable is not set!');
    return res.status(500).json({ success: false, error: 'Server misconfiguration' });
  }

  // Call Cloudflare Siteverify API
  let cfData;
  try {
    const cfRes = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret,
          response: token,
          remoteip: ip,
        }),
      }
    );
    cfData = await cfRes.json();
  } catch (err) {
    console.error('[Turnstile] Fetch to siteverify failed:', err);
    return res.status(500).json({ success: false, error: 'Verification request failed' });
  }

  // Evaluate Cloudflare's response
  if (cfData.success === true) {
    // ✅ Token is valid — visitor is human
    return res.status(200).json({ success: true });
  } else {
    // ❌ Token is invalid or expired
    console.warn('[Turnstile] Validation failed:', cfData['error-codes']);
    return res.status(403).json({
      success: false,
      errors: cfData['error-codes'] || [],
    });
  }
}
