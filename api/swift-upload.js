const SWIFT = 'https://swift.subnp.com/api/files';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'method_not_allowed' });
  const key = process.env.SWIFTCDN_API_KEY;
  if (!key) return res.status(503).json({ error: 'storage_not_configured' });
  try {
    const form = await req.formData();
    const file = form.get('file');
    if (!(file instanceof File)) return res.status(400).json({ error: 'file_required' });
    if (file.size > 10 * 1024 * 1024) return res.status(413).json({ error: 'file_too_large', message: 'This upload path is limited to 10 MB. Large-model resumable upload still needs the SwiftCDN resumable endpoint configured.' });
    const out = new FormData();
    out.append('file', file, file.name || 'model.json.gz');
    const r = await fetch(SWIFT, { method: 'POST', headers: { 'x-api-key': key }, body: out });
    const text = await r.text();
    let data; try { data = JSON.parse(text); } catch { data = { error: text || 'swift_upload_failed' }; }
    return res.status(r.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'upload_failed', message: e?.message || 'Upload failed' });
  }
}
