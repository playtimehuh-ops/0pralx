export default async function handler(req, res) {
  const upstream = "https://jtstdajaaasucialvsfs.supabase.co/functions/v1/v1";

  try {
    const response = await fetch(upstream, {
      method: req.method,
      headers: {
        "Authorization": req.headers.authorization || "",
        "Content-Type": req.headers["content-type"] || "application/json",
      },
      body: ["GET", "HEAD"].includes(req.method) ? undefined : JSON.stringify(req.body),
      redirect: "manual",
    });

    const text = await response.text();
    res.status(response.status);
    res.setHeader("Content-Type", response.headers.get("content-type") || "application/json");
    res.send(text);
  } catch {
    res.status(502).json({
      error: {
        code: "upstream_unavailable",
        message: "API connection is temporarily unavailable."
      }
    });
  }
}
