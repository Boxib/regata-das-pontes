// Recebe {user, pass, gaia, arrabida}, valida a palavra-passe e grava state.json no GitHub.
// O token do GitHub vive só aqui (secret GH_TOKEN) e nunca chega ao browser.
const enc = new TextEncoder();

async function sha256(txt) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(txt));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function eq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function utf8ToB64(s) {
  let bin = "";
  for (const b of enc.encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
}

export default {
  async fetch(req, env) {
    const cors = {
      "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      Vary: "Origin",
    };
    const reply = (status, code) =>
      new Response(JSON.stringify({ ok: status === 200, code }), {
        status,
        headers: { ...cors, "Content-Type": "application/json" },
      });

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (req.method !== "POST") return reply(405, "method");
    if (req.headers.get("Origin") !== env.ALLOWED_ORIGIN) return reply(403, "origin");
    if (!env.GH_TOKEN) return reply(500, "no-token");

    let b;
    try { b = await req.json(); } catch { return reply(400, "json"); }

    const user = String(b.user ?? "");
    const pass = String(b.pass ?? "");
    const hash = await sha256(user + "\n" + pass);
    if (user !== env.ADMIN_USER || !eq(hash, env.PASS_HASH)) return reply(401, "auth");

    const gaia = Number(b.gaia), arrabida = Number(b.arrabida);
    const okNum = (v) => Number.isInteger(v) && v >= 0 && v <= 999;
    if (!okNum(gaia) || !okNum(arrabida)) return reply(400, "range");

    const next = { updated: new Date().toISOString(), gaia, arrabida };
    const api = `https://api.github.com/repos/${env.REPO}/contents/state.json`;
    const hd = {
      Authorization: `Bearer ${env.GH_TOKEN}`,
      Accept: "application/vnd.github+json",
      "User-Agent": "regata-pontes-save",
    };

    const cur = await fetch(api, { headers: hd });
    if (cur.status === 401 || cur.status === 403) return reply(502, "gh-auth");
    const sha = cur.ok ? (await cur.json()).sha : undefined;

    const put = await fetch(api, {
      method: "PUT",
      headers: hd,
      body: JSON.stringify({
        message: `pontos: Gaia ${gaia} · Arrábida ${arrabida}`,
        content: utf8ToB64(JSON.stringify(next)),
        sha,
      }),
    });
    if (put.status === 409 || put.status === 422) return reply(409, "conflict");
    if (put.status === 401 || put.status === 403) return reply(502, "gh-auth");
    if (!put.ok) return reply(502, "other");
    return reply(200, "saved");
  },
};
