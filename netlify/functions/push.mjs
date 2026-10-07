// Web Push for the Ajwir tournament site (Netlify Function).
//   GET  ?key               -> public VAPID key (generated once, kept server-side in Blobs; or from env)
//   GET  ?log               -> recent notifications (public, for the in-site notification center)
//   POST {action:'subscribe'|'prefs'|'unsubscribe', ...}   -> a fan's device (public)
//   POST {action:'stats'|'notify', token, ...}              -> admin only (token from the data function login)
// Standard Web Push (RFC 8030/8291/8292) implemented with node:crypto only - no npm dependencies besides @netlify/blobs.
import { createHmac, timingSafeEqual, createECDH, createPrivateKey, sign, createCipheriv, randomBytes, hkdfSync, createHash } from "node:crypto";

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const b64u = (b) => Buffer.from(b).toString("base64url"), fromB = (s) => Buffer.from(String(s), "base64url");
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
const sig = (pw, ts) => createHmac("sha256", pw).update(String(ts)).digest("hex");
const okTok = (pw, t) => { const [ts, s] = String(t || "").split("."); return !!(pw && ts && s && Date.now() - Number(ts) < 432e5 && eq(s, sig(pw, ts))); };

export function encrypt(sub, payload, fixed) {
  const ua = fromB(sub.keys.p256dh), auth = fromB(sub.keys.auth), e = createECDH("prime256v1");
  if (fixed && fixed.priv) e.setPrivateKey(fixed.priv); else e.generateKeys();
  const as = e.getPublicKey(), secret = e.computeSecret(ua), salt = (fixed && fixed.salt) || randomBytes(16);
  const ikm = Buffer.from(hkdfSync("sha256", secret, auth, Buffer.concat([Buffer.from("WebPush: info\0"), ua, as]), 32));
  const cek = Buffer.from(hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: aes128gcm\0"), 16));
  const nonce = Buffer.from(hkdfSync("sha256", ikm, salt, Buffer.from("Content-Encoding: nonce\0"), 12));
  const ci = createCipheriv("aes-128-gcm", cek, nonce);
  const ct = Buffer.concat([ci.update(Buffer.concat([Buffer.from(payload), Buffer.from([2])])), ci.final(), ci.getAuthTag()]);
  return Buffer.concat([salt, Buffer.from([0, 0, 16, 0]), Buffer.from([as.length]), as, ct]);
}
export function vapidJwt(v, aud) {
  const h = b64u(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const c = b64u(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 43200, sub: process.env.VAPID_SUBJECT || "mailto:admin@ajwir.example" }));
  const pub = fromB(v.pub), key = createPrivateKey({ key: { kty: "EC", crv: "P-256", x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)), d: v.d }, format: "jwk" });
  return h + "." + c + "." + b64u(sign("sha256", Buffer.from(h + "." + c), { key, dsaEncoding: "ieee-p1363" }));
}
async function vapid(meta) {
  if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY) return { pub: process.env.VAPID_PUBLIC_KEY, d: process.env.VAPID_PRIVATE_KEY };
  let v = null; try { v = await meta.get("vapid", { type: "json" }); } catch {}
  if (v && v.pub && v.d) return v;
  const e = createECDH("prime256v1"); e.generateKeys();
  v = { pub: b64u(e.getPublicKey()), d: b64u(e.getPrivateKey()) }; await meta.setJSON("vapid", v); return v;
}
const CAT = { goal: "goals", cancel: "goals", chance: "chances", lineup: "lineups", card: "cards", sub: "subs", phase: "results", result: "results", qual: "results", final: "results", news: "news", manual: "manual" };
export function wants(sub, n) {
  const p = sub.prefs || {}, c = n.cat || CAT[n.type] || "manual";
  if (p.off) return false;
  if (c === "chances") { if (!p.cats || p.cats.chances !== true) return false; }
  else if (c !== "manual" && p.cats && p.cats[c] === false) return false;
  if (!n.teamIds || !n.teamIds.length) return true;
  if (n.strict) return n.teamIds.some((t) => (p.teams || []).includes(t)); // manual message "to followers of team X": only those who chose X
  if (p.all !== false) return true;
  return n.teamIds.some((t) => (p.teams || []).includes(t));
}
async function sendOne(v, s, payload) {
  const u = new URL(s.endpoint);
  const r = await fetch(s.endpoint, { method: "POST", headers: { "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", TTL: "3600", Urgency: "high", Authorization: "vapid t=" + vapidJwt(v, u.origin) + ", k=" + v.pub }, body: encrypt(s, payload) });
  return r.status;
}
const clean = (s, n) => String(s ?? "").slice(0, n);

export default async (req) => {
  let getStore; try { ({ getStore } = await import("@netlify/blobs")); } catch { return J({ error: "التخزين غير متاح" }, 500); }
  const meta = getStore("push-meta"), subs = getStore("push-subs"), url = new URL(req.url);
  try {
    if (req.method === "GET") {
      if (url.searchParams.has("key")) return J({ key: (await vapid(meta)).pub });
      if (url.searchParams.has("log")) return J({ items: (await meta.get("log", { type: "json" })) || [] });
      return J({ ok: true, fn: "push" });
    }
    if (req.method !== "POST") return J({ error: "method" }, 405);
    let b; try { b = await req.json(); } catch { return J({ error: "bad request" }, 400); }
    if (b.action === "subscribe" || b.action === "prefs" || b.action === "unsubscribe") {
      const ep = clean(b.sub?.endpoint || b.endpoint, 600);
      if (!/^https:\/\//.test(ep)) return J({ error: "endpoint" }, 400);
      const id = createHash("sha256").update(ep).digest("hex");
      if (b.action === "unsubscribe") { await subs.delete(id); return J({ ok: true }); }
      const prev = (await subs.get(id, { type: "json" })) || {};
      const keys = b.sub?.keys || prev.keys;
      if (!keys || !keys.p256dh || !keys.auth) return J({ error: "keys" }, 400);
      const p = b.prefs || prev.prefs || {};
      await subs.setJSON(id, { endpoint: ep, keys: { p256dh: clean(keys.p256dh, 200), auth: clean(keys.auth, 100) }, prefs: { off: !!p.off, all: p.all !== false, teams: (Array.isArray(p.teams) ? p.teams : []).map(Number).filter(Boolean).slice(0, 20), cats: p.cats && typeof p.cats === "object" ? Object.fromEntries(Object.entries(p.cats).slice(0, 12).map(([k, x]) => [clean(k, 20), !!x])) : {} }, t: prev.t || Date.now() });
      return J({ ok: true });
    }
    const pw = process.env.ADMIN_PASSWORD;
    if (!okTok(pw, b.token)) return J({ error: "unauthorized" }, 401);
    const all = async () => { const { blobs } = await subs.list(); return (await Promise.all(blobs.map(async (x) => { try { const s = await subs.get(x.key, { type: "json" }); return s ? { key: x.key, ...s } : null; } catch { return null; } }))).filter(Boolean); };
    if (b.action === "stats") {
      const L = await all(), teams = {}; L.forEach((s) => (s.prefs.teams || []).forEach((t) => (teams[t] = (teams[t] || 0) + 1)));
      return J({ subs: L.length, active: L.filter((s) => !s.prefs.off).length, teams, all: L.filter((s) => s.prefs.all !== false && !s.prefs.off).length });
    }
    if (b.action === "export") { // full private backup: VAPID keys + subscriptions + notification log
      return J({ vapid: await vapid(meta), subs: (await all()).map(({ key, ...s }) => s), log: (await meta.get("log", { type: "json" })) || [] });
    }
    if (b.action === "import") { // restore on a fresh site (keys + subscriptions + log)
      const v = b.vapid, okv = v && typeof v.pub === "string" && typeof v.d === "string" && fromB(v.pub).length === 65;
      if (okv && !(process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY)) await meta.setJSON("vapid", { pub: v.pub, d: v.d });
      let n = 0;
      for (const s of (Array.isArray(b.subs) ? b.subs : []).slice(0, 5000)) { if (!s || !/^https:\/\//.test(String(s.endpoint)) || !s.keys || !s.keys.p256dh || !s.keys.auth) continue; await subs.setJSON(createHash("sha256").update(String(s.endpoint)).digest("hex"), { endpoint: clean(s.endpoint, 600), keys: { p256dh: clean(s.keys.p256dh, 200), auth: clean(s.keys.auth, 100) }, prefs: s.prefs || {}, t: s.t || Date.now() }); n++; }
      if (Array.isArray(b.log)) await meta.setJSON("log", b.log.slice(0, 100));
      return J({ ok: true, subs: n, vapid: !!okv });
    }
    if (b.action === "notify") {
      const n = b.notif || {}, title = clean(n.title, 120), body = clean(n.body, 400);
      if (!title) return J({ error: "title" }, 400);
      const log = (await meta.get("log", { type: "json" })) || [], id = clean(n.id || "m" + Date.now(), 120);
      if (log.some((x) => x.id === id)) return J({ dup: true, sent: 0 });
      const item = { id, type: clean(n.type || "manual", 20), title, body, url: clean(n.url || "#/", 200), teamIds: (n.teamIds || []).map(Number).filter(Boolean), strict: !!n.strict, t: Date.now() };
      await meta.setJSON("log", [item, ...log].slice(0, 100)); // written first: a repeated id can never be sent twice
      const v = await vapid(meta), payload = JSON.stringify({ title, body, url: "/" + item.url, tag: id, type: item.type });
      const targets = (await all()).filter((s) => wants(s, item));
      let sent = 0, failed = 0;
      for (let i = 0; i < targets.length; i += 25) await Promise.all(targets.slice(i, i + 25).map(async (s) => { try { const st = await sendOne(v, s, payload); if (st >= 200 && st < 300) sent++; else { failed++; if (st === 404 || st === 410) await subs.delete(s.key); } } catch { failed++; } }));
      const cur = (await meta.get("log", { type: "json" })) || []; const k = cur.findIndex((x) => x.id === id); if (k >= 0) { cur[k] = { ...cur[k], sent, failed }; await meta.setJSON("log", cur); }
      return J({ ok: true, sent, failed, targets: targets.length });
    }
    return J({ error: "action" }, 400);
  } catch (e) { return J({ error: "تعذر التنفيذ: " + clean(e && e.message, 120) }, 500); }
};
