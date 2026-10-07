// Data + admin login for the Ajwir tournament site (Netlify Function, v2 syntax).
// GET  ?status                       -> diagnostics (no secrets)
// GET                                -> saved tournament data (404 if nothing saved yet -> the site falls back to data.json)
// POST {action:'login',password}     -> {token}   (locks the client IP for 15 min after 8 wrong attempts)
// POST {token,data}                  -> saves data (and keeps automatic safety copies: "prev" + one snapshot per day)
// POST {token,action:'versions'}     -> list of safety copies;  {token,action:'getver',key} -> one copy
import { createHmac, timingSafeEqual } from "node:crypto";
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
const sig = (pw, ts) => createHmac("sha256", pw).update(String(ts)).digest("hex");
const mkTok = (pw) => { const ts = Date.now(); return ts + "." + sig(pw, ts); };
const okTok = (pw, t) => { const [ts, s] = String(t || "").split("."); return !!(pw && ts && s && Date.now() - Number(ts) < 432e5 && eq(s, sig(pw, ts))); };
const MAX_FAILS = 8, LOCK_MS = 15 * 60 * 1000, KEEP = 30;

async function storage() {
  let detail = "";
  try {
    const { getStore } = await import("@netlify/blobs");
    const st = getStore("ajwir"), sec = getStore("ajwir-sec");
    await st.get("data", { type: "text" }); // probe: throws if Blobs is not configured
    return { kind: "blobs", raw: st, sec, get: () => st.get("data", { type: "text" }), set: (v) => st.set("data", v) };
  } catch (e) { detail = String(e && e.message || e).slice(0, 160); }
  const u = process.env.UPSTASH_REDIS_REST_URL, t = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (u && t) {
    const h = { authorization: "Bearer " + t };
    return { kind: "upstash",
      get: async () => (await (await fetch(u + "/get/ajwir_data", { headers: h })).json()).result ?? null,
      set: async (v) => { const r = await fetch(u + "/set/ajwir_data", { method: "POST", headers: h, body: v }); if (!r.ok) throw new Error("upstash " + r.status); } };
  }
  return { kind: null, detail };
}
const ipOf = (req) => String(req.headers.get("x-nf-client-connection-ip") || req.headers.get("x-forwarded-for") || "x").split(",")[0].trim().replace(/[^0-9a-fA-F:.x]/g, "").slice(0, 45) || "x";
const day = () => new Date().toISOString().slice(0, 10);

async function keepCopies(st, newText) {
  if (st.kind !== "blobs") return;
  try {
    const old = await st.raw.get("data", { type: "text" });
    if (!old || old === newText) return;
    await st.raw.set("prev", old);
    const k = "snap:" + day();
    if ((await st.raw.get(k, { type: "text" })) === null) await st.raw.set(k, old);
    const { blobs } = await st.raw.list({ prefix: "snap:" });
    const keys = blobs.map((b) => b.key).sort();
    for (const x of keys.slice(0, Math.max(0, keys.length - KEEP))) await st.raw.delete(x);
  } catch {}
}

export default async (req) => {
  const pw = process.env.ADMIN_PASSWORD;
  const url = new URL(req.url);
  const st = await storage();
  if (req.method === "GET") {
    if (url.searchParams.has("status")) return J({ fn: true, pw: !!pw, storage: st.kind, detail: st.kind ? "" : st.detail });
    if (!st.kind) return J({ error: "no storage" }, 404);
    try { const d = await st.get(); return d ? new Response(d, { headers: { "content-type": "application/json", "cache-control": "no-store" } }) : J({}, 404); }
    catch { return J({}, 404); }
  }
  if (req.method !== "POST") return J({ error: "method" }, 405);
  if (!pw) return J({ error: "ADMIN_PASSWORD غير مضبوطة في Netlify" }, 500);
  let b; try { b = await req.json(); } catch { return J({ error: "bad request" }, 400); }
  if (b.action === "login") {
    const lk = "ip:" + ipOf(req);
    let rec = null; if (st.sec) { try { rec = await st.sec.get(lk, { type: "json" }); } catch {} }
    if (rec && rec.n >= MAX_FAILS && Date.now() - rec.t < LOCK_MS) return J({ error: "locked", retryAfterMin: Math.ceil((LOCK_MS - (Date.now() - rec.t)) / 60000) }, 429);
    if (!eq(b.password ?? "", pw)) {
      if (st.sec) { try { const n = rec && Date.now() - rec.t < LOCK_MS ? rec.n + 1 : 1; await st.sec.setJSON(lk, { n, t: Date.now() }); } catch {} }
      await new Promise((r) => setTimeout(r, 700)); return J({ error: "unauthorized" }, 401);
    }
    if (rec && st.sec) { try { await st.sec.delete(lk); } catch {} }
    return J({ token: mkTok(pw) });
  }
  if (!okTok(pw, b.token)) return J({ error: "unauthorized" }, 401);
  if (b.action === "versions") {
    if (st.kind !== "blobs") return J({ versions: [] });
    const { blobs } = await st.raw.list({ prefix: "snap:" }), v = blobs.map((x) => x.key).sort().reverse().map((k) => ({ key: k, label: k.slice(5) }));
    if ((await st.raw.get("prev", { type: "text" })) !== null) v.unshift({ key: "prev", label: "النسخة السابقة مباشرة" });
    return J({ versions: v });
  }
  if (b.action === "getver") {
    if (st.kind !== "blobs" || !/^(prev|snap:\d{4}-\d{2}-\d{2})$/.test(String(b.key))) return J({ error: "bad key" }, 400);
    const d = await st.raw.get(b.key, { type: "text" }); return d ? new Response(d, { headers: { "content-type": "application/json", "cache-control": "no-store" } }) : J({ error: "missing" }, 404);
  }
  if (!b.data || !Array.isArray(b.data.teams) || !Array.isArray(b.data.matches)) return J({ error: "bad data" }, 400);
  if (!st.kind) return J({ error: "لا يوجد تخزين: Netlify Blobs غير متاح" }, 500);
  const text = JSON.stringify(b.data);
  try { await keepCopies(st, text); await st.set(text); return J({ ok: true }); }
  catch (e) { return J({ error: "تعذر الحفظ: " + String(e && e.message || e).slice(0, 120) }, 500); }
};
