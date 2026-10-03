// Admin API for the Ajwir tournament site (Netlify Function, v2 syntax).
// GET  ?status        -> diagnostics (no secrets)
// GET                 -> saved tournament data (404 if nothing saved yet)
// POST {action:'login',password} -> {token}
// POST {token,data}   -> saves data (token required)
import { createHmac, timingSafeEqual } from "node:crypto";
const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && timingSafeEqual(x, y); };
const sig = (pw, ts) => createHmac("sha256", pw).update(String(ts)).digest("hex");
const mkTok = (pw) => { const ts = Date.now(); return ts + "." + sig(pw, ts); };
const okTok = (pw, t) => { const [ts, s] = String(t || "").split("."); return !!(ts && s && Date.now() - Number(ts) < 432e5 && eq(s, sig(pw, ts))); };

async function storage() {
  let detail = "";
  try {
    const { getStore } = await import("@netlify/blobs");
    const st = getStore("ajwir");
    await st.get("data", { type: "text" }); // probe: throws if Blobs is not configured
    return { kind: "blobs", get: () => st.get("data", { type: "text" }), set: (v) => st.set("data", v) };
  } catch (e) { detail = String(e && e.message || e).slice(0, 160); }
  const u = process.env.UPSTASH_REDIS_REST_URL, t = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (u && t) {
    const h = { authorization: "Bearer " + t };
    return {
      kind: "upstash",
      get: async () => (await (await fetch(u + "/get/ajwir_data", { headers: h })).json()).result ?? null,
      set: async (v) => { const r = await fetch(u + "/set/ajwir_data", { method: "POST", headers: h, body: v }); if (!r.ok) throw new Error("upstash " + r.status); },
    };
  }
  return { kind: null, detail };
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
    if (!eq(b.password ?? "", pw)) { await new Promise((r) => setTimeout(r, 700)); return J({ error: "unauthorized" }, 401); }
    return J({ token: mkTok(pw) });
  }
  if (!okTok(pw, b.token)) return J({ error: "unauthorized" }, 401);
  if (!b.data || !Array.isArray(b.data.teams) || !Array.isArray(b.data.matches)) return J({ error: "bad data" }, 400);
  if (!st.kind) return J({ error: "لا يوجد تخزين: Netlify Blobs غير متاح" }, 500);
  try { await st.set(JSON.stringify(b.data)); return J({ ok: true }); }
  catch (e) { return J({ error: "تعذر الحفظ: " + String(e && e.message || e).slice(0, 120) }, 500); }
};
export const config = { path: "/api/data" };
