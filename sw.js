// Service worker: shows Web Push notifications and opens the right match page on tap.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("push", (e) => {
  let d = {}; try { d = e.data.json(); } catch { d = { title: "بطولة آجوير", body: e.data ? e.data.text() : "" }; }
  e.waitUntil(self.registration.showNotification(d.title || "بطولة آجوير", { body: d.body || "", tag: d.tag || undefined, dir: "rtl", lang: "ar", icon: "/icon.svg", badge: "/icon.svg", data: { url: d.url || "/" } }));
});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const u = new URL((e.notification.data && e.notification.data.url) || "/", self.location.origin).href;
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((l) => { for (const c of l) { if ("focus" in c) { if (c.navigate) c.navigate(u); return c.focus(); } } return self.clients.openWindow(u); }));
});
