/* stilla Service Worker — Installierbarkeit (PWA) + Push-Benachrichtigungen */
self.addEventListener("install", () => { self.skipWaiting(); });
self.addEventListener("activate", (e) => { e.waitUntil(self.clients.claim()); });

/* Netzwerk-durchreichen (die App ist dynamisch; wir cachen nichts Veraltetes). */
self.addEventListener("fetch", () => {});

/* Eingehende Push-Nachricht -> Systembenachrichtigung.
   Inhalt bleibt privat: der Server schickt nur einen neutralen Hinweis, keinen Text. */
self.addEventListener("push", (e) => {
  let data = { title: "stilla", body: "Neue Nachricht" };
  try { if (e.data) data = Object.assign(data, e.data.json()); } catch (_) {}
  e.waitUntil(self.registration.showNotification(data.title || "stilla", {
    body: data.body || "Neue Nachricht",
    icon: "/icon-192.png",
    badge: "/icon-192.png",
    tag: "stilla",
    renotify: true,
    vibrate: [80, 40, 80]
  }));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((cs) => {
    for (const c of cs) { if ("focus" in c) return c.focus(); }
    if (self.clients.openWindow) return self.clients.openWindow("/");
  }));
});
