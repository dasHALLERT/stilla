/**
 * stilla · Lokaler Server (ECHT lauffähig)  —  Phase 2, Baustein 2b
 * ----------------------------------------------------------------------
 * Startet den Relay + liefert eine kleine Chat-Seite aus, erreichbar im
 * eigenen WLAN. Zwei Geräte öffnen die Seite und chatten ECHT verschlüsselt.
 *
 *   node local-server.js
 *   -> dann am Handy/2. Gerät:  http://<Mac-IP>:8787  öffnen
 *
 * Verschlüsselung passiert im Browser (WebCrypto). Der Server sieht nur
 * verschlüsselte Umschläge und löscht sie nach Abholung.
 */
const http = require("node:http");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const nacl = require("tweetnacl");   // geprüfte Krypto, läuft überall (auch iPhone)

// Web-Push (Benachrichtigungen). Der PRIVATE Schlüssel kommt ausschließlich aus
// der Umgebungsvariable VAPID_PRIVATE (niemals in den Code/ins Repo!). Ohne ihn
// laufen alle anderen Funktionen normal weiter, nur Push ist dann aus.
let webpush=null;
const VAPID_PUBLIC = process.env.VAPID_PUBLIC || "BBp8lGotK5Uoo2qFmxuTSSiAPq9PfaEKgS67ZjijzkIx0K8d6YgyM-z1kTMAXnv6PAXFBd3zFzTKJp-uj4m6m94";
const VAPID_PRIVATE = process.env.VAPID_PRIVATE || "";
if(VAPID_PRIVATE){
  try{ webpush=require("web-push"); webpush.setVapidDetails("mailto:info@dashallert.de", VAPID_PUBLIC, VAPID_PRIVATE); }
  catch(e){ console.log("  (web-push nicht verfügbar – Benachrichtigungen aus)"); }
}else{
  console.log("  (VAPID_PRIVATE nicht gesetzt – Benachrichtigungen aus, siehe Render-Env)");
}

// Speicher: Postgres (dauerhaft) wenn DATABASE_URL gesetzt, sonst Arbeitsspeicher.
const { createStore, memStore } = require("./store");
let store = createStore();

const challenges = new Map();  // kurzlebig (Login-Nonce) – darf im Speicher bleiben
const lastSeen  = new Map();   // number -> Zeitpunkt des letzten Lebenszeichens (Präsenz) – flüchtig
const ONLINE_MS = 30000;       // als "online" gilt, wer < 30 s aktiv war

async function pushTo(number){
  if(!webpush) return;
  const sub=await store.getPushSub(number); if(!sub) return;
  const payload=JSON.stringify({title:"stilla",body:"Neue Nachricht"});   // neutral, kein Inhalt
  webpush.sendNotification(sub,payload).catch(async err=>{ if(err&&(err.statusCode===404||err.statusCode===410)) await store.delPushSub(number); });
}

function send(res,code,obj){ res.writeHead(code,{"Content-Type":"application/json"}); res.end(JSON.stringify(obj)); }
function body(req){ return new Promise(r=>{let d="";req.on("data",c=>d+=c);req.on("end",()=>{try{r(JSON.parse(d||"{}"));}catch{r({});}});}); }

/* ---------- E-Mail-Bestätigung (Resend) ---------- */
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const APP_URL        = process.env.APP_URL || "https://stilla-h5v4.onrender.com";
const MAIL_FROM      = process.env.MAIL_FROM || "stilla <noreply@getstilla.me>";   // getstilla.me ist bei Resend verifiziert
const VERIFY_SECRET  = process.env.VERIFY_SECRET || crypto.randomBytes(32).toString("hex");  // ideal per ENV
const b64url = b => Buffer.from(b).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
function signData(s){ return crypto.createHmac("sha256",VERIFY_SECRET).update(s).digest("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
function makeToken(number){ const p=number+"."+(Date.now()+48*3600*1000); return b64url(p)+"."+signData(p); }
function checkToken(tok){ try{ const i=tok.lastIndexOf("."); const b=tok.slice(0,i), sig=tok.slice(i+1);
  const p=Buffer.from(b.replace(/-/g,"+").replace(/_/g,"/"),"base64").toString();
  if(signData(p)!==sig) return null; const [number,exp]=p.split("."); if(Date.now()>Number(exp)) return null; return number;
}catch{ return null; } }
const validEmail = e => typeof e==="string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length<=120;
async function sendVerifyMail(email,number){
  if(!RESEND_API_KEY) return {ok:false,error:"email-disabled"};
  const link=APP_URL+"/?verify="+encodeURIComponent(makeToken(number));
  const html=`<div style="font-family:system-ui,sans-serif;background:#10151e;color:#e8eef3;padding:28px;border-radius:14px;max-width:460px;margin:auto">
    <h2 style="font-family:Georgia,serif;color:#e8eef3">stilla</h2>
    <p>Bitte bestätige deine E-Mail-Adresse, damit dein Account und deine Nummer erhalten bleiben.</p>
    <p><a href="${link}" style="display:inline-block;background:#7cc3bb;color:#07201d;text-decoration:none;font-weight:600;padding:12px 22px;border-radius:10px">E-Mail bestätigen</a></p>
    <p style="color:#8798a8;font-size:13px">Oder diesen Link öffnen:<br>${link}</p>
    <p style="color:#8798a8;font-size:12px">Der Link gilt 48 Stunden. Wenn du das nicht warst, ignoriere diese E-Mail.</p>
  </div>`;
  try{
    const r=await fetch("https://api.resend.com/emails",{method:"POST",
      headers:{"Authorization":"Bearer "+RESEND_API_KEY,"Content-Type":"application/json"},
      body:JSON.stringify({from:MAIL_FROM,to:[email],subject:"stilla – E-Mail bestätigen",html,text:"Bestätige deine E-Mail für stilla: "+link})});
    if(r.ok) return {ok:true};
    const t=await r.text(); console.log("Resend-Fehler",r.status,t); return {ok:false,error:"send-failed",status:r.status};
  }catch(e){ console.log("Resend-Exception",e.message); return {ok:false,error:"send-exception"}; }
}
function fmtNum(n){ return String(n).replace(/(\d{3})(\d{3})(\d{3})/,"$1 $2 $3"); }
async function sendRecoverMail(email,numbers){
  if(!RESEND_API_KEY) return {ok:false,error:"email-disabled"};
  const list=numbers.map(n=>`<div style="font-family:ui-monospace,monospace;font-size:20px;letter-spacing:2px;color:#58d5c9;margin:6px 0">${fmtNum(n)}</div>`).join("");
  const html=`<div style="font-family:system-ui,sans-serif;background:#10151e;color:#e8eef3;padding:28px;border-radius:14px;max-width:460px;margin:auto">
    <h2 style="font-family:Georgia,serif;color:#e8eef3">stilla</h2>
    <p>Hier ist ${numbers.length>1?"sind deine stilla-Nummern":"deine stilla-Nummer"}:</p>
    ${list}
    <p style="color:#8798a8;font-size:13px">Zum Einloggen: stilla öffnen → „Einloggen" → Nummer und Passwort eingeben.</p>
    <p style="color:#8798a8;font-size:12px">Wenn du das nicht angefordert hast, ignoriere diese E-Mail einfach.</p>
  </div>`;
  const text="Deine stilla-Nummer(n): "+numbers.map(fmtNum).join(", ")+" — Einloggen mit Nummer und Passwort.";
  try{
    const r=await fetch("https://api.resend.com/emails",{method:"POST",
      headers:{"Authorization":"Bearer "+RESEND_API_KEY,"Content-Type":"application/json"},
      body:JSON.stringify({from:MAIL_FROM,to:[email],subject:"stilla – deine Nummer",html,text})});
    if(r.ok) return {ok:true};
    const t=await r.text(); console.log("Resend-Fehler(recover)",r.status,t); return {ok:false};
  }catch(e){ console.log("Resend-Exception(recover)",e.message); return {ok:false}; }
}

// Login: Ed25519-Signatur per TweetNaCl prüfen (passt zum Client auf jedem Gerät)
function verifyLogin(signPubB64, nonce, sigB64){
  try{
    return nacl.sign.detached.verify(
      new Uint8Array(Buffer.from(nonce, "utf8")),
      new Uint8Array(Buffer.from(sigB64, "base64")),
      new Uint8Array(Buffer.from(signPubB64, "base64"))
    );
  }catch{ return false; }
}

const CLIENT = fs.readFileSync(path.join(__dirname,"public","index.html"));

const server = http.createServer(async (req,res)=>{
  const url = new URL(req.url,"http://x"); const p = url.pathname;

  if(req.method==="GET" && (p==="/"||p==="/index.html")){ res.writeHead(200,{"Content-Type":"text/html; charset=utf-8","Cache-Control":"no-cache, no-store, must-revalidate"}); return res.end(CLIENT); }

  // Keep-Alive-Endpunkt (hält den Gratis-Dienst wach, siehe keepAlive unten)
  if(req.method==="GET" && p==="/ping"){ res.writeHead(200,{"Content-Type":"text/plain","Cache-Control":"no-cache"}); return res.end("ok"); }

  // statische PWA-Dateien
  const STATIC={ "/manifest.json":["manifest.json","application/json; charset=utf-8"], "/sw.js":["sw.js","text/javascript; charset=utf-8"], "/icon-192.png":["icon-192.png","image/png"], "/icon-512.png":["icon-512.png","image/png"], "/apple-touch-icon.png":["apple-touch-icon.png","image/png"] };
  if(req.method==="GET" && STATIC[p]){ try{ const [f,ct]=STATIC[p]; const buf=fs.readFileSync(path.join(__dirname,"public",f)); res.writeHead(200,{"Content-Type":ct,"Cache-Control":"no-cache"}); return res.end(buf); }catch{ res.writeHead(404); return res.end(); } }

  // Push-Subscription speichern (für Benachrichtigungen)
  if(req.method==="POST" && p==="/subscribe"){ const b=await body(req); if(b.number&&b.subscription) await store.setPushSub(b.number,b.subscription); return send(res,200,{ok:true}); }

  // E-Mail-Bestätigung anfordern: schickt eine Mail mit Bestätigungslink
  if(req.method==="POST" && p==="/verify/request"){ const b=await body(req);
    if(!b.number||!validEmail(b.email)) return send(res,400,{error:"bad-input"});
    try{ await store.setEmail(b.number,b.email.trim()); }catch(_){}   // E-Mail der Nummer zuordnen (für Wiederherstellung)
    const r=await sendVerifyMail(b.email.trim(),b.number);
    return send(res, r.ok?200:502, r); }

  // Nummer vergessen: schickt die Nummer(n) an die E-Mail – nur wenn dort ein bestätigtes Konto liegt.
  // Antwort immer generisch, damit niemand fremde E-Mails/Nummern ausprobieren kann.
  if(req.method==="POST" && p==="/recover"){ const b=await body(req);
    if(validEmail(b.email)){
      try{ const nums=await store.numbersForEmail(b.email.trim());
        if(nums.length) await sendRecoverMail(b.email.trim(),nums); }catch(_){}
    }
    return send(res,200,{ok:true}); }

  // Bestätigungslink prüfen: markiert die Nummer serverseitig als bestätigt (überlebt Gerätewechsel)
  if(req.method==="POST" && p==="/verify/check"){ const b=await body(req);
    const number=checkToken(b.token||"");
    if(number){ try{ await store.setVerified(number); }catch(_){}; return send(res,200,{ok:true,number}); }
    return send(res,200,{ok:false}); }

  // Prüfen, ob eine E-Mail schon für ein Konto benutzt wird (eine E-Mail = ein Konto)
  if(req.method==="POST" && p==="/email-taken"){ const b=await body(req);
    let taken=false; try{ taken=await store.emailExists((b.email||"").trim()); }catch(_){}
    return send(res,200,{taken}); }

  if(req.method==="POST" && p==="/register"){ const b=await body(req);
    if(!b.signPub||!b.kexPub) return send(res,400,{error:"keys missing"});
    const number=await store.createIdentity({signPub:b.signPub,kexPub:b.kexPub,name:b.name||"",avatar:b.avatar||"",status:b.status||""});
    return send(res,200,{number}); }

  // Nummer zurueckholen/beanspruchen — ueberlebt Server-Neustart. Eigentuemer = signPub.
  if(req.method==="POST" && p==="/reclaim"){ const b=await body(req);
    if(!b.number||!b.signPub||!b.kexPub) return send(res,400,{error:"missing"});
    const r=await store.reclaim(b.number,{signPub:b.signPub,kexPub:b.kexPub,name:b.name||"",avatar:b.avatar||"",status:b.status||""});
    if(r.taken) return send(res,409,{taken:true});   // andere Identitaet haelt die Nummer
    return send(res,200,{ok:true,number:b.number}); }

  // Verschlüsselte Schlüssel-Sicherung ablegen (für Login auf neuen Geräten).
  // Nur der Besitzer (per Signatur) UND nur ein bestätigter Account darf das.
  if(req.method==="POST" && p==="/backup/set"){ const b=await body(req);
    if(!b.number||!b.signPub||!b.signature||!b.blob) return send(res,400,{error:"missing"});
    const e=await store.getIdentity(b.number);
    if(!e) return send(res,404,{error:"unknown number"});
    if(e.signPub!==b.signPub) return send(res,403,{error:"not owner"});
    let ok=false; try{ ok=nacl.sign.detached.verify(new Uint8Array(Buffer.from(b.blob,"utf8")),new Uint8Array(Buffer.from(b.signature,"base64")),new Uint8Array(Buffer.from(b.signPub,"base64"))); }catch{}
    if(!ok) return send(res,401,{error:"bad-signature"});
    await store.setBackup(b.number,String(b.blob).slice(0,300000));
    return send(res,200,{ok:true}); }

  // Verschlüsselte Sicherung holen (undurchsichtig; ohne Passwort nutzlos)
  if(req.method==="GET" && p==="/backup"){ const n=url.searchParams.get("number");
    const blob=await store.getBackup(n); return send(res,200,{blob:blob||null}); }

  // Profil aktualisieren (Name, Avatar, Status) — Testversion ohne Signatur-Zwang
  if(req.method==="POST" && p==="/profile"){ const b=await body(req);
    const ok=await store.updateProfile(b.number,{name:b.name,avatar:b.avatar,status:b.status});
    if(!ok) return send(res,404,{error:"unknown number"});
    return send(res,200,{ok:true}); }

  if(req.method==="GET" && p==="/keys"){ const n=url.searchParams.get("number"); const e=await store.getIdentity(n);
    return e?send(res,200,{number:n,...e}):send(res,404,{error:"unknown number"}); }

  // Präsenz: welche der angefragten Nummern sind gerade online?
  if(req.method==="GET" && p==="/presence"){ const now=Date.now();
    const nums=(url.searchParams.get("numbers")||"").split(",").filter(Boolean);
    const online=nums.filter(n=>{const t=lastSeen.get(n);return t&&(now-t)<ONLINE_MS;});
    return send(res,200,{online}); }

  if(req.method==="POST" && p==="/challenge"){ const b=await body(req);
    if(!(await store.hasIdentity(b.number))) return send(res,404,{error:"unknown number"});
    const nonce=crypto.randomBytes(24).toString("base64"); challenges.set(b.number,nonce);
    return send(res,200,{nonce}); }

  if(req.method==="POST" && p==="/login"){ const b=await body(req);
    const nonce=challenges.get(b.number), e=await store.getIdentity(b.number);
    if(!nonce||!e) return send(res,400,{error:"no challenge"}); challenges.delete(b.number);
    const ok=verifyLogin(e.signPub,nonce,b.signature);
    return send(res, ok?200:401, {ok}); }

  if(req.method==="POST" && p==="/send"){ const b=await body(req);
    if(b.from) lastSeen.set(b.from,Date.now());
    if(!(await store.hasIdentity(b.to))) return send(res,404,{error:"unknown recipient"});
    await store.pushMail(b.to,{from:b.from,envelope:b.envelope,ts:Number(b.ts)||Date.now()});
    pushTo(b.to).catch(()=>{});   // Benachrichtigung ans Zielgerät (neutral, ohne Inhalt) – fire-and-forget
    return send(res,200,{queued:true}); }

  if(req.method==="POST" && p==="/fetch"){ const b=await body(req);
    if(b.number && !b.invisible) lastSeen.set(b.number,Date.now());  // Lebenszeichen (nicht bei Unsichtbar)
    else if(b.number && b.invisible) lastSeen.delete(b.number);      // sofort offline erscheinen
    const q=await store.fetchMail(b.number);                          // atomar lesen+löschen
    return send(res,200,{messages:q}); }

  send(res,404,{error:"not found"});
});

function localIPs(){ const out=[]; const ifs=os.networkInterfaces();
  for(const name in ifs) for(const i of ifs[name]) if(i.family==="IPv4"&&!i.internal) out.push(i.address);
  return out; }

const PORT = process.env.PORT || 8787;   // Hosting-Dienste geben den Port per Umgebungsvariable vor
(async ()=>{
  try{
    await store.init();
    console.log("  Speicher: "+store.kind+(store.kind==="postgres"?" (dauerhaft)":" (nur Arbeitsspeicher)"));
  }catch(e){
    console.log("  DB-Start fehlgeschlagen ("+e.message+") – falle auf Arbeitsspeicher zurück.");
    store=memStore(); await store.init();
  }
  server.listen(PORT,"0.0.0.0",()=>{
    console.log("\n  stilla-Server läuft auf Port "+PORT+".\n");
    console.log("  Auf diesem Mac:      http://localhost:"+PORT);
    localIPs().forEach(ip=>console.log("  Im WLAN (2. Gerät):  http://"+ip+":"+PORT));
    console.log("\n  Beenden mit Strg+C.\n");
  });
})();

/* Keep-Alive: verhindert, dass der Gratis-Dienst (Render) nach ~15 Minuten
   einschläft und dabei alle Nummern/Daten aus dem Speicher verliert.
   Nur aktiv, wenn eine öffentliche URL bekannt ist (Produktion). */
(function keepAlive(){
  const url = process.env.APP_URL || "";
  if(!/^https?:\/\//.test(url)) return;      // lokal: kein Selbst-Ping
  const https = require("https");
  const http  = require("http");
  const pinger = url.startsWith("https") ? https : http;
  const target = url.replace(/\/+$/,"") + "/ping";
  setInterval(()=>{
    try{
      const req = pinger.get(target,(r)=>{ r.resume(); });
      req.on("error",()=>{});
      req.setTimeout(10000,()=>{ req.destroy(); });
    }catch(_){}
  }, 10*60*1000);                            // alle 10 Minuten
})();
