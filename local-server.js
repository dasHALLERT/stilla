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

const directory = new Map();   // number -> { signPub, kexPub, name }
const mailbox   = new Map();   // number -> [ {from, envelope, ts} ]
const challenges = new Map();
const lastSeen  = new Map();   // number -> Zeitpunkt des letzten Lebenszeichens (Präsenz)
const pushSubs  = new Map();   // number -> Push-Subscription (für Benachrichtigungen)
const ONLINE_MS = 30000;       // als "online" gilt, wer < 30 s aktiv war
const nextNumber = () => { for(;;){ const n=String(crypto.randomInt(100000000,1000000000)); if(!directory.has(n)) return n; } };

function pushTo(number){
  if(!webpush) return;
  const sub=pushSubs.get(number); if(!sub) return;
  const payload=JSON.stringify({title:"stilla",body:"Neue Nachricht"});   // neutral, kein Inhalt
  webpush.sendNotification(sub,payload).catch(err=>{ if(err&&(err.statusCode===404||err.statusCode===410)) pushSubs.delete(number); });
}

function send(res,code,obj){ res.writeHead(code,{"Content-Type":"application/json"}); res.end(JSON.stringify(obj)); }
function body(req){ return new Promise(r=>{let d="";req.on("data",c=>d+=c);req.on("end",()=>{try{r(JSON.parse(d||"{}"));}catch{r({});}});}); }

/* ---------- E-Mail-Bestätigung (Resend) ---------- */
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const APP_URL        = process.env.APP_URL || "https://stilla-h5v4.onrender.com";
const MAIL_FROM      = process.env.MAIL_FROM || "stilla <onboarding@resend.dev>";   // nach Domain-Verifizierung: noreply@getstilla.me
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

  if(req.method==="GET" && (p==="/"||p==="/index.html")){ res.writeHead(200,{"Content-Type":"text/html; charset=utf-8"}); return res.end(CLIENT); }

  // statische PWA-Dateien
  const STATIC={ "/manifest.json":["manifest.json","application/json; charset=utf-8"], "/sw.js":["sw.js","text/javascript; charset=utf-8"], "/icon-192.png":["icon-192.png","image/png"], "/icon-512.png":["icon-512.png","image/png"], "/apple-touch-icon.png":["apple-touch-icon.png","image/png"] };
  if(req.method==="GET" && STATIC[p]){ try{ const [f,ct]=STATIC[p]; const buf=fs.readFileSync(path.join(__dirname,"public",f)); res.writeHead(200,{"Content-Type":ct,"Cache-Control":"no-cache"}); return res.end(buf); }catch{ res.writeHead(404); return res.end(); } }

  // Push-Subscription speichern (für Benachrichtigungen)
  if(req.method==="POST" && p==="/subscribe"){ const b=await body(req); if(b.number&&b.subscription) pushSubs.set(b.number,b.subscription); return send(res,200,{ok:true}); }

  // E-Mail-Bestätigung anfordern: schickt eine Mail mit Bestätigungslink
  if(req.method==="POST" && p==="/verify/request"){ const b=await body(req);
    if(!b.number||!validEmail(b.email)) return send(res,400,{error:"bad-input"});
    const r=await sendVerifyMail(b.email.trim(),b.number);
    return send(res, r.ok?200:502, r); }

  // Bestätigungslink prüfen: gibt die zugehörige Nummer zurück (stateless, per HMAC)
  if(req.method==="POST" && p==="/verify/check"){ const b=await body(req);
    const number=checkToken(b.token||""); return number?send(res,200,{ok:true,number}):send(res,200,{ok:false}); }

  if(req.method==="POST" && p==="/register"){ const b=await body(req);
    if(!b.signPub||!b.kexPub) return send(res,400,{error:"keys missing"});
    const number=nextNumber(); directory.set(number,{signPub:b.signPub,kexPub:b.kexPub,name:b.name||"",avatar:b.avatar||"",status:b.status||""});
    return send(res,200,{number}); }

  // Nummer zurueckholen/beanspruchen — ueberlebt Server-Neustart. Eigentuemer = signPub.
  if(req.method==="POST" && p==="/reclaim"){ const b=await body(req);
    if(!b.number||!b.signPub||!b.kexPub) return send(res,400,{error:"missing"});
    const e=directory.get(b.number);
    if(e && e.signPub!==b.signPub) return send(res,409,{taken:true});   // andere Identitaet haelt die Nummer
    directory.set(b.number,{signPub:b.signPub,kexPub:b.kexPub,name:b.name||"",avatar:b.avatar||"",status:b.status||""});
    return send(res,200,{ok:true,number:b.number}); }

  // Profil aktualisieren (Name, Avatar, Status) — Testversion ohne Signatur-Zwang
  if(req.method==="POST" && p==="/profile"){ const b=await body(req);
    const e=directory.get(b.number); if(!e) return send(res,404,{error:"unknown number"});
    if(typeof b.name==="string") e.name=b.name.slice(0,40);
    if(typeof b.avatar==="string") e.avatar=b.avatar.slice(0,200000);   // kleines Bild als data-URL
    if(typeof b.status==="string") e.status=b.status.slice(0,60);
    directory.set(b.number,e);
    return send(res,200,{ok:true}); }

  if(req.method==="GET" && p==="/keys"){ const e=directory.get(url.searchParams.get("number"));
    return e?send(res,200,{number:url.searchParams.get("number"),...e}):send(res,404,{error:"unknown number"}); }

  // Präsenz: welche der angefragten Nummern sind gerade online?
  if(req.method==="GET" && p==="/presence"){ const now=Date.now();
    const nums=(url.searchParams.get("numbers")||"").split(",").filter(Boolean);
    const online=nums.filter(n=>{const t=lastSeen.get(n);return t&&(now-t)<ONLINE_MS;});
    return send(res,200,{online}); }

  if(req.method==="POST" && p==="/challenge"){ const b=await body(req);
    if(!directory.has(b.number)) return send(res,404,{error:"unknown number"});
    const nonce=crypto.randomBytes(24).toString("base64"); challenges.set(b.number,nonce);
    return send(res,200,{nonce}); }

  if(req.method==="POST" && p==="/login"){ const b=await body(req);
    const nonce=challenges.get(b.number), e=directory.get(b.number);
    if(!nonce||!e) return send(res,400,{error:"no challenge"}); challenges.delete(b.number);
    return send(res, verifyLogin(e.signPub,nonce,b.signature)?200:401, {ok:verifyLogin(e.signPub,nonce,b.signature)}); }

  if(req.method==="POST" && p==="/send"){ const b=await body(req);
    if(b.from) lastSeen.set(b.from,Date.now());
    if(!directory.has(b.to)) return send(res,404,{error:"unknown recipient"});
    const q=mailbox.get(b.to)||[]; q.push({from:b.from,envelope:b.envelope,ts:Number(b.ts)||Date.now()}); mailbox.set(b.to,q);
    pushTo(b.to);   // Benachrichtigung ans Zielgerät (neutral, ohne Inhalt)
    return send(res,200,{queued:true}); }

  if(req.method==="POST" && p==="/fetch"){ const b=await body(req);
    if(b.number && !b.invisible) lastSeen.set(b.number,Date.now());  // Lebenszeichen (nicht bei Unsichtbar)
    else if(b.number && b.invisible) lastSeen.delete(b.number);      // sofort offline erscheinen
    const q=mailbox.get(b.number)||[]; mailbox.delete(b.number);     // sofort löschen
    return send(res,200,{messages:q}); }

  send(res,404,{error:"not found"});
});

function localIPs(){ const out=[]; const ifs=os.networkInterfaces();
  for(const name in ifs) for(const i of ifs[name]) if(i.family==="IPv4"&&!i.internal) out.push(i.address);
  return out; }

const PORT = process.env.PORT || 8787;   // Hosting-Dienste geben den Port per Umgebungsvariable vor
server.listen(PORT,"0.0.0.0",()=>{
  console.log("\n  stilla-Server läuft auf Port "+PORT+".\n");
  console.log("  Auf diesem Mac:      http://localhost:"+PORT);
  localIPs().forEach(ip=>console.log("  Im WLAN (2. Gerät):  http://"+ip+":"+PORT));
  console.log("\n  Beenden mit Strg+C.\n");
});
