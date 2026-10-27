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

const directory = new Map();   // number -> { signPub, kexPub, name }
const mailbox   = new Map();   // number -> [ {from, envelope, ts} ]
const challenges = new Map();
const lastSeen  = new Map();   // number -> Zeitpunkt des letzten Lebenszeichens (Präsenz)
const ONLINE_MS = 30000;       // als "online" gilt, wer < 30 s aktiv war
const nextNumber = () => { for(;;){ const n=String(crypto.randomInt(100000000,1000000000)); if(!directory.has(n)) return n; } };

function send(res,code,obj){ res.writeHead(code,{"Content-Type":"application/json"}); res.end(JSON.stringify(obj)); }
function body(req){ return new Promise(r=>{let d="";req.on("data",c=>d+=c);req.on("end",()=>{try{r(JSON.parse(d||"{}"));}catch{r({});}});}); }

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
