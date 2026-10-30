/**
 * stilla · Cloudflare Worker (immer wach, kein Einschlafen)
 * ----------------------------------------------------------------------
 * Gleiche Logik wie local-server.js, nur als Worker:
 *   - API-Routen werden hier behandelt
 *   - alle statischen Dateien (index.html, manifest.json, sw.js, Icons)
 *     liefert die Assets-Bindung (public/) aus
 *   - Datenbank: Neon (serverless-Treiber, läuft über HTTPS/WebSocket)
 *
 * Secrets/Variablen kommen aus `env` (im Cloudflare-Dashboard gesetzt):
 *   DATABASE_URL, RESEND_API_KEY, APP_URL, MAIL_FROM, VERIFY_SECRET
 *
 * Hinweis: Push-Benachrichtigungen sind in dieser Version noch aus
 * (werden auf Cloudflare separat nachgerüstet). Alles andere ist identisch.
 */
import nacl from "tweetnacl";
import { neon } from "@neondatabase/serverless";
import { createStore } from "./store.js";
import crypto from "node:crypto";

// Neon über HTTP (richtig für Cloudflare Workers – jede Query ist eine eigene HTTP-Anfrage,
// kein Hängen durch Dauerverbindungen). Als "Pool" verpackt, damit store.js unverändert bleibt.
class NeonHttpPool {
  constructor(opts){ this.sql = neon(opts.connectionString, { fullResults: true }); }
  async query(text, params){
    params = params || [];
    let res;
    if(typeof this.sql.query === "function"){
      res = await this.sql.query(text, params);
    } else {
      // Tagged-Template-Weg (immer vorhanden): "$1,$2,…" in Template-Teile zerlegen (unsere Queries nutzen sie in Reihenfolge, je einmal)
      const parts = text.split(/\$\d+/);
      const strings = parts.slice(); strings.raw = parts.slice();
      res = await this.sql(strings, ...params);
    }
    if(Array.isArray(res)) return { rows: res, rowCount: res.length };
    return { rows: res.rows || [], rowCount: (res.rowCount != null ? res.rowCount : (res.rows ? res.rows.length : 0)) };
  }
}

// Präsenz + Login-Nonce: flüchtig, im Worker-Speicher (für kleine Tester-Gruppe ausreichend)
const lastSeen = new Map();
const challenges = new Map();
const ONLINE_MS = 30000;

let _store = null;
function getStore(env){
  if(_store) return _store;
  _store = createStore({ Pool: NeonHttpPool, connectionString: env.DATABASE_URL || "" });
  return _store;
}
let _inited = false;
async function ensureInit(store){ if(_inited) return; await store.init(); _inited = true; }

/* ---------- Helfer ---------- */
const JSONH = { "Content-Type": "application/json" };
const json = (obj, status=200) => new Response(JSON.stringify(obj), { status, headers: JSONH });
async function readBody(request){ try{ return await request.json(); }catch{ return {}; } }

const b64url = b => Buffer.from(b).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
function signData(secret,s){ return crypto.createHmac("sha256",secret).update(s).digest("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
function makeToken(secret,number){ const p=number+"."+(Date.now()+48*3600*1000); return b64url(p)+"."+signData(secret,p); }
function checkToken(secret,tok){ try{ const i=tok.lastIndexOf("."); const b=tok.slice(0,i), sig=tok.slice(i+1);
  const p=Buffer.from(b.replace(/-/g,"+").replace(/_/g,"/"),"base64").toString();
  if(signData(secret,p)!==sig) return null; const [number,exp]=p.split("."); if(Date.now()>Number(exp)) return null; return number;
}catch{ return null; } }
function makeResetToken(secret,number){ const p=number+".reset."+(Date.now()+2*3600*1000); return b64url(p)+"."+signData(secret,p); }
function checkResetToken(secret,tok){ try{ const i=tok.lastIndexOf("."); const b=tok.slice(0,i), sig=tok.slice(i+1);
  const p=Buffer.from(b.replace(/-/g,"+").replace(/_/g,"/"),"base64").toString();
  if(signData(secret,p)!==sig) return null; const [number,kind,exp]=p.split("."); if(kind!=="reset") return null; if(Date.now()>Number(exp)) return null; return number;
}catch{ return null; } }
const validEmail = e => typeof e==="string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length<=120;
const fmtNum = n => String(n).replace(/(\d{3})(\d{3})(\d{3})/,"$1 $2 $3");

function verifyMsg(msg, sigB64, signPubB64){
  try{ return nacl.sign.detached.verify(
    new Uint8Array(Buffer.from(msg,"utf8")),
    new Uint8Array(Buffer.from(sigB64,"base64")),
    new Uint8Array(Buffer.from(signPubB64,"base64"))); }catch{ return false; }
}

/* ---------- E-Mail (Resend) ---------- */
async function sendMail(env, to, subject, html, text){
  if(!env.RESEND_API_KEY) return {ok:false,error:"email-disabled"};
  const from = env.MAIL_FROM || "stilla <noreply@getstilla.me>";
  try{
    const r=await fetch("https://api.resend.com/emails",{method:"POST",
      headers:{"Authorization":"Bearer "+env.RESEND_API_KEY,"Content-Type":"application/json"},
      body:JSON.stringify({from,to:[to],subject,html,text})});
    if(r.ok) return {ok:true};
    const t=await r.text(); console.log("Resend-Fehler",subject,r.status,t); return {ok:false,error:"send-failed",status:r.status};
  }catch(e){ console.log("Resend-Exception",e.message); return {ok:false,error:"send-exception"}; }
}
function mailShell(inner){ return `<div style="font-family:system-ui,sans-serif;background:#10151e;color:#e8eef3;padding:28px;border-radius:14px;max-width:460px;margin:auto"><h2 style="font-family:Georgia,serif;color:#e8eef3">stilla</h2>${inner}</div>`; }
async function sendVerifyMail(env,appUrl,email,number){
  const link=appUrl+"/?verify="+encodeURIComponent(makeToken(env.VERIFY_SECRET,number));
  const html=mailShell(`<p>Bitte bestätige deine E-Mail-Adresse, damit dein Account und deine Nummer erhalten bleiben.</p>
    <p><a href="${link}" style="display:inline-block;background:#58d5c9;color:#07201d;text-decoration:none;font-weight:600;padding:12px 22px;border-radius:10px">E-Mail bestätigen</a></p>
    <p style="color:#8798a8;font-size:13px">Oder diesen Link öffnen:<br>${link}</p>
    <p style="color:#8798a8;font-size:12px">Der Link gilt 48 Stunden. Wenn du das nicht warst, ignoriere diese E-Mail.</p>`);
  return sendMail(env,email,"stilla – E-Mail bestätigen",html,"Bestätige deine E-Mail für stilla: "+link);
}
async function sendResetMail(env,appUrl,email,number){
  const link=appUrl+"/?reset="+encodeURIComponent(makeResetToken(env.VERIFY_SECRET,number));
  const html=mailShell(`<p>Du möchtest das Passwort für Nummer <b>${fmtNum(number)}</b> zurücksetzen. Klick auf den Button, um ein neues Passwort zu vergeben:</p>
    <p><a href="${link}" style="display:inline-block;background:#58d5c9;color:#07201d;text-decoration:none;font-weight:600;padding:12px 22px;border-radius:10px">Passwort neu setzen</a></p>
    <p style="color:#8798a8;font-size:13px">Oder diesen Link öffnen:<br>${link}</p>
    <p style="color:#8798a8;font-size:12px">Der Link gilt 2 Stunden. Wenn du das nicht warst, ignoriere diese E-Mail.</p>`);
  return sendMail(env,email,"stilla – Passwort zurücksetzen",html,"Passwort für stilla-Nummer "+fmtNum(number)+" zurücksetzen: "+link);
}
async function sendRecoverMail(env,email,numbers){
  const list=numbers.map(n=>`<div style="font-family:ui-monospace,monospace;font-size:20px;letter-spacing:2px;color:#58d5c9;margin:6px 0">${fmtNum(n)}</div>`).join("");
  const html=mailShell(`<p>Hier ist ${numbers.length>1?"sind deine stilla-Nummern":"deine stilla-Nummer"}:</p>${list}
    <p style="color:#8798a8;font-size:13px">Zum Einloggen: stilla öffnen → „Einloggen" → Nummer, E-Mail und Passwort eingeben.</p>
    <p style="color:#8798a8;font-size:12px">Wenn du das nicht angefordert hast, ignoriere diese E-Mail einfach.</p>`);
  return sendMail(env,email,"stilla – deine Nummer",html,"Deine stilla-Nummer(n): "+numbers.map(fmtNum).join(", "));
}

/* ---------- Router ---------- */
async function handleApi(request, env){
  const url = new URL(request.url); const p = url.pathname; const m = request.method;

  // /ping braucht KEINE Datenbank -> immer sofort antworten (Health-Check)
  if(m==="GET" && p==="/ping") return new Response("ok",{headers:{"Content-Type":"text/plain","Cache-Control":"no-cache"}});

  const store = getStore(env);
  await ensureInit(store);
  const SECRET = env.VERIFY_SECRET || "stilla-dev-secret-change-me";
  const appUrl = (env.APP_URL && /^https?:\/\//.test(env.APP_URL)) ? env.APP_URL.replace(/\/+$/,"") : url.origin;

  if(m==="POST" && p==="/subscribe"){ const b=await readBody(request); if(b.number&&b.subscription) await store.setPushSub(b.number,b.subscription); return json({ok:true}); }

  if(m==="POST" && p==="/verify/request"){ const b=await readBody(request);
    if(!b.number||!validEmail(b.email)) return json({error:"bad-input"},400);
    try{ if(await store.emailVerifiedElsewhere(b.email.trim(),b.number)) return json({ok:false,error:"email-taken"}); }catch(_){}
    try{ await store.setEmail(b.number,b.email.trim()); }catch(_){}
    const r=await sendVerifyMail(env,appUrl,b.email.trim(),b.number);
    return json(r, r.ok?200:502); }

  if(m==="POST" && p==="/recover"){ const b=await readBody(request);
    if(validEmail(b.email)){ try{ const nums=await store.numbersForEmail(b.email.trim()); if(nums.length) await sendRecoverMail(env,b.email.trim(),nums); }catch(_){} }
    return json({ok:true}); }

  if(m==="POST" && p==="/verify/check"){ const b=await readBody(request);
    const number=checkToken(SECRET,b.token||"");
    if(number){
      try{ const e=await store.getIdentity(number); if(e && e.email && await store.emailVerifiedElsewhere(e.email,number)) return json({ok:false,error:"email-taken"}); }catch(_){}
      try{ await store.setVerified(number); }catch(_){}
      return json({ok:true,number}); }
    return json({ok:false}); }

  if(m==="POST" && p==="/email-taken"){ const b=await readBody(request);
    let taken=false; try{ taken=await store.emailExists((b.email||"").trim()); }catch(_){}
    return json({taken}); }

  if(m==="POST" && p==="/reset/request"){ const b=await readBody(request);
    const number=(b.number||"").replace(/\D/g,"");
    if(/^\d{9}$/.test(number)){ try{ const e=await store.getIdentity(number); if(e && e.email) await sendResetMail(env,appUrl,e.email,number); }catch(_){} }
    return json({ok:true}); }

  if(m==="GET" && p==="/reset/resolve"){ const number=checkResetToken(SECRET,url.searchParams.get("token")||""); return json({number:number||null}); }

  if(m==="POST" && p==="/reset/complete"){ const b=await readBody(request);
    const number=checkResetToken(SECRET,b.token||"");
    if(!number) return json({ok:false,error:"bad-token"});
    if(!b.signPub||!b.kexPub||!b.blob) return json({error:"missing"},400);
    const e=await store.getIdentity(number);
    if(!e) return json({error:"unknown"},404);
    await store.putIdentity(number,{signPub:b.signPub,kexPub:b.kexPub,name:e.name,avatar:e.avatar,status:e.status,email:e.email,verified:e.verified});
    await store.setBackup(number,String(b.blob).slice(0,300000));
    return json({ok:true,number,name:e.name||"",avatar:e.avatar||"",status:e.status||"",email:e.email||""}); }

  if(m==="POST" && p==="/register"){ const b=await readBody(request);
    if(!b.signPub||!b.kexPub) return json({error:"keys missing"},400);
    const number=await store.createIdentity({signPub:b.signPub,kexPub:b.kexPub,name:b.name||"",avatar:b.avatar||"",status:b.status||""});
    return json({number}); }

  if(m==="POST" && p==="/reclaim"){ const b=await readBody(request);
    if(!b.number||!b.signPub||!b.kexPub) return json({error:"missing"},400);
    const r=await store.reclaim(b.number,{signPub:b.signPub,kexPub:b.kexPub,name:b.name||"",avatar:b.avatar||"",status:b.status||""});
    if(r.taken) return json({taken:true},409);
    return json({ok:true,number:b.number}); }

  if(m==="POST" && p==="/backup/set"){ const b=await readBody(request);
    if(!b.number||!b.signPub||!b.signature||!b.blob) return json({error:"missing"},400);
    const e=await store.getIdentity(b.number);
    if(!e) return json({error:"unknown number"},404);
    if(e.signPub!==b.signPub) return json({error:"not owner"},403);
    let ok=false; try{ ok=nacl.sign.detached.verify(new Uint8Array(Buffer.from(b.blob,"utf8")),new Uint8Array(Buffer.from(b.signature,"base64")),new Uint8Array(Buffer.from(b.signPub,"base64"))); }catch{}
    if(!ok) return json({error:"bad-signature"},401);
    await store.setBackup(b.number,String(b.blob).slice(0,300000));
    return json({ok:true}); }

  if(m==="GET" && p==="/backup"){ const n=url.searchParams.get("number"); const blob=await store.getBackup(n); return json({blob:blob||null}); }

  if(m==="POST" && p==="/account/delete"){ const b=await readBody(request);
    if(!b.number||!b.signPub||!b.signature) return json({error:"missing"},400);
    const e=await store.getIdentity(b.number);
    if(!e) return json({ok:true});
    if(e.signPub!==b.signPub) return json({error:"not owner"},403);
    if(!verifyMsg("delete:"+b.number,b.signature,b.signPub)) return json({error:"bad-signature"},401);
    await store.deleteIdentity(b.number);
    return json({ok:true}); }

  if(m==="POST" && p==="/profile"){ const b=await readBody(request);
    const ok=await store.updateProfile(b.number,{name:b.name,avatar:b.avatar,status:b.status});
    if(!ok) return json({error:"unknown number"},404);
    return json({ok:true}); }

  if(m==="GET" && p==="/keys"){ const n=url.searchParams.get("number"); const e=await store.getIdentity(n);
    return e?json({number:n,...e}):json({error:"unknown number"},404); }

  if(m==="GET" && p==="/presence"){ const now=Date.now();
    const nums=(url.searchParams.get("numbers")||"").split(",").filter(Boolean);
    const online=nums.filter(n=>{const t=lastSeen.get(n);return t&&(now-t)<ONLINE_MS;});
    return json({online}); }

  if(m==="POST" && p==="/challenge"){ const b=await readBody(request);
    if(!(await store.hasIdentity(b.number))) return json({error:"unknown number"},404);
    const nonce=Buffer.from(crypto.randomBytes(24)).toString("base64"); challenges.set(b.number,nonce);
    return json({nonce}); }

  if(m==="POST" && p==="/login"){ const b=await readBody(request);
    const nonce=challenges.get(b.number), e=await store.getIdentity(b.number);
    if(!nonce||!e) return json({error:"no challenge"},400); challenges.delete(b.number);
    let ok=false; try{ ok=nacl.sign.detached.verify(new Uint8Array(Buffer.from(nonce,"utf8")),new Uint8Array(Buffer.from(b.signature,"base64")),new Uint8Array(Buffer.from(e.signPub,"base64"))); }catch{}
    return json({ok}, ok?200:401); }

  if(m==="POST" && p==="/send"){ const b=await readBody(request);
    if(b.from) lastSeen.set(b.from,Date.now());
    if(!(await store.hasIdentity(b.to))) return json({error:"unknown recipient"},404);
    await store.pushMail(b.to,{from:b.from,envelope:b.envelope,ts:Number(b.ts)||Date.now()});
    return json({queued:true}); }

  if(m==="POST" && p==="/fetch"){ const b=await readBody(request);
    if(b.number && !b.invisible) lastSeen.set(b.number,Date.now());
    else if(b.number && b.invisible) lastSeen.delete(b.number);
    const q=await store.fetchMail(b.number);
    return json({messages:q}); }

  return null;   // keine API-Route -> Aufrufer liefert statische Datei
}

const API_PREFIXES = ["/ping","/subscribe","/verify/","/recover","/email-taken","/reset/","/register","/reclaim","/backup","/account/","/profile","/keys","/presence","/challenge","/login","/send","/fetch"];
function isApi(pathname){ return API_PREFIXES.some(x => x.endsWith("/") ? pathname.startsWith(x) : pathname===x); }

export default {
  async fetch(request, env, ctx){
    const url = new URL(request.url);
    if(isApi(url.pathname)){
      try{ const r = await handleApi(request, env); if(r) return r; }
      catch(e){ console.log("API-Fehler", url.pathname, e && e.message); return json({error:"server"},500); }
      return json({error:"not found"},404);
    }
    // alles andere: statische Dateien aus public/ (index.html, manifest.json, sw.js, Icons)
    return env.ASSETS.fetch(request);
  }
};
