/**
 * stilla · Speicher-Schicht
 * ----------------------------------------------------------------------
 * Zwei Hintergründe hinter EINER Schnittstelle:
 *   - Postgres  (wenn DATABASE_URL gesetzt ist)  -> dauerhaft, übersteht
 *     Neustart/Schlaf des Servers. Nummern bleiben für immer ihrer
 *     Identität zugeordnet und werden nie an jemand anderen vergeben.
 *   - Arbeitsspeicher (sonst) -> für lokale Entwicklung, verliert Daten
 *     beim Neustart (wie bisher).
 *
 * Alle Methoden sind async, damit die Aufrufer identisch bleiben.
 */
const crypto = require("node:crypto");

/* ---------- Arbeitsspeicher-Variante ---------- */
function memStore(){
  const directory=new Map(), mailbox=new Map(), subs=new Map(), backups=new Map();
  return {
    kind:"memory",
    async init(){},
    async setBackup(n,blob){ backups.set(n,blob); },
    async getBackup(n){ return backups.get(n)||null; },
    async getIdentity(n){ return directory.get(n)?{...directory.get(n)}:null; },
    async hasIdentity(n){ return directory.has(n); },
    async setVerified(n){ const e=directory.get(n); if(e){ e.verified=true; directory.set(n,e); return true; } return false; },
    async createIdentity(d){
      let n; do{ n=String(crypto.randomInt(100000000,1000000000)); }while(directory.has(n));
      directory.set(n,{signPub:d.signPub,kexPub:d.kexPub,name:d.name||"",avatar:d.avatar||"",status:d.status||""});
      return n;
    },
    async reclaim(n,d){
      const e=directory.get(n);
      if(e && e.signPub!==d.signPub) return {taken:true};
      directory.set(n,{signPub:d.signPub,kexPub:d.kexPub,name:d.name||"",avatar:d.avatar||"",status:d.status||""});
      return {ok:true};
    },
    async updateProfile(n,d){
      const e=directory.get(n); if(!e) return false;
      if(typeof d.name==="string") e.name=d.name.slice(0,40);
      if(typeof d.avatar==="string") e.avatar=d.avatar.slice(0,200000);
      if(typeof d.status==="string") e.status=d.status.slice(0,60);
      directory.set(n,e); return true;
    },
    async pushMail(to,item){ const q=mailbox.get(to)||[]; q.push(item); mailbox.set(to,q); },
    async fetchMail(n){ const q=mailbox.get(n)||[]; mailbox.delete(n); return q; },
    async setPushSub(n,sub){ subs.set(n,sub); },
    async getPushSub(n){ return subs.get(n)||null; },
    async delPushSub(n){ subs.delete(n); },
  };
}

/* ---------- Postgres-Variante ---------- */
function pgStore(Pool, connectionString){
  const pool = connectionString
    ? new Pool({connectionString, ssl:sslOpt(connectionString)})
    : new Pool();
  const q=(sql,params)=>pool.query(sql,params);
  const api={
    kind:"postgres",
    pool,
    async init(){
      await q(`CREATE TABLE IF NOT EXISTS identities(
        number TEXT PRIMARY KEY,
        sign_pub TEXT, kex_pub TEXT,
        name TEXT DEFAULT '', avatar TEXT DEFAULT '', status TEXT DEFAULT '',
        created_at BIGINT)`);
      try{ await q(`ALTER TABLE identities ADD COLUMN IF NOT EXISTS verified INTEGER DEFAULT 0`); }catch(_){}
      try{ await q(`ALTER TABLE identities ADD COLUMN IF NOT EXISTS email TEXT`); }catch(_){}
      await q(`CREATE TABLE IF NOT EXISTS mailbox(
        id SERIAL PRIMARY KEY,
        to_number TEXT, from_number TEXT, envelope TEXT, ts BIGINT)`);
      try{ await q(`CREATE INDEX IF NOT EXISTS mailbox_to ON mailbox(to_number)`); }catch(_){}
      await q(`CREATE TABLE IF NOT EXISTS push_subs(number TEXT PRIMARY KEY, sub TEXT)`);
      // Mit Passwort verschlüsselte Schlüssel-Sicherung (für Login auf neuen Geräten).
      // Der Server speichert nur den undurchsichtigen, verschlüsselten Block.
      await q(`CREATE TABLE IF NOT EXISTS backups(number TEXT PRIMARY KEY, blob TEXT, updated_at BIGINT)`);
    },
    async setBackup(n,blob){
      await q(`INSERT INTO backups(number,blob,updated_at) VALUES($1,$2,$3)
        ON CONFLICT (number) DO UPDATE SET blob=EXCLUDED.blob, updated_at=EXCLUDED.updated_at`,[n,blob,Date.now()]);
    },
    async getBackup(n){ const r=await q(`SELECT blob FROM backups WHERE number=$1`,[n]); return r.rows.length?r.rows[0].blob:null; },
    async getIdentity(n){
      const r=await q(`SELECT sign_pub,kex_pub,name,avatar,status,verified FROM identities WHERE number=$1`,[n]);
      if(!r.rows.length) return null; const x=r.rows[0];
      return {signPub:x.sign_pub,kexPub:x.kex_pub,name:x.name||"",avatar:x.avatar||"",status:x.status||"",verified:!!x.verified};
    },
    async hasIdentity(n){ const r=await q(`SELECT 1 FROM identities WHERE number=$1`,[n]); return r.rows.length>0; },
    async setVerified(n){ const r=await q(`UPDATE identities SET verified=1 WHERE number=$1`,[n]); return r.rowCount>0; },
    async createIdentity(d){
      for(let i=0;i<10000;i++){
        const n=String(crypto.randomInt(100000000,1000000000));
        const r=await q(`INSERT INTO identities(number,sign_pub,kex_pub,name,avatar,status,created_at)
          VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (number) DO NOTHING`,
          [n,d.signPub,d.kexPub,d.name||"",d.avatar||"",d.status||"",Date.now()]);
        if(r.rowCount===1) return n;
      }
      throw new Error("keine freie Nummer gefunden");
    },
    async reclaim(n,d){
      const e=await api.getIdentity(n);
      if(e && e.signPub!==d.signPub) return {taken:true};          // andere Identität hält die Nummer
      await q(`INSERT INTO identities(number,sign_pub,kex_pub,name,avatar,status,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (number) DO UPDATE SET
          sign_pub=EXCLUDED.sign_pub, kex_pub=EXCLUDED.kex_pub,
          name=EXCLUDED.name, avatar=EXCLUDED.avatar, status=EXCLUDED.status`,
        [n,d.signPub,d.kexPub,d.name||"",d.avatar||"",d.status||"",Date.now()]);
      return {ok:true};
    },
    async updateProfile(n,d){
      const e=await api.getIdentity(n); if(!e) return false;
      const name  = typeof d.name==="string"  ? d.name.slice(0,40)      : e.name;
      const avatar= typeof d.avatar==="string"? d.avatar.slice(0,200000): e.avatar;
      const status= typeof d.status==="string"? d.status.slice(0,60)    : e.status;
      await q(`UPDATE identities SET name=$2,avatar=$3,status=$4 WHERE number=$1`,[n,name,avatar,status]);
      return true;
    },
    async pushMail(to,item){
      // Umschlag ist ein Objekt {n,c}; als JSON-Text ablegen (TEXT-Spalte)
      const env = typeof item.envelope==="string" ? item.envelope : JSON.stringify(item.envelope);
      await q(`INSERT INTO mailbox(to_number,from_number,envelope,ts) VALUES($1,$2,$3,$4)`,
        [to,item.from,env,item.ts]);
    },
    async fetchMail(n){
      const r=await q(`DELETE FROM mailbox WHERE to_number=$1 RETURNING id,from_number,envelope,ts`,[n]);
      return r.rows.sort((a,b)=>Number(a.id)-Number(b.id))
        .map(x=>({from:x.from_number,envelope:parseEnv(x.envelope),ts:Number(x.ts)}));
    },
    async setPushSub(n,sub){
      await q(`INSERT INTO push_subs(number,sub) VALUES($1,$2)
        ON CONFLICT (number) DO UPDATE SET sub=EXCLUDED.sub`,[n,JSON.stringify(sub)]);
    },
    async getPushSub(n){
      const r=await q(`SELECT sub FROM push_subs WHERE number=$1`,[n]);
      try{ return r.rows.length?JSON.parse(r.rows[0].sub):null; }catch{ return null; }
    },
    async delPushSub(n){ await q(`DELETE FROM push_subs WHERE number=$1`,[n]); },
  };
  return api;
}

// Umschlag aus der DB kommt als JSON-Text zurück -> zurück zum Objekt {n,c}
function parseEnv(v){
  if(v && typeof v==="object") return v;
  if(typeof v==="string"){ try{ return JSON.parse(v); }catch{ return v; } }
  return v;
}

function sslOpt(cs){
  // Managed Postgres (Neon/Supabase/Render) verlangt i.d.R. SSL, aber kein Cert-Pinning.
  if(/sslmode=disable/.test(cs)) return false;
  return {rejectUnauthorized:false};
}

function createStore(opts){
  opts=opts||{};
  const cs=opts.connectionString!==undefined ? opts.connectionString : (process.env.DATABASE_URL||"");
  if(opts.Pool) return pgStore(opts.Pool, cs);           // Test: injizierter Pool (z.B. pg-mem)
  if(cs){
    let Pool;
    try{ Pool=require("pg").Pool; }
    catch(e){ console.log("  (Paket 'pg' fehlt – nutze Arbeitsspeicher)"); return memStore(); }
    return pgStore(Pool, cs);
  }
  return memStore();
}

module.exports={createStore,memStore,pgStore};
