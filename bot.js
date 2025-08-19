#!/usr/bin/env node
/**
 * SUI AUTO-SELL — FINAL++ (DEX-only, exclude blast.fun) + Auto-TP Harga + GLOBAL master switch
 * --------------------------------------------------------------------------------------------
 * MODE 1 (lama): Auto-sell saat BUY via DEX (per token), jual exact amount pembeli.
 * MODE 2 (lama): Auto-TP — jual saat HARGA token >= target (Aftermath quote).
 * MODE 3 (baru): GLOBAL — master switch:
 *   - ON  → set semua token running=true, 1 loop global pantau semuanya (hemat RPC).
 *   - OFF → set semua token running=false.
 *
 * ENV (.env):
 *   PRIVATE_KEY=0x...                 # ed25519
 *   HTTP_URL=https://fullnode.mainnet.sui.io:443
 *   FAST_POLL_MS=80
 *   SAFE_BPS=300
 *   SELL_LOCK_MS=1500
 *   QUIET_429=true
 *
 *   # Paket yang SELALU DIKECUALIKAN (blacklist). Default: blast.fun
 *   EXCLUDE_PACKAGES=0x779829966a2e8642c310bed79e6ba603e5acd3c31b25d7d4511e2c9303d6e3ef
 *
 *   # Whitelist DEX (opsional). Jika diisi, hanya paket ini yang dianggap DEX.
 *   # DEX_PACKAGES=0x<cetus>,0x<flowx>,0x<aftermath>,0x<turbos>,0x<bluemove>,0x<kriya>
 *
 *   # Mode ketat nama target (tanpa whitelist)
 *   STRICT_DEX_NAMES=false
 *   DEX_NAME_LIST=cetus,clmm,pool,integrate,flowx,aggregator,swap_exact_input,swap_exact_output,swap_tokens,aftermath,amm,stableswap,turbos,router,bluemove,dex,deepbook,db_router,smart_router,route,swap,kriya,bluefin,route_all
 *
 *   # Debug: tampilkan MoveCall targets
 *   DEBUG_DEX_MATCH=false
 *
 *   # Auto-TP (lama)
 *   TP_POLL_MS=1200
 *
 *   # GLOBAL master switch (opsional, bisa ON/OFF dari menu)
 *   MULTI_WALKER=false
 *
 * Install:
 *   npm i aftermath-ts-sdk@1.3.17 --legacy-peer-deps @mysten/sui inquirer dotenv
 */

import 'dotenv/config';
import inquirer from 'inquirer';
import { performance } from 'node:perf_hooks';
import { appendFile, mkdir, readFile, writeFile } from 'fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SuiClient } from '@mysten/sui/client';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { fromHEX } from '@mysten/sui/utils';

// ===== ENV / CONST =====
const SUI = '0x2::sui::SUI';
const HTTP_URL   = process.env.HTTP_URL || 'https://fullnode.mainnet.sui.io:443';
const PRIVATE_KEY= (process.env.PRIVATE_KEY || '').trim();
if (!PRIVATE_KEY) { console.error('❌ PRIVATE_KEY belum diisi'); process.exit(1); }

const FAST_POLL_MS = Math.max(50, Number(process.env.FAST_POLL_MS || '80'));
const SAFE_BPS     = Math.max(0,  Number(process.env.SAFE_BPS     || '300'));
const SELL_LOCK_MS = Math.max(500, Number(process.env.SELL_LOCK_MS || '1500'));
const QUIET_429    = String(process.env.QUIET_429 || 'true').toLowerCase() !== 'false';

const STRICT_DEX_NAMES = String(process.env.STRICT_DEX_NAMES||'false').toLowerCase()==='true';
const DEBUG_DEX_MATCH  = String(process.env.DEBUG_DEX_MATCH||'false').toLowerCase()==='true';

const TP_POLL_MS = Math.max(400, Number(process.env.TP_POLL_MS || '1200')); // Auto-TP poll
const MULTI_WALKER = String(process.env.MULTI_WALKER||'false').toLowerCase()==='true';

const DEFAULT_DEX_NAME_LIST = [
  'cetus','clmm','pool','integrate',
  'flowx','aggregator','swap_exact_input','swap_exact_output','swap_tokens','route_all',
  'aftermath','amm','stableswap','router',
  'turbos','router',
  'bluemove','dex',
  'kriya','bluefin',
  'deepbook','db_router','smart_router','route','swap','router'
];
const DEX_NAME_LIST = (process.env.DEX_NAME_LIST||'')
  .split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
const DEX_NAME_SET = new Set(DEX_NAME_LIST.length? DEX_NAME_LIST : DEFAULT_DEX_NAME_LIST);

// === Blacklist (EXCLUDE) & whitelist (INCLUDE) paket ===
const EXCLUDE_PACKAGES = (process.env.EXCLUDE_PACKAGES||
  '0x779829966a2e8642c310bed79e6ba603e5acd3c31b25d7d4511e2c9303d6e3ef' // blast.fun
).split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);

const DEX_PACKAGES = (process.env.DEX_PACKAGES||'')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

// Fallback regex kalau STRICT false & whitelist kosong
const DEX_NAME_REGEX = /\b(swap|router|cetus|flowx|turbos|bluemove|aftermath|kriya|deepbook)\b/i;

// ===== IO =====
const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const TOK_PATH   = join(__dirname, 'tokens.json');
const LOG_PATH   = join(__dirname, 'activity.log');

async function readJsonSafe(p,d){ try{ return JSON.parse(await readFile(p,'utf8')); }catch{ return d; } }
async function writeJson(p,v){ await writeFile(p, JSON.stringify(v,null,2)); }
async function logLine(s){
  const line = `[${new Date().toISOString()}] ${s}\n`;
  try{
    await appendFile(LOG_PATH,line).catch(async()=>{ await mkdir(dirname(LOG_PATH),{recursive:true}); await appendFile(LOG_PATH,line); });
  }catch{}
}

// ===== Client / Keys =====
const client = new SuiClient({ url: HTTP_URL });
function keypairFromEnv(pk){
  const hex = pk.startsWith('0x') ? pk.slice(2) : pk;
  const bytes = fromHEX(hex);
  const sk = bytes.length === 64 ? bytes.slice(32) : bytes;
  return Ed25519Keypair.fromSecretKey(sk);
}
const keypair = keypairFromEnv(PRIVATE_KEY);
const OWNER   = keypair.getPublicKey().toSuiAddress();

// ===== Utils =====
const sleep = (ms)=> new Promise(r=>setTimeout(r,ms));
const toBig = (v)=>{ try{ return typeof v==='bigint'? v: BigInt(v??0);}catch{ return 0n; } };
const toNum = (v,d=0)=> Number.isFinite(Number(v))? Number(v): d;
const lower = (x)=> String(x||'').toLowerCase();
function isCoinType(s){ return /^0x[0-9a-fA-F]+::[A-Za-z0-9_]+::[A-Za-z0-9_]+$/.test(s||''); }
async function getBalanceRaw(owner, coinType){ const r=await client.getBalance({ owner, coinType }); return BigInt(r.totalBalance||'0'); }
function fmtMist(raw){ const s=BigInt(raw).toString().padStart(10,'0'); const i=s.slice(0,-9)||'0', f=s.slice(-9).replace(/0+$/,''); return f?`${i}.${f}`:i; }

// ===== Decimals cache for Auto-TP =====
const DECIMALS = new Map(); // coinType -> decimals
async function getDecimals(coinType){
  if (DECIMALS.has(coinType)) return DECIMALS.get(coinType);
  const md = await client.getCoinMetadata({ coinType });
  const d = Number(md?.decimals ?? 9);
  DECIMALS.set(coinType, d);
  return d;
}
function pow10(n){ let r=1n; for(let i=0;i<n;i++) r*=10n; return r; }

// ===== tokens.json =====
function normalizeCfg(raw={}){
  return {
    // Lama (oneshot/DEX runner):
    sellPercent: Math.min(100, Math.max(1, toNum(raw.sellPercent, 100))),
    minSellRaw:  toBig(raw.minSellRaw ?? 0),
    cooldownMs:  Math.max(200, toNum(raw.cooldownMs, 900)),
    slippageBps: Math.max(1, Math.min(5000, toNum(raw.slippageBps, 200))),
    running:     !!raw.running,       // runner DEX-only
    lastSellMs:  toNum(raw.lastSellMs, 0),

    // Auto-TP:
    tpRunning:      !!raw.tpRunning,
    tpPriceSui:     Math.max(0, toNum(raw.tpPriceSui, 0)), // target SUI per 1 token
    tpSellPercent:  Math.min(100, Math.max(1, toNum(raw.tpSellPercent, 100))),
    tpProbeRaw:     raw.tpProbeRaw ? toBig(raw.tpProbeRaw) : 0n,
    tpLastHitMs:    toNum(raw.tpLastHitMs, 0),
  };
}
let TOKENS = new Map();
async function loadTokens(){
  const data=await readJsonSafe(TOK_PATH,{});
  const map=new Map();
  if (Array.isArray(data)) for(const it of data) if(it?.coinType&&isCoinType(it.coinType)) map.set(it.coinType, normalizeCfg(it));
  else if (data && typeof data==='object') for(const [k,v] of Object.entries(data)) if(isCoinType(k)) map.set(k, normalizeCfg(v));
  return map;
}
async function saveTokens(){
  const obj={};
  for(const [k,vr] of TOKENS){
    const v=normalizeCfg(vr);
    obj[k]={
      sellPercent:v.sellPercent, minSellRaw:v.minSellRaw.toString(), cooldownMs:v.cooldownMs,
      slippageBps:v.slippageBps, running:v.running, lastSellMs:v.lastSellMs,
      tpRunning:v.tpRunning, tpPriceSui:v.tpPriceSui, tpSellPercent:v.tpSellPercent,
      tpProbeRaw:(v.tpProbeRaw||0n).toString(), tpLastHitMs:v.tpLastHitMs
    };
  }
  await writeJson(TOK_PATH, obj);
}

// ===== Locks / Dedupe =====
const RUNNERS    = new Map();        // coinType -> stop() for DEX runner
const SUBMITTING = new Map();        // coinType -> bool (shared)
const SELL_LOCK  = new Map();        // coinType -> untilTs
const SEEN_BUY   = new Map();        // coinType -> Set<digest> (LRU)
// Auto-TP runner
const TP_RUNNERS = new Map();        // coinType -> stop()
// GLOBAL master
let GLOBAL_RUN = false;

function lockActive(ct){ const until=SELL_LOCK.get(ct)||0; return Date.now()<until; }
function armLock(ct, ms){ SELL_LOCK.set(ct, Date.now()+Math.max(SELL_LOCK_MS, ms||0)); }
function seenSet(ct){ let s=SEEN_BUY.get(ct); if(!s){ s=new Set(); SEEN_BUY.set(ct,s);} return s; }
function rememberDigest(ct, dig){ if(!dig) return; const s=seenSet(ct); s.add(dig); if(s.size>500){ const arr=[...s]; s.clear(); for(const d of arr.slice(-200)) s.add(d); } }
function alreadySeen(ct, dig){ return !!dig && seenSet(ct).has(dig); }

// ===== Deep scan MoveCall targets =====
function looksLikeTarget(s){
  if (typeof s !== 'string') return false;
  const parts = s.split('::');
  return parts.length >= 3 && /^0x[0-9a-fA-F]+$/.test(parts[0]);
}
function composeTarget(pkg, mod, fn){
  if (!pkg || !mod || !fn) return null;
  const p = String(pkg), m=String(mod), f=String(fn);
  if (!/^0x[0-9a-fA-F]+$/.test(p)) return null;
  return `${p}::${m}::${f}`;
}
function deepCollectTargets(root){
  const out = new Set();
  const stack = [root];
  const seen = new Set();
  while (stack.length){
    const cur = stack.pop();
    if (!cur || typeof cur !== 'object') continue;
    if (seen.has(cur)) continue; seen.add(cur);

    const directTargets = [
      cur?.MoveCall?.target, cur?.MoveCall?.Target,
      cur?.moveCall?.target, cur?.moveCall?.Target,
      cur?.target, cur?.Target, cur?.targetFunction
    ];
    for (const t of directTargets) if (looksLikeTarget(t)) out.add(String(t));

    if (cur?.MoveCall && (cur.MoveCall.package || cur.MoveCall.module || cur.MoveCall.function)){
      const t = composeTarget(cur.MoveCall.package, cur.MoveCall.module, cur.MoveCall.function);
      if (t) out.add(t);
    }
    if (cur?.package && cur?.module && cur?.function){
      const t = composeTarget(cur.package, cur.module, cur.function);
      if (t) out.add(t);
    }
    for (const k of Object.keys(cur)){
      const v = cur[k];
      if (!v) continue;
      if (Array.isArray(v)) for (const it of v) stack.push(it);
      else if (typeof v === 'object') stack.push(v);
    }
  }
  return [...out];
}
function collectProgrammableTransactions(tx){
  const buckets = [];
  const t = tx?.transaction;
  buckets.push(t?.data?.transaction?.transactions);
  buckets.push(t?.data?.transactions);
  buckets.push(t?.data?.transaction?.kind?.ProgrammableTransaction?.transactions);
  buckets.push(t?.data?.kind?.ProgrammableTransaction?.transactions);
  buckets.push(tx?.effects?.transaction?.kind?.ProgrammableTransaction?.transactions);
  buckets.push(tx?.programmableTransaction?.transactions);
  return buckets.filter(Array.isArray).flat();
}
function parseMoveCallTargets(tx){
  const targets = new Set();
  const progTxs = collectProgrammableTransactions(tx);
  for (const node of progTxs) for (const f of deepCollectTargets(node)) targets.add(f);
  for (const f of deepCollectTargets(tx)) targets.add(f);
  const arr = [...targets];
  if (DEBUG_DEX_MATCH) console.log('[DEBUG] MoveCall targets:', arr.length? arr.join(' | ') : '(none)');
  return arr;
}

// ===== BUY validator: wajib DEX & bukan EXCLUDED =====
function hasExcludedPackage(targets){
  for (const tgt of targets){
    const pkg = String(tgt).split('::')[0].toLowerCase();
    if (EXCLUDE_PACKAGES.includes(pkg)) return true;
  }
  return false;
}
function anyDexMoveCall(targets){
  if (!targets || !targets.length) return false;
  if (hasExcludedPackage(targets)) return false; // blacklist

  if (DEX_PACKAGES.length>0){
    for (const tgt of targets){
      const pkg = String(tgt).split('::')[0].toLowerCase();
      if (DEX_PACKAGES.includes(pkg)) return true;
    }
    return false;
  }
  if (STRICT_DEX_NAMES){
    for (const tgt of targets){
      const l = String(tgt).toLowerCase();
      const [pkg, mod, fn] = l.split('::');
      const fields = [l, pkg||'', mod||'', fn||''];
      for (const f of fields){
        for (const key of DEX_NAME_SET){
          if (f.includes(key)) return true;
        }
      }
    }
    return false;
  }
  return targets.some(t => DEX_NAME_REGEX.test(String(t)));
}
function buyerSuiOutTokenIn(balanceChanges, buyerAddr, coinType){
  if (!Array.isArray(balanceChanges)) return false;
  let gotToken=0n, spentSui=0n;
  for(const bc of balanceChanges){
    const own = lower(bc?.owner?.AddressOwner||'');
    if (own !== lower(buyerAddr)) continue;
    if (bc?.coinType === coinType){ try{ gotToken += BigInt(bc.amount||0); }catch{} }
    if (bc?.coinType === SUI){     try{ spentSui += BigInt(bc.amount||0); }catch{} }
  }
  return (gotToken > 0n) && (spentSui < 0n);
}
async function confirmDexBuy(digest, coinType, buyerAddr){
  if (!digest) return false;
  try{
    const tx = await client.getTransactionBlock({
      digest,
      options:{ showBalanceChanges:true, showEvents:false, showInput:true, showEffects:true }
    });
    const swapPattern = buyerSuiOutTokenIn(tx?.balanceChanges||[], buyerAddr, coinType);
    if (!swapPattern) return false;
    const targets = parseMoveCallTargets(tx);
    if (hasExcludedPackage(targets)){
      if (DEBUG_DEX_MATCH) console.log(`[DEBUG] digest=${digest} SKIP (EXCLUDED PKG)`);
      return false;
    }
    const dexOK = anyDexMoveCall(targets);
    if (DEBUG_DEX_MATCH) console.log(`[DEBUG] digest=${digest} buyer=${buyerAddr} dexOK=${dexOK} targets=${targets.length}`);
    return dexOK;
  }catch(e){
    await logLine(`[DETECT WARN] getTx ${coinType}: ${e?.message||e}`);
    return false;
  }
}

// ===== Aftermath swap =====
let AF=null, ROUTER=null;
async function ensureAftermath(){ if(ROUTER) return ROUTER; const mod=await import('aftermath-ts-sdk'); AF=mod.Aftermath; ROUTER=new AF('MAINNET').Router(); return ROUTER; }
function extractEst(any){
  if(!any) return 0n;
  const KEYS=['coinOutAmount','amountOut','estimatedAmountOut','expectedAmountOut','outAmount','totalAmountOut','minAmountOut'];
  let best=0n;
  (function scan(o){
    if(!o||typeof o!=='object') return;
    for(const k of Object.keys(o)){
      const v=o[k];
      if(v&&typeof v==='object') scan(v);
      else if(KEYS.includes(k)){ try{ const n=BigInt(String(v)); if(n>best) best=n; }catch{} }
    }
    if(Array.isArray(o.routes)) for(const r of o.routes) scan(r);
  })(any);
  return best;
}
async function buildSwapBytes(coinType, amountIn, slippageBps){
  const r = await ensureAftermath();
  const route = await r.getCompleteTradeRouteGivenAmountIn({
    coinInType: coinType, coinOutType: SUI, coinInAmount: BigInt(amountIn)
  });
  if(!route || !route.routes?.length) throw new Error('No route');

  const usedBps = Math.min(9900, Math.max(1, Number(slippageBps||200) + SAFE_BPS));
  const tx = await r.getTransactionForCompleteTradeRoute({
    walletAddress: OWNER, completeRoute: route, slippage: usedBps/10_000
  });
  try{ if(typeof tx.setGasOwner==='function') tx.setGasOwner(OWNER); }catch{}
  const bytes = await tx.build({ client });
  const estOut = extractEst(route);
  return { bytes, estOut, usedBps };
}
async function submitFast(bytes){
  return await client.signAndExecuteTransaction({
    signer: keypair, transaction: bytes,
    options: { showEffects: true, showEvents: true },
    requestType: 'WaitForLocalExecution',
  });
}

// ===== SELL exact (trigger DEX) =====
async function sellExactOnce(coinType, buyerAmountRaw){
  if (SUBMITTING.get(coinType)) return { skipped:'busy' };
  if (!buyerAmountRaw || buyerAmountRaw<=0n) return { skipped:'zero' };
  const cfg = normalizeCfg(TOKENS.get(coinType)||{});
  if (lockActive(coinType)) return { skipped:'locked' };

  SUBMITTING.set(coinType,true);
  try{
    const bal=await getBalanceRaw(OWNER, coinType);
    if (bal<=0n) return { skipped:'no_balance' };
    const amountIn = buyerAmountRaw > bal ? bal : buyerAmountRaw;

    const t0=performance.now();
    const { bytes, estOut, usedBps } = await buildSwapBytes(coinType, amountIn, cfg.slippageBps);
    const res = await submitFast(bytes);
    const ok  = res?.effects?.status?.status==='success';
    const ms  = (performance.now()-t0).toFixed(0);

    if (!ok) {
      await logLine(`[SELL ABORT] ${coinType} exact=${amountIn} ms=${ms} slipBps=${usedBps}`);
      armLock(coinType, cfg.cooldownMs);
      return { failed: res?.effects?.status?.error || 'abort' };
    }
    console.log(`✅ [SELL OK] ${coinType} exact=${amountIn} digest=${res.digest} (~${ms}ms) estOut≈${fmtMist(estOut)} SUI (slip=${(usedBps/100).toFixed(2)}%)`);
    await logLine(`[SELL OK] ${coinType} exact=${amountIn} dig=${res.digest} ms=${ms} estOut=${estOut} slip=${usedBps}`);
    armLock(coinType, cfg.cooldownMs);
    return { digest: res.digest };
  }catch(e){
    await logLine(`[SELL FAIL] ${coinType}: ${e?.message||e}`);
    armLock(coinType, cfg.cooldownMs);
    return { failed: String(e?.message||e) };
  }finally{
    SUBMITTING.set(coinType,false);
  }
}

// ===== SELL by percent (Auto-TP) =====
async function sellPercentOnce(coinType, percent){
  if (SUBMITTING.get(coinType)) return { skipped:'busy' };
  percent = Math.min(100, Math.max(1, Number(percent||100)));
  const cfg = normalizeCfg(TOKENS.get(coinType)||{});
  if (lockActive(coinType)) return { skipped:'locked' };

  SUBMITTING.set(coinType,true);
  try{
    const bal=await getBalanceRaw(OWNER, coinType);
    if (bal<=0n) return { skipped:'no_balance' };
    const amountIn = (bal*BigInt(Math.floor(percent)))/100n;
    if (amountIn<=0n) return { skipped:'zero_calc' };

    const t0=performance.now();
    const { bytes, estOut, usedBps } = await buildSwapBytes(coinType, amountIn, cfg.slippageBps);
    const res = await submitFast(bytes);
    const ok  = res?.effects?.status?.status==='success';
    const ms  = (performance.now()-t0).toFixed(0);

    if (!ok) {
      await logLine(`[TP ABORT] ${coinType} pct=${percent}% ms=${ms} slipBps=${usedBps}`);
      armLock(coinType, cfg.cooldownMs);
      return { failed: res?.effects?.status?.error || 'abort' };
    }
    console.log(`🎯✅ [TP SELL OK] ${coinType} pct=${percent}% digest=${res.digest} (~${ms}ms) estOut≈${fmtMist(estOut)} SUI`);
    await logLine(`[TP SELL OK] ${coinType} pct=${percent} dig=${res.digest} ms=${ms} estOut=${estOut} slip=${usedBps}`);
    armLock(coinType, cfg.cooldownMs);
    return { digest: res.digest };
  }catch(e){
    await logLine(`[TP SELL FAIL] ${coinType}: ${e?.message||e}`);
    armLock(coinType, cfg.cooldownMs);
    return { failed: String(e?.message||e) };
  }finally{
    SUBMITTING.set(coinType,false);
  }
}

// ===== Detector (DEX-only BUY + dedupe) — per token =====
function transferEventType(ct){ return `0x2::coin::TransferEvent<${ct}>`; }
const rateLogState={ last:0, count:0 };
async function warn429(tag, ct, msg){
  const is429=/429/.test(msg||'');
  if (is429 && QUIET_429){
    rateLogState.count++; const n=Date.now();
    if(n-rateLogState.last>4000){
      await logLine(`[DETECT WARN] 429 x${rateLogState.count} (throttled)`);
      rateLogState.last=n; rateLogState.count=0;
    }
  } else {
    await logLine(`[DETECT WARN] ${tag} ${ct}: ${msg}`);
  }
}
function pickDigestFromEvent(ev){
  return ev?.id?.txDigest || ev?.transactionDigest || ev?.id || null;
}
async function triggerSellExact(coinType, digestHint, buyerAmountRaw){
  if (!buyerAmountRaw || buyerAmountRaw<=0n) return;
  if (digestHint && alreadySeen(coinType, digestHint)) return;  // 1x/tx
  if (digestHint) rememberDigest(coinType, digestHint);
  await sellExactOnce(coinType, buyerAmountRaw);
}
async function detectLoop(coinType){
  let cursor=null, nextCp=null;
  let seenEv=new Set(), seenTx=new Set();

  while(RUNNERS.has(coinType)){
    let triggered=false;

    // 1) Events: Transfer<coinType> (fast path)
    try{
      const resp=await client.queryEvents({ query:{ MoveEventType: transferEventType(coinType) }, cursor: cursor??null, limit:40, order:'descending' });
      const evs=resp?.data||[]; if(evs.length) cursor=evs[0].id;
      for(const ev of evs){
        if(!RUNNERS.has(coinType)) break;
        const evKey = `${ev.id?.txDigest || ev.id?.eventSeq || JSON.stringify(ev.id)}`;
        if(seenEv.has(evKey)) continue; seenEv.add(evKey); if(seenEv.size>1200) seenEv=new Set([...seenEv].slice(-400));

        const pj=ev.parsedJson||{};
        const to = lower(pj.to||pj.recipient||'');
        const amt= toBig(pj.amount??pj.value??0);
        const dig = pickDigestFromEvent(ev);

        if(amt>0n && to && to!==lower(OWNER)){
          const okBuy = await confirmDexBuy(dig, coinType, to);
          if (okBuy){
            const cfg=normalizeCfg(TOKENS.get(coinType)||{}); const n=Date.now();
            if(!lockActive(coinType) && (n-(cfg.lastSellMs||0)>=cfg.cooldownMs)){
              TOKENS.set(coinType,{...cfg,lastSellMs:n,running:true}); await saveTokens();
              await triggerSellExact(coinType, dig, amt);
              triggered=true; break;
            }
          } else if (DEBUG_DEX_MATCH) {
            console.log(`[DEBUG] Skip digest=${dig} — bukan DEX / EXCLUDED.`);
          }
        }
      }
    }catch(e){ await warn429('events',coinType,String(e?.message||e)); }

    // 2) Checkpoint walker (backup)
    if(!triggered){
      try{
        const latestStr = await client.getLatestCheckpointSequenceNumber();
        const latest = Number(latestStr||0);
        if(!Number.isFinite(latest)) throw new Error('bad latest checkpoint');
        if(nextCp==null) nextCp=Math.max(0, latest-2);
        let steps=0;
        while(steps<3 && nextCp<=latest){
          const cp=await client.getCheckpoint({ id:String(nextCp) }); nextCp++; steps++;
          const digs=cp?.transactions||[]; if(!digs.length) continue;

          const txs=await client.multiGetTransactionBlocks({ digests:digs, options:{ showBalanceChanges:true, showInput:true, showEvents:false, showEffects:true } });
          for(const tx of (txs||[])){
            if(!tx?.digest || seenTx.has(tx.digest)) continue; seenTx.add(tx.digest); if(seenTx.size>2000) seenTx=new Set([...seenTx].slice(-700));

            const targets = parseMoveCallTargets(tx);
            if (hasExcludedPackage(targets)) { if (DEBUG_DEX_MATCH) console.log(`[DEBUG] Walker skip ${tx.digest} — EXCLUDED PKG`); continue; }

            for(const bc of (tx.balanceChanges||[])){
              if(bc?.coinType!==coinType) continue;
              const recv=lower(bc?.owner?.AddressOwner||''); const amt=toBig(bc.amount||'0');
              if(amt>0n && recv && recv!==lower(OWNER)){
                let okBuy = buyerSuiOutTokenIn(tx?.balanceChanges||[], recv, coinType);
                if (okBuy) okBuy = anyDexMoveCall(targets);
                if (okBuy){
                  const cfg=normalizeCfg(TOKENS.get(coinType)||{}); const n=Date.now();
                  if(!lockActive(coinType) && (n-(cfg.lastSellMs||0)>=cfg.cooldownMs)){
                    TOKENS.set(coinType,{...cfg,lastSellMs:n,running:true}); await saveTokens();
                    await triggerSellExact(coinType, tx.digest, amt);
                    triggered=true; break;
                  }
                } else if (DEBUG_DEX_MATCH) {
                  console.log(`[DEBUG] Walker skip digest=${tx.digest} — bukan DEX / EXCLUDED.`);
                }
              }
            }
            if(triggered) break;
          }
          if(triggered) break;
        }
      }catch(e){ await warn429('cp',coinType,String(e?.message||e)); }
    }

    await sleep(FAST_POLL_MS);
  }
}

// ===== GLOBAL Walker (pantau semua token running=true) =====
async function detectLoopGlobal(){
  let nextCp=null;
  let seenTx=new Set();

  while (GLOBAL_RUN){
    try{
      const latestStr = await client.getLatestCheckpointSequenceNumber();
      const latest = Number(latestStr||0);
      if(!Number.isFinite(latest)) throw new Error('bad latest checkpoint');
      if(nextCp==null) nextCp=Math.max(0, latest-2);

      let steps=0;
      while (GLOBAL_RUN && steps<5 && nextCp<=latest){
        const cp=await client.getCheckpoint({ id:String(nextCp) }); nextCp++; steps++;
        const digs=cp?.transactions||[];
        if(!digs.length) continue;

        const txs=await client.multiGetTransactionBlocks({
          digests:digs,
          options:{ showBalanceChanges:true, showInput:true, showEvents:false, showEffects:true }
        });

        // Siapkan daftar token aktif
        const ACTIVE = new Set();
        for (const [ct, cfg] of TOKENS){ if (cfg && cfg.running) ACTIVE.add(ct); }
        if (!ACTIVE.size) continue;

        for(const tx of (txs||[])){
          if(!GLOBAL_RUN) break;
          if(!tx?.digest || seenTx.has(tx.digest)) continue;
          seenTx.add(tx.digest); if(seenTx.size>4000) seenTx=new Set([...seenTx].slice(-1500));

          const targets = parseMoveCallTargets(tx);
          if (hasExcludedPackage(targets)) continue;

          const bcs = tx.balanceChanges||[];
          if(!bcs.length) continue;

          for(const bc of bcs){
            const ct = bc?.coinType;
            if (!ct || !ACTIVE.has(ct)) continue;

            const recv=lower(bc?.owner?.AddressOwner||'');
            const amt=toBig(bc?.amount||'0');
            if (amt<=0n || !recv || recv===lower(OWNER)) continue;

            let okBuy = buyerSuiOutTokenIn(bcs, recv, ct);
            if (okBuy) okBuy = anyDexMoveCall(targets);
            if (!okBuy) continue;

            if (alreadySeen(ct, tx.digest)) continue;
            rememberDigest(ct, tx.digest);

            const cfg=normalizeCfg(TOKENS.get(ct)||{});
            const n=Date.now();
            if (lockActive(ct) || (n-(cfg.lastSellMs||0)<cfg.cooldownMs)) continue;

            TOKENS.set(ct,{...cfg,lastSellMs:n}); await saveTokens();
            await sellExactOnce(ct, amt);
          }
        }
      }
    }catch(e){
      await warn429('global','*',String(e?.message||e));
    }
    await sleep(FAST_POLL_MS);
  }
}
async function startGlobalAutoSell(){
  if (GLOBAL_RUN) return;
  // 1) Set semua token running=true
  let changes=0;
  for (const [ct, cfg0] of TOKENS){
    const cfg = normalizeCfg(cfg0||{});
    if (!cfg.running){ TOKENS.set(ct,{...cfg, running:true}); changes++; }
  }
  if (changes>0){ await saveTokens(); console.log(`⚡ GLOBAL: set running=true untuk ${changes} token`); }
  // 2) Start loop global
  GLOBAL_RUN = true;
  detectLoopGlobal().catch(async e=>{ await logLine(`[GLOBAL ERROR] ${e?.message||e}`); });
  console.log(`⚡ GLOBAL Auto-sell ON (multi token; 1 loop pantau semua token)`);
}
async function stopGlobalAutoSell(){
  // 1) Stop loop
  GLOBAL_RUN = false;
  // 2) Balikkan semua token ke running=false
  let changes=0;
  for (const [ct, cfg0] of TOKENS){
    const cfg = normalizeCfg(cfg0||{});
    if (cfg.running){ TOKENS.set(ct,{...cfg, running:false}); changes++; }
  }
  if (changes>0){ await saveTokens(); console.log(`⏸️ GLOBAL: set running=false untuk ${changes} token`); }
  console.log(`⏸️ GLOBAL Auto-sell OFF`);
}

// ===== Auto-TP runner =====
async function ensureProbe(coinType){
  const cfg = normalizeCfg(TOKENS.get(coinType)||{});
  if (cfg.tpProbeRaw && cfg.tpProbeRaw>0n) return cfg.tpProbeRaw;
  const dec = await getDecimals(coinType);
  const probe = pow10(BigInt(dec)); // 1 token dalam raw units
  TOKENS.set(coinType, { ...cfg, tpProbeRaw: probe }); await saveTokens();
  return probe;
}
async function getQuoteSui(coinType, amountInRaw){
  const r = await ensureAftermath();
  const route = await r.getCompleteTradeRouteGivenAmountIn({
    coinInType: coinType, coinOutType: SUI, coinInAmount: BigInt(amountInRaw)
  });
  if(!route || !route.routes?.length) return 0n;
  return extractEst(route); // raw SUI (9 desimal)
}
async function tpLoop(coinType){
  while (TP_RUNNERS.has(coinType)){
    try{
      const cfg = normalizeCfg(TOKENS.get(coinType)||{});
      if (!cfg.tpRunning || cfg.tpPriceSui<=0) { await sleep(TP_POLL_MS); continue; }

      const probe = await ensureProbe(coinType);
      const quoteOut = await getQuoteSui(coinType, probe); // raw SUI
      const targetOut = BigInt(Math.floor(cfg.tpPriceSui * 1e9)); // SUI per 1 token → raw 9 desimal

      if (quoteOut >= targetOut){
        const n=Date.now();
        if(!lockActive(coinType) && (n-(cfg.lastSellMs||0)>=cfg.cooldownMs)){
          TOKENS.set(coinType,{...cfg,lastSellMs:n}); await saveTokens();
          console.log(`🎯 Target tercapai for ${coinType}: quote≈${fmtMist(quoteOut)} SUI ≥ target ${cfg.tpPriceSui}`);
          await sellPercentOnce(coinType, cfg.tpSellPercent);
        }
      }
    }catch(e){
      const msg = String(e?.message||e);
      if(!/429/.test(msg)) await logLine(`[TP WARN] ${coinType}: ${msg}`);
    }
    await sleep(TP_POLL_MS);
  }
}
async function startAutoTP(coinType){
  if (TP_RUNNERS.has(coinType)) return;
  TP_RUNNERS.set(coinType, { stop:()=> TP_RUNNERS.delete(coinType) });
  const cfg=normalizeCfg(TOKENS.get(coinType)||{});
  TOKENS.set(coinType,{...cfg,tpRunning:true}); await saveTokens();
  tpLoop(coinType).catch(async e=>{ await logLine(`[TP ERROR] ${coinType}: ${e?.message||e}`); });
  console.log(`🎯 Auto-TP ON ${coinType} (poll ~${TP_POLL_MS}ms)`);
}
async function stopAutoTP(coinType){
  const r=TP_RUNNERS.get(coinType); if(r){ try{ r.stop(); }catch{} }
  TP_RUNNERS.delete(coinType);
  const cfg=normalizeCfg(TOKENS.get(coinType)||{});
  TOKENS.set(coinType,{...cfg,tpRunning:false}); await saveTokens();
  console.log(`🎯⏸️ Auto-TP OFF ${coinType}`);
}

// ===== ON/OFF DEX runner (per token) =====
async function startAutoSell(coinType){
  if(RUNNERS.has(coinType)) return;
  RUNNERS.set(coinType, { stop:()=> RUNNERS.delete(coinType) });
  const cfg=normalizeCfg(TOKENS.get(coinType)||{});
  TOKENS.set(coinType,{...cfg,running:true}); await saveTokens();
  detectLoop(coinType).catch(async e=>{ await logLine(`[DETECT ERROR] ${coinType}: ${e?.message||e}`); });
  console.log(`▶️ Auto-sell ON ${coinType} (DEX-only, poll ~${FAST_POLL_MS}ms)`);
}
async function stopAutoSell(coinType){
  const r=RUNNERS.get(coinType); if(r){ try{ r.stop(); }catch{} }
  RUNNERS.delete(coinType);
  const cfg=normalizeCfg(TOKENS.get(coinType)||{});
  TOKENS.set(coinType,{...cfg,running:false}); await saveTokens();
  console.log(`⏸️ Auto-sell OFF ${coinType}`);
}

// ===== Menu =====
async function promptAddOrEdit(existing){
  const base=normalizeCfg(existing||{});
  const ans=await inquirer.prompt([
    { name:'coinType', message:'Coin type (0x..::mod::SYMBOL)', when:!existing, validate:v=>isCoinType(v)||'Format salah' },
    { name:'sellPercent', message:'Sell % (untuk Test SELL manual)', default: base.sellPercent, filter:Number },
    { name:'minSellRaw',  message:'Min sell (raw units)',           default: base.minSellRaw.toString(), filter:v=>BigInt(v) },
    { name:'cooldownMs',  message:'Cooldown antar SELL (ms)',       default: base.cooldownMs, filter:Number },
    { name:'slippageBps', message:'Slippage (bps)',                 default: base.slippageBps, filter:Number },
  ]);
  return ans;
}
async function promptSetTP(existing){
  const base=normalizeCfg(existing||{});
  const dec = await getDecimals(existing?.coinType || (await (async()=>{throw new Error('Pilih token dahulu');})()));
  const ans=await inquirer.prompt([
    { name:'tpPriceSui',    message:`Target harga (SUI per 1 token, desimal token=${dec})`, default: base.tpPriceSui||0, filter:Number },
    { name:'tpSellPercent', message:'Sell % saat TP', default: base.tpSellPercent||100, filter:Number },
  ]);
  ans.tpPriceSui = Math.max(0, Number(ans.tpPriceSui||0));
  ans.tpSellPercent = Math.min(100, Math.max(1, Number(ans.tpSellPercent||100)));
  return ans;
}
function renderTable(){
  const rows=[];
  for(const [k,vr] of TOKENS){
    const v=normalizeCfg(vr);
    rows.push({
      coinType:k, sellPct:v.sellPercent, cooldownMs:v.cooldownMs, slipBps:v.slippageBps,
      running:!!v.running, lastSell:v.lastSellMs? new Date(v.lastSellMs).toLocaleTimeString():'-',
      tpRunning:!!v.tpRunning, tpPriceSui:v.tpPriceSui, tpSellPct:v.tpSellPercent
    });
  }
  console.table(rows);
}
async function viewActivityLog(){
  const buf=await readFile(LOG_PATH,'utf8').catch(()=> '' );
  const lines=(buf?buf.trim().split('\n'):[]).slice(-200);
  console.log('\n===== ACTIVITY LOG (last 200) ====='); console.log(lines.join('\n') || '(log kosong)'); console.log('===================================\n');
  await inquirer.prompt([{ type:'input', name:'ok', message:'Enter untuk kembali' }]);
}
async function autoStartSaved(){
  const fixed=new Map(); for(const [k,v] of await loadTokens()) fixed.set(k, normalizeCfg(v)); TOKENS=fixed; await saveTokens();

  // GLOBAL master switch di startup
  if (MULTI_WALKER){
    await startGlobalAutoSell();
  } else {
    // Perilaku lama: start per token jika running=true
    for(const [k,v] of TOKENS){ if(v.running) startAutoSell(k); if(v.tpRunning) startAutoTP(k); }
  }
}

async function menu(){
  await autoStartSaved();
  while(true){
    const suiBal=fmtMist(await getBalanceRaw(OWNER,SUI));
    console.log(`\nRPC: ${HTTP_URL}`); console.log(`Owner: ${OWNER}`); console.log(`SUI Balance: ${suiBal}`);
    const {action}=await inquirer.prompt({
      type:'list', name:'action', message:'Pilih menu', pageSize:16, choices:[
        {name:'➕ Tambah token', value:'add'},
        {name:'✏️  Ubah token', value:'edit'},
        {name:'🚀 Test SELL sekali (submit sekarang)', value:'oneshot'},
        {name:'⚡ Auto-sell ON/OFF (DEX-only per token)', value:'toggle_dex'},
        {name:'⚡ Auto-sell GLOBAL ON/OFF (multi token)', value:'toggle_global'},
        {name:'🎯 Set TP Harga & Sell %', value:'set_tp'},
        {name:'🎯 Auto-TP ON/OFF (harga target)', value:'toggle_tp'},
        {name:'📋 Lihat status token', value:'list'},
        {name:'📜 Lihat activity.log (last 200)', value:'log'},
        {name:'Keluar', value:'exit'},
      ]
    });

    if(action==='add'){
      const a=await promptAddOrEdit();
      if(TOKENS.has(a.coinType)) console.log('Token sudah ada. Pakai menu Ubah.');
      else { TOKENS.set(a.coinType,{...normalizeCfg(a), running:false, tpRunning:false, lastSellMs:0 }); await saveTokens(); console.log(`[ADD] ${a.coinType}`); }
    }

    if(action==='edit'){
      if(!TOKENS.size){ console.log('Belum ada token.'); continue; }
      const {key}=await inquirer.prompt({ type:'list', name:'key', message:'Pilih token', choices:[...TOKENS.keys()] });
      const cur={...normalizeCfg(TOKENS.get(key)||{}), coinType:key}; const upd=await promptAddOrEdit(cur);
      TOKENS.set(key,{...normalizeCfg(cur), ...normalizeCfg(upd)}); await saveTokens(); console.log(`[EDIT] ${key}`);
    }

    if(action==='oneshot'){
      if(!TOKENS.size){ console.log('Belum ada token.'); continue; }
      const {key}=await inquirer.prompt({ type:'list', name:'key', message:'Pilih token', choices:[...TOKENS.keys()] });
      const cfg=normalizeCfg(TOKENS.get(key)||{});
      const bal=await getBalanceRaw(OWNER,key);
      const amountIn=(bal*BigInt(cfg.sellPercent))/100n;
      if(amountIn<=0n){ console.log('Saldo 0.'); continue; }
      console.log(`[TEST SELL] ${key} exact=${amountIn} …`);
      await sellExactOnce(key, amountIn);
    }

    if(action==='toggle_dex'){
      if(!TOKENS.size){ console.log('Belum ada token.'); continue; }
      const {key}=await inquirer.prompt({ type:'list', name:'key', message:'Pilih token (DEX runner)', choices:[...TOKENS.keys()] });
      const cfg=normalizeCfg(TOKENS.get(key)||{});
      if(!cfg.running){ TOKENS.set(key,{...cfg, running:true}); await saveTokens(); await startAutoSell(key); }
      else { await stopAutoSell(key); }
    }

    if(action==='toggle_global'){
      if (!GLOBAL_RUN){
        await startGlobalAutoSell();
      } else {
        await stopGlobalAutoSell();
      }
    }

    if(action==='set_tp'){
      if(!TOKENS.size){ console.log('Belum ada token.'); continue; }
      const {key}=await inquirer.prompt({ type:'list', name:'key', message:'Pilih token (set TP)', choices:[...TOKENS.keys()] });
      const cur={...normalizeCfg(TOKENS.get(key)||{}), coinType:key};
      const upd=await promptSetTP(cur);
      const newer={...cur, ...upd};
      TOKENS.set(key, normalizeCfg(newer)); await saveTokens();
      console.log(`[TP SET] ${key} target=${upd.tpPriceSui} SUI per 1 token, sell%=${upd.tpSellPercent}%`);
    }

    if(action==='toggle_tp'){
      if(!TOKENS.size){ console.log('Belum ada token.'); continue; }
      const {key}=await inquirer.prompt({ type:'list', name:'key', message:'Pilih token (Auto-TP)', choices:[...TOKENS.keys()] });
      const cfg=normalizeCfg(TOKENS.get(key)||{});
      if(!cfg.tpRunning){ TOKENS.set(key,{...cfg, tpRunning:true}); await saveTokens(); await startAutoTP(key); }
      else { await stopAutoTP(key); }
    }

    if(action==='list') renderTable();
    if(action==='log')  await viewActivityLog();
    if(action==='exit'){ console.log('Bye'); process.exit(0); }
  }
}

// ===== Start =====
process.on('unhandledRejection', async(e)=>{ await logLine(`[WARN] UnhandledRejection: ${e?.message||e}`); });
process.on('uncaughtException', async(e)=>{ await logLine(`[WARN] UncaughtException: ${e?.message||e}`); });
menu().catch(async e=>{ console.error('Fatal:', e?.message||e); await logLine(`[FATAL] ${e?.message||String(e)}`); process.exit(1); });
