#!/usr/bin/env node
/**
 * SUI AUTO-SELL — FINAL (DEX-agnostic trigger & DEX-only route)
 * --------------------------------------------------------------------------------------------
 * MODE 1: Auto-sell saat ada BUY via DEX (jual exact amount pembeli)
 * MODE 2: Auto-TP (jual saat harga >= target Aftermath quote)
 * MODE 3: GLOBAL walker (pantau semua token running=true)
 *
 * Inti:
 * - Guard pengirim: TX yang dikirim OWNER tidak pernah dianggap BUY.
 * - Deteksi buyer generik (SUI/USDC/USDT/apa pun) agar aggregator/DEX lain ikut kebaca.
 * - Whitelist paket DEX (opsional), plus blacklist 6 paket (2 blast.fun + 4 CA tambahan).
 * - Route filter "DEX-only" (paket blacklist disaring). Fallback bisa dimatikan via ALLOW_ROUTE_FALLBACK=false.
 * - Anti-LP yang aman: HANYA dari nama fungsi MoveCall (bukan objectChanges) agar swap tidak ikut diblok.
 * - AMBANG MIN-BUY (SUI): global + per-token (default 0.1 SUI), trigger JUAL hanya jika paidSuiRaw ≥ ambang.
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
const HTTP_URL    = process.env.HTTP_URL || 'https://fullnode.mainnet.sui.io:443';
const PRIVATE_KEY = (process.env.PRIVATE_KEY || '').trim();
if (!PRIVATE_KEY) { console.error('❌ PRIVATE_KEY belum diisi'); process.exit(1); }

const FAST_POLL_MS = Math.max(50, Number(process.env.FAST_POLL_MS || '80'));
const SAFE_BPS     = Math.max(0,  Number(process.env.SAFE_BPS     || '300'));
const SELL_LOCK_MS = Math.max(500, Number(process.env.SELL_LOCK_MS || '1500'));
const QUIET_429    = String(process.env.QUIET_429 || 'true').toLowerCase() !== 'false';

const STRICT_DEX_NAMES = String(process.env.STRICT_DEX_NAMES||'false').toLowerCase()==='true';
const DEBUG_DEX_MATCH  = String(process.env.DEBUG_DEX_MATCH||'false').toLowerCase()==='true';

const TP_POLL_MS   = Math.max(400, Number(process.env.TP_POLL_MS || '1200'));
const MULTI_WALKER = String(process.env.MULTI_WALKER||'false').toLowerCase()==='true';

// deteksi pembayaran BUY (agar aggregator/DEX apa pun kebaca)
const DETECT_ANY_PAY = String(process.env.DETECT_ANY_PAY || 'false').toLowerCase() === 'true';
const PAY_COINS = (process.env.DETECT_PAY_COINS || SUI)
  .split(',').map(s => s.trim()).filter(Boolean);
const PAY_SET = new Set(PAY_COINS.map(c => c.toLowerCase()));

// allow non-strict route fallback saat swap (hindari "No dex-only route")
const ALLOW_ROUTE_FALLBACK = String(process.env.ALLOW_ROUTE_FALLBACK||'false').toLowerCase()==='true';

// --- DEX name heuristics (fallback bila tidak pakai whitelist paket) ---
const DEFAULT_DEX_NAME_LIST = [
  'cetus','clmm','pool','integrate',
  'flowx','aggregator','swap_exact_input','swap_exact_output','swap_tokens','route_all',
  'aftermath','amm','stableswap','router',
  'turbos','router',
  'bluemove','dex',
  'kriya','bluefin',
  'deepbook','db_router','smart_router','route','swap','router','suiswap'
];
const DEX_NAME_LIST = (process.env.DEX_NAME_LIST||'')
  .split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);
const DEX_NAME_SET = new Set(DEX_NAME_LIST.length? DEX_NAME_LIST : DEFAULT_DEX_NAME_LIST);

// === Blacklist (EXCLUDE) & whitelist (INCLUDE) paket ===
// Default blacklist: 2 blast.fun + 4 CA tambahan (sesuai permintaan)
const DEFAULT_EXCLUDE_PACKAGES = [
  '0x779829966a2e8642c310bed79e6ba603e5acd3c31b25d7d4511e2c9303d6e3ef', // blast.fun
  '0x1dc6658e2d0df5303dbc44053495424a428f5789426ffe0f040710bfb8d26213', // blast.fun (interacted with)
  // 4 CA tambahan:
  '0x8406834e5a27c1600979da46d8c7cd830523d5937c3f443ea70af396ae27461e',
  '0x083d903646de7e14659e1eb0086477183ec7e997730b8e19722ae92ddb96dd54',
  '0xd2b0db05849cb7fd1f3de2ddd52a219b0805f7771dc7b01634ac3740fe436881',
  '0xa204bd0d48d49fc7b8b05c8ef3f3ae63d1b22d157526a88b91391b41e6053157',
].join(',');
const EXCLUDE_PACKAGES = (process.env.EXCLUDE_PACKAGES || DEFAULT_EXCLUDE_PACKAGES)
  .split(',').map(s=>s.trim().toLowerCase()).filter(Boolean);

// FlowX package default (kalau .env kosong, otomatis pakai ini) — TETAP, tapi logika trigger dibuat DEX-agnostic
const FLOWX_PKG_DEFAULT = '0xba153169476e8c3114962261d1edc70de5ad9781b83cc617ecc8c1923191cae0';
const DEX_PACKAGES = (process.env.DEX_PACKAGES || FLOWX_PKG_DEFAULT)
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

// Fallback regex kalau STRICT false & whitelist kosong
const DEX_NAME_REGEX = /\b(swap|router|cetus|flowx|turbos|bluemove|aftermath|kriya|deepbook|bluefin|suiswap)\b/i;

// === Fair-launch / aggregator yang harus dihindari pada rute ===
const FAIRLAUNCH_PROTOCOLS = ['HopFun','MovePump','DoubleUpPump','TurbosFun','BlastFun'];

// === Anti-LP: hanya lewat NAMA FUNGSI (jangan pakai objectChanges) ===
function _norm(s){ return String(s||'').toLowerCase().replace(/[^a-z]/g,''); }

const LIQUIDITY_FUNC_KEYS_NORM = new Set([
  'removeliquidity','removeliquidityandcollectfee','removeliquidityandcollectfees',
  'decreaseliquidity','withdrawliquidity','withdraw','collect','collectfee','collectfees',
  'addliquidity','increaseliquidity','mintposition','burnposition','burnlp',
  'createpool','openposition','closeposition','position','clmmposition',
]);

const LIQUIDITY_TYPE_HINTS = [
  '::lp::','::lp_token::','::pool::','::position::','::clmm_position::','::liquidity::'
];

function hasLiquidityFunction(targets){
  if(!Array.isArray(targets)) return false;
  for(const t of targets){
    const n = _norm(t);
    for(const k of LIQUIDITY_FUNC_KEYS_NORM){ if(n.includes(k)) return true; }
  }
  return false;
}
function hasLiquidityObjectChanges(tx){
  try{
    const oc = tx?.objectChanges || [];
    for(const ch of oc){
      const type = String(ch?.objectType || ch?.object_type || '').toLowerCase();
      for(const hint of LIQUIDITY_TYPE_HINTS){ if(type.includes(hint)) return true; }
    }
    return false;
  }catch{ return false; }
}
function isLiquidityTx(targets, tx){
  const flagged = hasLiquidityFunction(targets) || hasLiquidityObjectChanges(tx);
  if (!flagged) return false;
  const hasSwap = Array.isArray(targets) && targets.some(t => _norm(t).includes('swap'));
  if (hasSwap) return false;
  return true;
}

// ===== IO =====
const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const TOK_PATH   = join(__dirname, 'tokens.json');
const LOG_PATH   = join(__dirname, 'activity.log');

async function readJsonSafe(p,d){ try{ return JSON.parse(await readFile(p,'utf8')); }catch{ return d; } }
async function writeJsonAtomic(p, v){
  const tmp = p + '.tmp';
  await writeFile(tmp, JSON.stringify(v,null,2));
  await writeFile(p, await readFile(tmp,'utf8'));
}
async function logLine(s){
  const line = `[${new Date().toISOString()}] ${s}\n`;
  try{
    await appendFile(LOG_PATH,line).catch(async()=>{
      await mkdir(dirname(LOG_PATH),{recursive:true});
      await appendFile(LOG_PATH,line);
    });
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

// ===== Decimals cache (Auto-TP) =====
const DECIMALS = new Map();
async function getDecimals(coinType){
  if (DECIMALS.has(coinType)) return DECIMALS.get(coinType);
  const md = await client.getCoinMetadata({ coinType });
  const d = Number(md?.decimals ?? 9);
  DECIMALS.set(coinType, d);
  return d;
}
function pow10(n){ n=Number(n); let r=1n; for(let i=0;i<n;i++) r*=10n; return r; }

// ===== Global Min-BUY threshold (SUI) & helpers =====
const DEFAULT_MIN_BUY_MIST = 100_000_000n; // 0.1 SUI
function toMistRawFromSuiFloat(x){
  const n = Number(x||0);
  if (!Number.isFinite(n) || n<=0) return 0n;
  return BigInt(Math.round(n * 1e9));
}
function fromMistToSuiFloat(raw){
  try { return Number(BigInt(raw))/1e9; } catch { return 0; }
}
let GLOBAL = { useGlobalMin: true, minBuyMistRaw: DEFAULT_MIN_BUY_MIST };
let TOKENS = new Map();
function getActiveMinBuyMistRaw(cfg){
  const per = (cfg && cfg.minBuyMistRaw!=null) ? BigInt(cfg.minBuyMistRaw) : DEFAULT_MIN_BUY_MIST;
  return GLOBAL && GLOBAL.useGlobalMin ? (GLOBAL.minBuyMistRaw||DEFAULT_MIN_BUY_MIST) : per;
}

// ===== tokens.json =====
function normalizeCfg(raw={}){
  return {
    sellPercent: Math.min(100, Math.max(1, toNum(raw.sellPercent, 100))),
    minSellRaw:  toBig(raw.minSellRaw ?? 0),
    cooldownMs:  Math.max(200, toNum(raw.cooldownMs, 900)),
    slippageBps: Math.max(1, Math.min(5000, toNum(raw.slippageBps, 200))),
    running:     !!raw.running,
    lastSellMs:  toNum(raw.lastSellMs, 0),

    tpRunning:      !!raw.tpRunning,
    tpPriceSui:     Math.max(0, toNum(raw.tpPriceSui, 0)),
    tpSellPercent:  Math.min(100, Math.max(1, toNum(raw.tpSellPercent, 100))),
    tpProbeRaw:     raw.tpProbeRaw ? toBig(raw.tpProbeRaw) : 0n,
    tpLastHitMs:    toNum(raw.tpLastHitMs, 0),

    // minimal BUY in mist (SUI)
    minBuyMistRaw: (raw.minBuyMistRaw!=null? toBig(raw.minBuyMistRaw) : DEFAULT_MIN_BUY_MIST),
  };
}
async function loadTokens(){
  const data=await readJsonSafe(TOK_PATH,{});
  // Load GLOBAL if present
  if (data && typeof data==='object' && data.global){
    try {
      GLOBAL = {
        useGlobalMin: !!data.global.useGlobalMin,
        minBuyMistRaw: data.global.minBuyMistRaw!=null ? BigInt(data.global.minBuyMistRaw) : DEFAULT_MIN_BUY_MIST
      };
    } catch {}
  }
  // tokens could be under data.tokens (new) or root (legacy)
  const src = (data && typeof data==='object' && data.tokens && typeof data.tokens==='object') ? data.tokens : data;
  const map=new Map();
  if (Array.isArray(src)) {
    for(const it of src) if(it?.coinType&&isCoinType(it.coinType)) map.set(it.coinType, normalizeCfg(it));
  } else if (src && typeof src==='object') {
    for(const [k,v] of Object.entries(src)) if(isCoinType(k)) map.set(k, normalizeCfg(v));
  }
  return map;
}
async function saveTokens(){
  const obj = { tokens: {}, global: {
    useGlobalMin: !!GLOBAL.useGlobalMin,
    minBuyMistRaw: (GLOBAL.minBuyMistRaw || 0n).toString()
  }};
  for (const [k, vr] of TOKENS){
    const v = normalizeCfg(vr);
    obj.tokens[k] = {
      sellPercent: v.sellPercent,
      minSellRaw: (v.minSellRaw || 0n).toString(),
      cooldownMs: v.cooldownMs,
      slippageBps: v.slippageBps,
      running: !!v.running,
      lastSellMs: v.lastSellMs || 0,
      minBuyMistRaw: (v.minBuyMistRaw ?? DEFAULT_MIN_BUY_MIST).toString(),
      tpRunning: !!v.tpRunning,
      tpPriceSui: v.tpPriceSui || 0,
      tpSellPercent: v.tpSellPercent || 100,
      tpProbeRaw: (v.tpProbeRaw || 0n).toString(),
      tpLastHitMs: v.tpLastHitMs || 0
    };
  }
  await writeJsonAtomic(TOK_PATH, obj);
}

// ===== Locks / Dedupe =====
const RUNNERS    = new Map();
const SUBMITTING = new Map();
const SELL_LOCK  = new Map();
const SEEN_BUY   = new Map();
const TP_RUNNERS = new Map();
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

// ===== Scan paket dari ObjectChanges (untuk "interacted with" → hanya untuk blacklist CA) =====
function pkgFromType(typeStr){
  if (!typeStr || typeof typeStr !== 'string') return null;
  const m = typeStr.match(/^(0x[0-9a-fA-F]+)::/);
  return m ? m[1].toLowerCase() : null;
}
function collectPackagesFromObjectChanges(tx){
  const out = new Set();
  const oc = tx?.objectChanges || [];
  for (const ch of oc){
    const t = (ch && (ch.objectType || ch.object_type)) ? (ch.objectType || ch.object_type) : null;
    const pid = ch?.packageId || ch?.package_id || null;
    const p1 = pkgFromType(t);
    if (p1) out.add(p1);
    if (pid && /^0x[0-9a-fA-F]+$/.test(pid)) out.add(String(pid).toLowerCase());
  }
  return [...out];
}
function hasExcludedByObjectChanges(tx){
  try{
    const pkgs = collectPackagesFromObjectChanges(tx);
    for (const p of pkgs){
      if (EXCLUDE_PACKAGES.includes(String(p).toLowerCase())) return true;
    }
    return false;
  }catch{ return false; }
}

// ===== (NEW) Interacted-with DEX packages (Cetus) =====
const INTERACT_DEX_PACKAGES = [
  '0x550dcd6070230d8bf18d99d34e3b2ca1d3657b76cc80ffdacdb2b5d28d7e0124',
  '0x07c27e879ba9282506284b0fef26d393978906fc9496550d978c6f493dbfa3e5',
].map(s => s.toLowerCase());

function anyDexByObjectChanges(tx){
  try{
    if (!INTERACT_DEX_PACKAGES.length) return false;
    const pkgs = collectPackagesFromObjectChanges(tx);
    for (const p of pkgs){
      if (INTERACT_DEX_PACKAGES.includes(String(p).toLowerCase())) return true;
    }
    return false;
  }catch{
    return false;
  }
}

// ===== BUY validator & guards =====
function hasExcludedPackage(targets){
  for (const tgt of targets){
    const pkg = String(tgt).split('::')[0].toLowerCase();
    if (EXCLUDE_PACKAGES.includes(pkg)) return true;
  }
  return false;
}
function anyDexMoveCall(targets){
  if (!targets || !targets.length) return false;
  if (hasExcludedPackage(targets)) return false;

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

// SUI-only helpers
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
function buyerPaidSuiRaw(balanceChanges, buyerAddr){
  if (!Array.isArray(balanceChanges)) return 0n;
  let spent=0n;
  for(const bc of balanceChanges){
    const own = lower(bc?.owner?.AddressOwner||'');
    if (own !== lower(buyerAddr)) continue;
    if (bc?.coinType === SUI){ try{ const x=BigInt(bc.amount||0); if (x<0n) spent += (-x); }catch{} }
  }
  return spent;
}

// Deteksi generik (pembayaran apa pun)
function analyzeBuyers(balanceChanges, coinType){
  const by = new Map(); // addr -> {tokenIn:bigint, paid:bigint, paidSuiRaw:bigint}
  if (!Array.isArray(balanceChanges)) return [];

  for (const bc of balanceChanges){
    const addr = lower(bc?.owner?.AddressOwner || '');
    if (!addr) continue;

    const ct = String(bc?.coinType || '').toLowerCase();
    let amt = 0n; try{ amt = BigInt(bc?.amount || 0); }catch{}

    if (!by.has(addr)) by.set(addr, { tokenIn:0n, paid:0n, paidSuiRaw:0n });
    const o = by.get(addr);

    if (ct === String(coinType).toLowerCase() && amt > 0n) o.tokenIn += amt; // menerima token target

    if (amt < 0n && ct !== String(coinType).toLowerCase()){ // membayar token lain
      if (DETECT_ANY_PAY || PAY_SET.has(ct)) o.paid += (-amt);
      if (ct === SUI.toLowerCase()) o.paidSuiRaw += (-amt);
    }
  }

  const res = [];
  for (const [addr, o] of by){
    if (addr === lower(OWNER)) continue;       // jangan anggap diri sendiri
    if (o.tokenIn > 0n && o.paid > 0n) res.push({ addr, amountTokenIn: o.tokenIn, paidSuiRaw: o.paidSuiRaw||0n });
  }
  return res;
}

// Owner self-sell?
function ownerSoldThisTx(balanceChanges, coinType) {
  if (!Array.isArray(balanceChanges)) return false;
  for (const bc of balanceChanges) {
    const own = lower(bc?.owner?.AddressOwner || '');
    if (own === lower(OWNER) && bc?.coinType === coinType) {
      try { if (BigInt(bc.amount || 0) < 0n) return true; } catch {}
    }
  }
  return false;
}

async function confirmDexBuy(digest, coinType, buyerAddrHint){
  if (!digest) return { ok:false };
  try{
    const tx = await client.getTransactionBlock({
      digest,
      options:{
        showBalanceChanges:true,
        showEvents:false,
        showInput:true,
        showEffects:true,
        showObjectChanges:true,
      }
    });

    // GUARD: TX dikirim OWNER → bukan BUY
    const sender = lower(tx?.effects?.sender || tx?.transaction?.data?.sender || '');
    if (sender === lower(OWNER)) return { ok:false };

    if (ownerSoldThisTx(tx?.balanceChanges || [], coinType)) return { ok:false };

    const targets = parseMoveCallTargets(tx);

    // ❗ Anti-LP: HANYA dari nama fungsi (supaya swap tidak ketutup)
    if (isLiquidityTx(targets, tx)) return { ok:false };

    // TOLAK jika ada paket blacklist di targets ATAU di objectChanges
    if (hasExcludedPackage(targets) || hasExcludedByObjectChanges(tx)) return { ok:false };

    // 1) Deteksi pembeli nyata dulu (DEX-agnostic)
    const cands = analyzeBuyers(tx?.balanceChanges || [], coinType);
    if (cands.length){
      const pick = buyerAddrHint ? (cands.find(x => x.addr === lower(buyerAddrHint)) || cands[0]) : cands[0];
      return { ok:true, buyer: pick.addr, amount: pick.amountTokenIn, paidSuiRaw: pick.paidSuiRaw||0n };
    }

    // 2) Jika belum ketemu pembeli, pastikan transaksi memang via DEX
    const looksDex = anyDexMoveCall(targets) || anyDexByObjectChanges(tx);
    if (!looksDex) return { ok:false };

    // 3) SUI-only fallback kalau ada buyerAddrHint (tetap hitung paidSuiRaw)
    if (buyerAddrHint && buyerSuiOutTokenIn(tx?.balanceChanges||[], buyerAddrHint, coinType)){
      const paid = buyerPaidSuiRaw(tx?.balanceChanges||[], buyerAddrHint);
      return { ok:true, buyer: buyerAddrHint, amount: 0n, paidSuiRaw: paid };
    }

    return { ok:false };
  }catch(e){
    await logLine(`[DETECT WARN] getTx ${coinType}: ${e?.message||e}`);
    return { ok:false };
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

function routeLooksDexOnly(routeObj){
  try{
    const s = JSON.stringify(routeObj).toLowerCase();
    for(const bad of EXCLUDE_PACKAGES){ if (bad && s.includes(bad)) return false; }
    for(const p of FAIRLAUNCH_PROTOCOLS){ if (s.includes(String(p).toLowerCase())) return false; }
    if (DEX_PACKAGES.length>0){
      let ok=false;
      for(const good of DEX_PACKAGES){ if (good && s.includes(good)) { ok=true; break; } }
      if(!ok) return false;
    } else {
      if (!DEX_NAME_REGEX.test(s)) return false;
    }
    return true;
  }catch{ return false; }
}

async function buildSwapBytes(coinType, amountIn, slippageBps){
  const r = await ensureAftermath();

  let route;
  try{
    route = await r.getCompleteTradeRouteGivenAmountIn({
      coinInType: coinType,
      coinOutType: SUI,
      coinInAmount: BigInt(amountIn),
      protocolBlacklist: FAIRLAUNCH_PROTOCOLS,
    });
  }catch{
    route = await r.getCompleteTradeRouteGivenAmountIn({
      coinInType: coinType, coinOutType: SUI, coinInAmount: BigInt(amountIn)
    });
  }
  if(!route || !route.routes?.length) throw new Error('No route');

  const filtered = (route.routes||[]).filter(rt => routeLooksDexOnly(rt));
  let chosen;
  if (filtered.length){
    chosen = { ...route, routes: filtered };
  } else {
    if (!ALLOW_ROUTE_FALLBACK) throw new Error('No dex-only route (filtered)');
    // fallback: rute terbaik tanpa blacklist
    const safe = (route.routes||[]).filter(rt => {
      const s = JSON.stringify(rt).toLowerCase();
      return !EXCLUDE_PACKAGES.some(x => x && s.includes(x));
    });
    chosen = safe.length ? { ...route, routes:safe } : route;
  }

  const usedBps = Math.min(9900, Math.max(1, Number(slippageBps||200) + SAFE_BPS));
  const tx = await r.getTransactionForCompleteTradeRoute({
    walletAddress: OWNER, completeRoute: chosen, slippage: usedBps/10_000
  });
  try{ if(typeof tx.setGasOwner==='function') tx.setGasOwner(OWNER); }catch{}
  const bytes = await tx.build({ client });
  const estOut = extractEst(chosen);
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

// ===== Detector (per token) =====
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
  if (digestHint && alreadySeen(coinType, digestHint)) return;
  if (digestHint) rememberDigest(coinType, digestHint);
  await sellExactOnce(coinType, buyerAmountRaw);
}

async function detectLoop(coinType){
  let cursor=null, nextCp=null;
  let seenEv=new Set(), seenTx=new Set();

  while(RUNNERS.has(coinType)){
    let triggered=false;

    // 1) via TransferEvent (cepat)
    try{
      const resp=await client.queryEvents({
        query:{ MoveEventType: transferEventType(coinType) },
        cursor: cursor??null, limit:40, order:'descending'
      });
      const evs=resp?.data||[]; if(evs.length) cursor=evs[0].id;
      for(const ev of evs){
        if(!RUNNERS.has(coinType)) break;
        const evKey = `${ev.id?.txDigest || ev.id?.eventSeq || JSON.stringify(ev.id)}`;
        if(seenEv.has(evKey)) continue; seenEv.add(evKey); if(seenEv.size>1200) seenEv=new Set([...seenEv].slice(-400));

        const pj=ev.parsedJson||{};
        const from = lower(pj.from || pj.sender || '');
        const to   = lower(pj.to   || pj.recipient || '');
        const amt  = toBig(pj.amount ?? pj.value ?? 0);
        const dig  = pickDigestFromEvent(ev);

        if (from === lower(OWNER)) continue; // self-sell guard

        if(amt>0n && to && to!==lower(OWNER)){
          const c = await confirmDexBuy(dig, coinType, to);
          if (c.ok){
            const sellAmt = c.amount && c.amount>0n ? c.amount : amt;
            const cfg=normalizeCfg(TOKENS.get(coinType)||{}); const n=Date.now();
            const minBuy = getActiveMinBuyMistRaw(cfg);
            const paidSui = (c.paidSuiRaw||0n);
            if (paidSui < minBuy){ if (DEBUG_DEX_MATCH) console.log(`[DEBUG] Skip digest=${dig} — paidSui ${fmtMist(paidSui)} < min ${fmtMist(minBuy)} SUI`); continue; }
            if(!lockActive(coinType) && (n-(cfg.lastSellMs||0)>=cfg.cooldownMs)){
              TOKENS.set(coinType,{...cfg,lastSellMs:n,running:true});
              await triggerSellExact(coinType, dig, sellAmt);
              triggered=true; break;
            }
          } else if (DEBUG_DEX_MATCH) {
            console.log(`[DEBUG] Skip digest=${dig} — bukan BUY (EXCLUDED/self-sell/LP/heuristik DEX).`);
          }
        }
      }
    }catch(e){ await warn429('events',coinType,String(e?.message||e)); }

    // 2) Checkpoint walker (cadangan)
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

          const txs=await client.multiGetTransactionBlocks({
            digests:digs,
            options:{
              showBalanceChanges:true, showInput:true, showEvents:false, showEffects:true,
              showObjectChanges:true
            }
          });
          for(const tx of (txs||[])){
            if(!tx?.digest || seenTx.has(tx.digest)) continue;
            seenTx.add(tx.digest);
            if(seenTx.size>2000) seenTx=new Set([...seenTx].slice(-700));

            // GUARD: TX sender OWNER → skip
            const txSender = lower(tx?.effects?.sender || tx?.transaction?.data?.sender || '');
            if (txSender === lower(OWNER)) continue;

            const targets = parseMoveCallTargets(tx);
            if (isLiquidityTx(targets, tx)) continue;        // anti-LP via nama fungsi
            if (hasExcludedPackage(targets) || hasExcludedByObjectChanges(tx)) continue;
            if (ownerSoldThisTx(tx?.balanceChanges || [], coinType)) continue;

            const cands = analyzeBuyers(tx?.balanceChanges || [], coinType);
            if (!cands.length) continue;

            // 🔒 Ambang SUI wajib lolos
            const cfg=normalizeCfg(TOKENS.get(coinType)||{});
            const paidSui = cands[0].paidSuiRaw || 0n;
            const minBuy = getActiveMinBuyMistRaw(cfg);
            if (paidSui < minBuy) continue;

            if (alreadySeen(coinType, tx.digest)) continue;
            rememberDigest(coinType, tx.digest);

            const n=Date.now();
            if(lockActive(coinType) || (n-(cfg.lastSellMs||0)<cfg.cooldownMs)) continue;

            TOKENS.set(coinType,{...cfg,lastSellMs:n,running:true}); 
            await sellExactOnce(coinType, cands[0].amountTokenIn);
            triggered=true; break;
          }
          if(triggered) break;
        }
      }catch(e){ await warn429('cp',coinType,String(e?.message||e)); }
    }

    await sleep(FAST_POLL_MS);
  }
}

// ===== GLOBAL Walker =====
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
        const digs=cp?.transactions||[]; if(!digs.length) continue;

        const txs=await client.multiGetTransactionBlocks({
          digests:digs,
          options:{
            showBalanceChanges:true, showInput:true, showEvents:false, showEffects:true,
            showObjectChanges:true
          }
        });

        const ACTIVE = new Set();
        for (const [ct, cfg] of TOKENS){ if (cfg && cfg.running) ACTIVE.add(ct); }
        if (!ACTIVE.size) continue;

        for(const tx of (txs||[])){
          if(!GLOBAL_RUN) break;
          if(!tx?.digest || seenTx.has(tx.digest)) continue;
          seenTx.add(tx.digest); if(seenTx.size>4000) seenTx=new Set([...seenTx].slice(-1500));

          // GUARD: TX sender OWNER → skip
          const txSender = lower(tx?.effects?.sender || tx?.transaction?.data?.sender || '');
          if (txSender === lower(OWNER)) continue;

          const targets = parseMoveCallTargets(tx);
          if (isLiquidityTx(targets, tx)) continue;          // anti-LP via nama fungsi
          if (hasExcludedPackage(targets) || hasExcludedByObjectChanges(tx)) continue;

          const bcs = tx.balanceChanges||[];
          if(!bcs.length) continue;

          // skip jika tx adalah self-sell untuk coin aktif mana pun
          let selfSellHit = false;
          for (const ct of ACTIVE){
            if (ownerSoldThisTx(bcs, ct)) { selfSellHit = true; break; }
          }
          if (selfSellHit) continue;

          for (const ct of ACTIVE){
            const list = analyzeBuyers(bcs, ct);
            if (!list.length) continue;

            // 🔒 Ambang SUI wajib lolos (global/per-token)
            const cfg=normalizeCfg(TOKENS.get(ct)||{});
            const paidSui = list[0].paidSuiRaw || 0n;
            const minBuy = getActiveMinBuyMistRaw(cfg);
            if (paidSui < minBuy) continue;

            if (alreadySeen(ct, tx.digest)) continue;
            rememberDigest(ct, tx.digest);

            const n=Date.now();
            if (lockActive(ct) || (n-(cfg.lastSellMs||0)<cfg.cooldownMs)) continue;

            TOKENS.set(ct,{...cfg,lastSellMs:n}); 
            await sellExactOnce(ct, list[0].amountTokenIn);
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
  let changes=0;
  for (const [ct, cfg0] of TOKENS){
    const cfg = normalizeCfg(cfg0||{});
    if (!cfg.running){ TOKENS.set(ct,{...cfg, running:true}); changes++; }
  }
  if (changes>0){ await saveTokens(); console.log(`⚡ GLOBAL: set running=true untuk ${changes} token`); }
  GLOBAL_RUN = true;
  detectLoopGlobal().catch(async e=>{ await logLine(`[GLOBAL ERROR] ${e?.message||e}`); });
  console.log(`⚡ GLOBAL Auto-sell ON (multi token; 1 loop pantau semua token)`);
}
async function stopGlobalAutoSell(){
  GLOBAL_RUN = false;
  let changes=0;
  for (const [ct, cfg0] of TOKENS){
    const cfg = normalizeCfg(cfg0||{});
    if (cfg.running){ TOKENS.set(ct,{...cfg, running:false}); changes++; }
  }
  if (changes>0){ await saveTokens(); console.log(`⏸️ GLOBAL: set running=false untuk ${changes} token`); }
  console.log(`⏸️ GLOBAL Auto-sell OFF`);
}

// ===== Auto-TP =====
async function ensureProbe(coinType){
  const cfg = normalizeCfg(TOKENS.get(coinType)||{});
  if (cfg.tpProbeRaw && cfg.tpProbeRaw>0n) return cfg.tpProbeRaw;
  const dec = await getDecimals(coinType);
  const probe = pow10(dec);
  TOKENS.set(coinType, { ...cfg, tpProbeRaw: probe }); 
  return probe;
}
async function getQuoteSui(coinType, amountInRaw){
  const r = await ensureAftermath();
  const route = await r.getCompleteTradeRouteGivenAmountIn({
    coinInType: coinType, coinOutType: SUI, coinInAmount: BigInt(amountInRaw),
    protocolBlacklist: FAIRLAUNCH_PROTOCOLS
  });
  if(!route || !route.routes?.length) return 0n;
  const filtered = (route.routes||[]).filter(rt => routeLooksDexOnly(rt));
  const used = filtered.length ? { ...route, routes: filtered } : route;
  return extractEst(used);
}
async function tpLoop(coinType){
  while (TP_RUNNERS.has(coinType)){
    try{
      const cfg = normalizeCfg(TOKENS.get(coinType)||{});
      if (!cfg.tpRunning || cfg.tpPriceSui<=0) { await sleep(TP_POLL_MS); continue; }

      const probe = await ensureProbe(coinType);
      const quoteOut = await getQuoteSui(coinType, probe);
      const targetOut = BigInt(Math.floor(cfg.tpPriceSui * 1e9));

      if (quoteOut >= targetOut){
        const n=Date.now();
        if(!lockActive(coinType) && (n-(cfg.lastSellMs||0)>=cfg.cooldownMs)){
          TOKENS.set(coinType,{...cfg,lastSellMs:n}); 
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
  TOKENS.set(coinType,{...cfg,tpRunning:true}); 
  tpLoop(coinType).catch(async e=>{ await logLine(`[TP ERROR] ${coinType}: ${e?.message||e}`); });
  console.log(`🎯 Auto-TP ON ${coinType} (poll ~${TP_POLL_MS}ms)`);
}
async function stopAutoTP(coinType){
  const r=TP_RUNNERS.get(coinType); if(r){ try{ r.stop(); }catch{} }
  TP_RUNNERS.delete(coinType);
  const cfg=normalizeCfg(TOKENS.get(coinType)||{});
  TOKENS.set(coinType,{...cfg,tpRunning:false}); 
  console.log(`🎯⏸️ Auto-TP OFF ${coinType}`);
}

// ===== ON/OFF DEX runner (per token) =====
async function startAutoSell(coinType){
  if(RUNNERS.has(coinType)) return;
  RUNNERS.set(coinType, { stop:()=> RUNNERS.delete(coinType) });
  const cfg=normalizeCfg(TOKENS.get(coinType)||{});
  TOKENS.set(coinType,{...cfg,running:true}); 
  detectLoop(coinType).catch(async e=>{ await logLine(`[DETECT ERROR] ${coinType}: ${e?.message||e}`); });
  console.log(`▶️ Auto-sell ON ${coinType} (DEX-agnostic, poll ~${FAST_POLL_MS}ms)`);
}
async function stopAutoSell(coinType){
  const r = RUNNERS.get(coinType);
  if (r) { try { r.stop(); } catch {} }
  RUNNERS.delete(coinType);
  const cfg = normalizeCfg(TOKENS.get(coinType) || {});
  TOKENS.set(coinType, { ...cfg, running: false });
  console.log(`⏸️ Auto-sell OFF ${coinType}`);
}

// ===== Menu =====
async function promptAddOrEdit(existing){
  const base = normalizeCfg(existing || {});
  const isNew = !existing;

  const ans = await inquirer.prompt([
    {
      name:'coinType',
      message:'Coin type (0x..::mod::SYMBOL)',
      when: !existing,
      validate: v => isCoinType(v) || 'Format salah'
    },
    {
      name:'sellPercent',
      message:'Sell % (untuk Test SELL manual)',
      default: isNew ? 1 : base.sellPercent,
      filter: Number
    },
    {
      name:'minSellRaw',
      message:'Min sell (raw units)',
      default: base.minSellRaw.toString(),
      filter: v => BigInt(v)
    },
    {
      name:'cooldownMs',
      message:'Cooldown antar SELL (ms)',
      default: base.cooldownMs,
      filter: Number
    },
    {
      name:'slippageBps',
      message:'Slippage (bps)',
      default: base.slippageBps,
      filter: Number
    },
    // NEW: per-token Min BUY (SUI)
    {
      name:'minBuyMistRaw',
      message:'Min BUY (SUI) untuk trigger auto-sell (per-token)',
      default: isNew ? 0.1 : fromMistToSuiFloat(base.minBuyMistRaw || DEFAULT_MIN_BUY_MIST),
      filter: v => toMistRawFromSuiFloat(v)
    },
  ]);

  return ans;
}

async function promptSetTP(existing){
  const base = normalizeCfg(existing || {});
  const ans = await inquirer.prompt([
    {
      name:'tpPriceSui',
      message:'Target harga (SUI per 1 token, contoh 0.0000012)',
      default: base.tpPriceSui || 0,
      filter: Number
    },
    {
      name:'tpSellPercent',
      message:'Sell % saat TP terpenuhi',
      default: base.tpSellPercent || 100,
      filter: Number
    }
  ]);
  return ans;
}

function renderTable(){
  const rows=[];
  for(const [k,vr] of TOKENS){
    const v=normalizeCfg(vr);
    rows.push({
      coinType:k, sellPct:v.sellPercent, cooldownMs:v.cooldownMs, slipBps:v.slippageBps,
      minBuySui: fromMistToSuiFloat(getActiveMinBuyMistRaw(v)),
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

  if (MULTI_WALKER){
    await startGlobalAutoSell();
  } else {
    for(const [k,v] of TOKENS){ if(v.running) startAutoSell(k); if(v.tpRunning) startAutoTP(k); }
  }
}

async function menu(){
  await autoStartSaved();
  while(true){
    const suiBal=fmtMist(await getBalanceRaw(OWNER,SUI));
    console.log(`\nRPC: ${HTTP_URL}`);
    console.log(`Owner: ${OWNER}`);
    console.log(`SUI Balance: ${suiBal}`);
    const {action}=await inquirer.prompt({
      type:'list', name:'action', message:'Pilih menu', pageSize:16, choices:[
        {name:'➕ Tambah token', value:'add'},
        {name:'✏️  Ubah token', value:'edit'},
        {name:'🚀 Test SELL sekali (submit sekarang)', value:'oneshot'},
        {name:'⚡ Auto-sell ON/OFF (DEX-only per token)', value:'toggle_dex'},
        {name:'⚡ Auto-sell GLOBAL ON/OFF (multi token)', value:'toggle_global'},
        {name:'🎯 Set TP Harga & Sell %', value:'set_tp'},
        {name:'🎯 Auto-TP ON/OFF (harga target)', value:'toggle_tp'},
        {name:'🌐 Atur ambang BUY (SUI) — GLOBAL', value:'global_min_buy_set'},
        {name:`🌐 Mode GLOBAL ambang BUY: ${GLOBAL.useGlobalMin ? 'ON' : 'OFF'}`, value:'global_min_buy_toggle'},
        {name:'📋 Lihat status token', value:'list'},
        {name:'📜 Lihat activity.log (last 200)', value:'log'},
        {name:'Keluar', value:'exit'},
      ]
    });

    if(action==='add'){
      const a=await promptAddOrEdit();
      if(TOKENS.has(a.coinType)) {
        console.log('Token sudah ada. Pakai menu Ubah.');
      } else {
        TOKENS.set(a.coinType,{...normalizeCfg(a), running:true, tpRunning:false, lastSellMs:0 });
        await saveTokens();
        await startAutoSell(a.coinType);
        console.log(`[ADD] ${a.coinType} (running=true, auto-sell aktif)`);
      }
    }

    if(action==='edit'){
      if(!TOKENS.size){ console.log('Belum ada token.'); continue; }
      const {key}=await inquirer.prompt({ type:'list', name:'key', message:'Pilih token', choices:[...TOKENS.keys()] });
      const cur={...normalizeCfg(TOKENS.get(key)||{}), coinType:key};
      const upd=await promptAddOrEdit(cur);
      TOKENS.set(key,{...normalizeCfg(cur), ...normalizeCfg(upd)});
      await saveTokens();
      console.log(`[EDIT] ${key}`);
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
      if(!cfg.running){
        TOKENS.set(key,{...cfg, running:true});
        await saveTokens();
        await startAutoSell(key);
      } else {
        await stopAutoSell(key);
        await saveTokens();
      }
    }

    if(action==='toggle_global'){
      if (!GLOBAL_RUN){ await startGlobalAutoSell(); }
      else { await stopGlobalAutoSell(); }
    }

    if(action==='set_tp'){
      if(!TOKENS.size){ console.log('Belum ada token.'); continue; }
      const {key}=await inquirer.prompt({ type:'list', name:'key', message:'Pilih token (set TP)', choices:[...TOKENS.keys()] });
      const cur={...normalizeCfg(TOKENS.get(key)||{}), coinType:key};
      const upd=await promptSetTP(cur);
      TOKENS.set(key, normalizeCfg({ ...cur, ...upd }));
      await saveTokens();
      console.log(`[TP SET] ${key} target=${upd.tpPriceSui} SUI per 1 token, sell%=${upd.tpSellPercent}%`);
    }

    if(action==='toggle_tp'){
      if(!TOKENS.size){ console.log('Belum ada token.'); continue; }
      const {key}=await inquirer.prompt({ type:'list', name:'key', message:'Pilih token (Auto-TP)', choices:[...TOKENS.keys()] });
      const cfg=normalizeCfg(TOKENS.get(key)||{});
      if(!cfg.tpRunning){
        TOKENS.set(key,{...cfg, tpRunning:true});
        await saveTokens();
        await startAutoTP(key);
      } else {
        await stopAutoTP(key);
        await saveTokens();
      }
    }

    if(action==='global_min_buy_set'){
      const {sui} = await inquirer.prompt([{
        name:'sui',
        message:`Set ambang GLOBAL (SUI) [saat ini: ${fromMistToSuiFloat(GLOBAL.minBuyMistRaw)}]`,
        default: fromMistToSuiFloat(GLOBAL.minBuyMistRaw),
        filter: Number
      }]);
      const raw = toMistRawFromSuiFloat(sui);
      GLOBAL.minBuyMistRaw = raw;
      for (const [k, v0] of TOKENS){
        const v = normalizeCfg(v0);
        v.minBuyMistRaw = raw;
        TOKENS.set(k, v);
      }
      await saveTokens();
      console.log(`Ambang GLOBAL diset ke ${fromMistToSuiFloat(raw)} SUI dan diterapkan ke semua token.`);
    }

    if(action==='global_min_buy_toggle'){
      GLOBAL.useGlobalMin = !GLOBAL.useGlobalMin;
      await saveTokens();
      console.log(`Mode GLOBAL ambang BUY sekarang: ${GLOBAL.useGlobalMin ? 'ON' : 'OFF'}.`);
    }

    if(action==='list') renderTable();
    if(action==='log')  await viewActivityLog();
    if(action==='exit'){ console.log('Bye'); process.exit(0); }
  }
}

// ===== Start =====
process.on('unhandledRejection', async (e) => { await logLine(`[WARN] UnhandledRejection: ${e?.message||e}`); });
process.on('uncaughtException', async (e) => { await logLine(`[WARN] UncaughtException: ${e?.message||e}`); });
menu().catch(async (e) => {
  console.error('Fatal:', e?.message||e);
  await logLine(`[FATAL] ${e?.message||String(e)}`);
  process.exit(1);
});
