/* ============================================================
   lib/util.js — Workers 版通用工具（无 Node 依赖）
   fetch / IP 工具 / RDAP / XML 转义 / 同步短哈希
   ============================================================ */
"use strict";

export async function fetchRaw(url, headers, timeout) {
  const r = await fetch(url, {
    headers: headers || {},
    signal: AbortSignal.timeout(timeout || 8000),
    cf: { cacheTtl: 0 },
  });
  const body = await r.text();
  return { status: r.status, body };
}

export async function fetchJson(url, headers, timeout) {
  const r = await fetchRaw(url, headers, timeout);
  if (r.status !== 200) throw new Error("HTTP " + r.status);
  return JSON.parse(r.body);
}

const V4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
export const isV4 = (ip) => V4_RE.test(String(ip || ""));
export const isV6 = (ip) => String(ip || "").includes(":") && /^[0-9a-f:.]+$/i.test(String(ip));

export function expandV6(ip) {
  const halves = String(ip).split("::");
  let head = halves[0] ? halves[0].split(":") : [];
  let tail = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
  if (halves.length > 1) while (head.length + tail.length < 8) head.push("0");
  return head.concat(tail).map((h) => (h || "0").padStart(4, "0")).join(":").toLowerCase();
}

export function normalizeIp(ip) {
  const s = String(ip || "");
  if (V4_RE.test(s)) return s.replace(/\.\d+$/, ".1");
  if (isV6(s)) {
    try {
      return expandV6(s).split(":").slice(0, 4).map((g) => g.replace(/^0+(?=.)/, "")).join(":") + "::";
    } catch (e) { return s; }
  }
  return s;
}

export function isBogon(ip) {
  if (!V4_RE.test(ip)) return false;
  if (/^(0\.|10\.|127\.|169\.254\.|192\.168\.|22[4-9]\.|2[34]\d\.)/.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true;
  return false;
}

export function xmlEsc(s) {
  return String(s || "").replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------------- RDAP ---------------- */
const RDAP_BOOT = { url: "https://data.iana.org/rdap/dns.json", data: null, t: 0 };
export async function rdapBootstrap() {
  if (RDAP_BOOT.data && Date.now() - RDAP_BOOT.t < 24 * 3600 * 1000) return RDAP_BOOT.data;
  RDAP_BOOT.data = await fetchJson(RDAP_BOOT.url);
  RDAP_BOOT.t = Date.now();
  return RDAP_BOOT.data;
}
export async function rdapGet(url) {
  const r = await fetchRaw(url, { accept: "application/rdap+json, application/json", "User-Agent": "NetProbe/1.0" }, 10000);
  if (r.status !== 200) throw new Error("HTTP " + r.status);
  return JSON.parse(r.body);
}

/* 同步短哈希（FNV-1a）——版本号/键名用，无需 crypto */
export function shortHash(s) {
  let h = 0x811c9dc5;
  const str = String(s);
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}
