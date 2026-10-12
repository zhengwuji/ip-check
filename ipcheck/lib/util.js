/* ============================================================
   lib/util.js — 零依赖通用工具：HTTP 请求 / IP 工具 / RDAP / XML 转义
   无其他内部依赖，供所有 lib 模块共用。
   ============================================================ */
"use strict";
const http = require("http");
const https = require("https");
const crypto = require("crypto");

function fetchRaw(url, headers, timeout) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith("https:") ? https : http;
    const req = mod.get(url, { headers: headers || {}, timeout: timeout || 8000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        return resolve(fetchRaw(res.headers.location, headers, timeout));
      }
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
  });
}

async function fetchJson(url, headers, timeout) {
  const r = await fetchRaw(url, headers, timeout);
  if (r.status !== 200) throw new Error("HTTP " + r.status);
  return JSON.parse(r.body);
}

/* POST JSON 并返回完整响应（需要读 Location 等响应头时用，如 Globalping 建测量）
   返回 { status, headers, body }，不因非 2xx 抛错，由调用方判断。 */
function postRaw(url, payload, headers, timeout) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith("https:") ? https : http;
    const body = Buffer.from(JSON.stringify(payload));
    const h = Object.assign({ "Content-Type": "application/json", "Content-Length": body.length }, headers || {});
    const req = mod.request(url, { method: "POST", headers: h, timeout: timeout || 8000 }, (res) => {
      let buf = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (buf += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: buf }));
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end(body);
  });
}

/* POST JSON：用于 ip-api 批量接口等只接受 POST 的数据源 */
async function postJson(url, payload, headers, timeout) {
  const r = await postRaw(url, payload, headers, timeout);
  if (r.status < 200 || r.status >= 300) throw new Error("HTTP " + r.status);
  return JSON.parse(r.body);
}

const V4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const isV4 = (ip) => V4_RE.test(String(ip || ""));

/* 展开缩写 IPv6 为 8 组 4 位十六进制 */
function expandV6(ip) {
  const halves = String(ip).split("::");
  let head = halves[0] ? halves[0].split(":") : [];
  let tail = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
  if (halves.length > 1) {
    while (head.length + tail.length < 8) head.push("0");
  }
  return head.concat(tail).map((h) => (h || "0").padStart(4, "0")).join(":").toLowerCase();
}

const isV6 = (ip) => String(ip || "").includes(":") && /^[0-9a-f:.]+$/i.test(String(ip));

/* 缓存键归一：IPv4 → /24 网段基址（.1），IPv6 → 展开后取前 4 组（/64）首地址 */
function normalizeIp(ip) {
  const s = String(ip || "");
  if (V4_RE.test(s)) return s.replace(/\.\d+$/, ".1");
  if (isV6(s)) {
    try {
      const groups = expandV6(s).split(":").slice(0, 4);
      return groups.map((g) => g.replace(/^0+(?=.)/, "")).join(":") + "::";
    } catch (e) { return s; }
  }
  return s;
}

function isBogon(ip) {
  if (!V4_RE.test(ip)) return false;
  if (/^(0\.|10\.|127\.|169\.254\.|192\.168\.|22[4-9]\.|2[34]\d\.)/.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(ip)) return true;
  return false;
}

function xmlEsc(s) {
  return String(s || "").replace(/[<>&"']/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&#39;" }[c]));
}

/* ---------------- RDAP（iana 引导 → 注册局） ---------------- */
const RDAP_BOOT = { url: "https://data.iana.org/rdap/dns.json", data: null, t: 0 };
async function rdapBootstrap() {
  if (RDAP_BOOT.data && Date.now() - RDAP_BOOT.t < 24 * 3600 * 1000) return RDAP_BOOT.data;
  RDAP_BOOT.data = await fetchJson(RDAP_BOOT.url);
  RDAP_BOOT.t = Date.now();
  return RDAP_BOOT.data;
}
async function rdapGet(url) {
  const r = await fetchRaw(url, { accept: "application/rdap+json, application/json", "User-Agent": "NetProbe/1.0" }, 10000);
  if (r.status !== 200) throw new Error("HTTP " + r.status);
  return JSON.parse(r.body);
}

/* 原子写盘：写临时文件后 rename，避免进程中断写坏 JSON */
function writeJsonAtomic(file, data) {
  const fs = require("fs");
  const path = require("path");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + ".tmp." + process.pid;
  fs.writeFileSync(tmp, data);
  try { fs.renameSync(tmp, file); } catch (e) {
    // Windows 上目标被占用时 rename 可能失败，退回直接覆盖
    fs.writeFileSync(file, data);
    try { fs.unlinkSync(tmp); } catch (e2) {}
  }
}

function shortHash(s) {
  return crypto.createHash("sha1").update(String(s)).digest("hex").slice(0, 8);
}

module.exports = {
  fetchRaw, fetchJson, postJson, postRaw, isV4, isV6, expandV6, normalizeIp, isBogon, xmlEsc,
  rdapBootstrap, rdapGet, writeJsonAtomic, shortHash,
};
