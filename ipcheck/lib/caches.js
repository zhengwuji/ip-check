/* ============================================================
   lib/caches.js — 统一 TTL 缓存工厂
   - 所有缓存注册进 registry，供 /api/health 查看与 /api/admin/purge 清理
   - 每小时自动清理过期条目（此前只读时惰性判断，长期运行内存会缓慢上涨）
   ============================================================ */
"use strict";

const registry = [];

function makeCache(name, ttlMs, maxEntries) {
  const map = new Map();
  const max = maxEntries || 20000;
  const c = {
    name,
    ttl: ttlMs,
    get(k) {
      const hit = map.get(k);
      if (hit && Date.now() - hit.t < ttlMs) return hit.d;
      return undefined;
    },
    has(k) {
      const hit = map.get(k);
      return !!(hit && Date.now() - hit.t < ttlMs);
    },
    set(k, d) {
      if (map.size >= max) {
        const drop = Math.floor(max / 10);
        let n = 0;
        for (const key of map.keys()) { map.delete(key); if (++n >= drop) break; }
      }
      map.set(k, { t: Date.now(), d });
    },
    del(k) { map.delete(k); },
    clear() { map.clear(); },
    size() { return map.size; },
    prune() {
      const now = Date.now();
      let removed = 0;
      for (const [k, v] of map) {
        if (now - v.t >= ttlMs) { map.delete(k); removed++; }
      }
      return removed;
    },
  };
  registry.push(c);
  return c;
}

function pruneAll() {
  return registry.map((c) => ({ name: c.name, removed: c.prune() }));
}

function stats() {
  return registry.map((c) => ({ name: c.name, entries: c.size() }));
}

function clearAll() {
  registry.forEach((c) => c.clear());
  return registry.length;
}

// 每小时清理一次过期条目；unref 保证不阻止进程退出
setInterval(() => { try { pruneAll(); } catch (e) {} }, 3600 * 1000).unref();

module.exports = { makeCache, pruneAll, stats, clearAll, registry };
