/* ============================================================
   lib/caches.js — Workers 版 TTL 缓存（纯内存，每个隔离实例独立）
   不使用 KV / DO：实例被回收即清空，属可接受的降级。
   无定时器可用：在 set() 时机会式清理过期与超限。
   ============================================================ */
"use strict";

export const registry = [];

export function makeCache(name, ttlMs, maxEntries) {
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
    set(k, d) {
      map.set(k, { t: Date.now(), d });
      if (map.size > max * 1.2) c.prune();
      if (map.size > max) {
        const drop = Math.floor(max / 10);
        let n = 0;
        for (const key of map.keys()) { map.delete(key); if (++n >= drop) break; }
      }
    },
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

export function pruneAll() {
  return registry.map((c) => ({ name: c.name, removed: c.prune() }));
}
export function stats() {
  return registry.map((c) => ({ name: c.name, entries: c.size() }));
}
export function clearAll() {
  registry.forEach((c) => c.clear());
  return registry.length;
}
