/* ============================================================
   lib/status.js — Workers 版服务状态巡检
   无常驻定时器：改为惰性巡检——/api/status/history 被访问时，
   若距上次巡检超过 5 分钟则现场巡检一轮（首位访问者多等 2-4 秒）。
   结果存内存；如需跨实例持久可自行绑定 KV（本版本按约定不使用）。
   ============================================================ */
"use strict";
import { fetchJson } from "./util.js";

export const STATUS_SERVICES = [
  { name: "OpenAI / ChatGPT", url: "https://status.openai.com/api/v2/summary.json" },
  { name: "Claude (Anthropic)", url: "https://status.anthropic.com/api/v2/summary.json" },
  { name: "Perplexity", url: "https://status.perplexity.com/api/v2/summary.json" },
  { name: "Cursor", url: "https://status.cursor.com/api/v2/summary.json" },
  { name: "Groq", url: "https://groqstatus.com/api/v2/summary.json" },
  { name: "ElevenLabs", url: "https://status.elevenlabs.io/api/v2/summary.json" },
  { name: "Replicate", url: "https://status.replicate.com/api/v2/summary.json" },
  { name: "Hugging Face", url: "https://status.huggingface.co/api/v2/summary.json" },
  { name: "Cloudflare", url: "https://www.cloudflarestatus.com/api/v2/summary.json" },
  { name: "Vercel", url: "https://www.vercel-status.com/api/v2/summary.json" },
  { name: "Supabase", url: "https://status.supabase.com/api/v2/summary.json" },
  { name: "Fly.io", url: "https://status.flyio.net/api/v2/summary.json" },
  { name: "DigitalOcean", url: "https://status.digitalocean.com/api/v2/summary.json" },
  { name: "Figma", url: "https://status.figma.com/api/v2/summary.json" },
  { name: "GitHub", url: "https://www.githubstatus.com/api/v2/summary.json" },
  { name: "npm", url: "https://status.npmjs.org/api/v2/summary.json" },
  { name: "Atlassian", url: "https://status.atlassian.com/api/v2/summary.json" },
  { name: "Sentry", url: "https://status.sentry.io/api/v2/summary.json" },
  { name: "Discord", url: "https://discordstatus.com/api/v2/summary.json" },
  { name: "Zoom", url: "https://status.zoom.us/api/v2/summary.json" },
];

const PATROL_INTERVAL = 5 * 60 * 1000;
let statusLog = { current: {}, changes: [], lastRun: 0 };
let patrolling = false;

export async function getStatusHistory(wait) {
  if (Date.now() - statusLog.lastRun > PATROL_INTERVAL && !patrolling) {
    if (wait) await patrolStatuses();
    else patrolStatuses().catch(() => {}); // 不等待：先返回上次结果
  }
  return {
    current: statusLog.current,
    changes: statusLog.changes.slice(0, 40),
    lastRun: statusLog.lastRun,
    note: "Workers 版为惰性巡检（访问时触发），数据存内存",
  };
}

export async function patrolStatuses() {
  if (patrolling) return;
  patrolling = true;
  try {
    const results = await Promise.all(STATUS_SERVICES.map(async (svc) => {
      try {
        const d = await fetchJson(svc.url, null, 9000);
        const level = (d.status && d.status.indicator) || "none";
        return { name: svc.name, level, desc: (d.status && d.status.description) || "" };
      } catch (e) {
        return { name: svc.name, level: "unknown", desc: "巡检查询失败" };
      }
    }));
    const now = new Date().toISOString();
    const fresh = [];
    for (const r of results) {
      const prev = statusLog.current[r.name];
      if (!prev || prev.level !== r.level) {
        fresh.push({ t: now, name: r.name, from: prev ? prev.level : "init", to: r.level, desc: r.desc });
      }
      statusLog.current[r.name] = { level: r.level, desc: r.desc, t: now };
    }
    if (fresh.length) {
      statusLog.changes = fresh.concat(statusLog.changes).slice(0, 200);
    }
    statusLog.lastRun = Date.now();
  } finally {
    patrolling = false;
  }
}
