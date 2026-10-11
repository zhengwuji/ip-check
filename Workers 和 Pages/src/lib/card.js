/* ============================================================
   lib/card.js — IP 信息卡片（动态 SVG，访客各自看到自己的 IP）
   支持 IPv4 / IPv6（v6 地址过长时自动缩小字号）。
   依赖：util、caches、geo、cfrisk
   ============================================================ */
"use strict";
import { isV4, isV6, xmlEsc } from "./util.js";
import { makeCache } from "./caches.js";
import { geoLookup, classifyRisk } from "./geo.js";
import { cfRisk } from "./cfrisk.js";

const CARD_STYLES = {
  midnight: { name: "暗夜",  bg: ["#0f172a", "#1e293b"], text: "#f1f5f9", sub: "#94a3b8", accent: "#7dd3fc" },
  minimal:  { name: "极简",  bg: ["#ffffff", "#f1f5f9"], text: "#0f172a", sub: "#64748b", accent: "#2563eb" },
  sunset:   { name: "落日",  bg: ["#f97316", "#ec4899"], text: "#fff7ed", sub: "#ffe4e6", accent: "#fde68a" },
  ocean:    { name: "海岸",  bg: ["#0369a1", "#06b6d4"], text: "#f0f9ff", sub: "#cffafe", accent: "#fef08a" },
  aurora:   { name: "极光",  bg: ["#0d9488", "#7c3aed"], text: "#f0fdfa", sub: "#ddd6fe", accent: "#5eead4" },
  neon:     { name: "霓虹",  bg: ["#1e1b4b", "#4c1d95"], text: "#f5d0fe", sub: "#a5b4fc", accent: "#22d3ee", ring: "#22d3ee" },
  terminal: { name: "终端",  bg: ["#09090b", "#052e16"], text: "#4ade80", sub: "#166534", accent: "#4ade80", mono: true },
  coffee:   { name: "咖啡",  bg: ["#e7d3b6", "#c8a27a"], text: "#422006", sub: "#78350f", accent: "#92400e" },
  sakura:   { name: "樱粉",  bg: ["#fbcfe8", "#fda4af"], text: "#831843", sub: "#9f1239", accent: "#be185d" },
  starry:   { name: "星夜",  bg: ["#1e1b4b", "#312e81"], text: "#e0e7ff", sub: "#818cf8", accent: "#fbbf24", stars: true },
  forest:   { name: "翡翠",  bg: ["#064e3b", "#10b981"], text: "#ecfdf5", sub: "#a7f3d0", accent: "#fde68a" },
  ink:      { name: "水墨",  bg: ["#f8fafc", "#cbd5e1"], text: "#111827", sub: "#4b5563", accent: "#1f2937" },
};
const CARD_STICKERS = {
  none: "", rainbow: "🌈", rocket: "🚀", fire: "🔥", bolt: "⚡", star: "⭐", moon: "🌙",
  cherry: "🌸", cat: "🐱", dog: "🐶", pizza: "🍕", coffee: "☕", game: "🎮", skull: "💀",
  crown: "👑", gem: "💎", clover: "🍀", robot: "🤖", ghost: "👻", vip: "VIP", linux: "LINUX",
  dev: "DEV", passed: "PASSED", pro: "PRO", n666: "666",
};

const cardCache = makeCache("card-svg", 5 * 60000, 5000);

async function cardSvg(ip, styleKey, stickerKey, w) {
  const st = CARD_STYLES[styleKey] || CARD_STYLES.midnight;
  const sticker = CARD_STICKERS[stickerKey] || "";
  const cacheKey = [ip, styleKey, stickerKey, w].join("|");
  const hit = cardCache.get(cacheKey);
  if (hit) return hit;

  const [riskData, cfr] = await Promise.all([
    geoLookup(ip).catch(() => null),
    cfRisk(ip).catch(() => null),
  ]);
  const risk = riskData ? classifyRisk(riskData) : null;
  const country = risk ? risk.country || "" : "";
  const cc = risk ? (risk.country_code || "").toLowerCase() : "";
  const place = [country, risk && risk.city, risk && risk.region].filter(Boolean).join(" · ");
  const netline = risk && risk.asn ? "AS" + risk.asn + (risk.asname || risk.org ? " · " + (risk.asname || risk.org) : "") : (risk && risk.isp) || "未知网络";
  const typeLabel = risk ? (risk.is_datacenter ? "机房网络" : risk.company_type === "education" ? "教育网" : risk.isResidential ? "家庭宽带" : "未知类型") : "未知类型";
  const trust = cfr && typeof cfr.score === "number" ? Math.max(0, 100 - cfr.score) : null;
  const isEmoji = sticker && !/^[A-Z0-9]+$/.test(sticker);
  const flag = cc ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65)) : "🌐";

  const ipLen = (ip || "").length;
  const ipSize = ipLen <= 14 ? 56 : ipLen <= 16 ? 46 : ipLen <= 21 ? 32 : 24;
  const mono = st.mono ? "monospace" : "system-ui, 'Segoe UI', 'Microsoft YaHei', sans-serif";
  const stars = st.stars
    ? Array.from({ length: 26 }, (_, i) => {
        const x = (i * 137 + 40) % 700 + 10, y = (i * 89 + 30) % 300 + 10, r = i % 3 ? 1.1 : 1.8;
        return `<circle cx='${x}' cy='${y}' r='${r}' fill='#ffffff' opacity='0.5'/>`;
      }).join("")
    : "";
  const ring = st.ring ? `<rect x='6' y='6' width='708' height='328' rx='22' fill='none' stroke='${st.ring}' stroke-width='2.5' opacity='0.85'/>` : "";
  const stickerSvg = sticker
    ? (isEmoji
        ? `<text x='668' y='88' font-size='40' text-anchor='middle'>${sticker}</text>`
        : `<g transform='rotate(-8 662 74)'><rect x='616' y='58' width='92' height='30' rx='6' fill='${st.accent}'/><text x='662' y='79' font-size='16' font-weight='800' text-anchor='middle' fill='#111' font-family='monospace'>${sticker}</text></g>`)
    : "";
  const typePill =
    `<rect x='50' y='286' width='108' height='30' rx='15' fill='#00000022'/><text x='104' y='307' font-size='15' font-weight='700' text-anchor='middle' fill='${st.text}'>${typeLabel}</text>`;
  const trustPill = trust === null ? "" :
    `<rect x='170' y='286' width='118' height='30' rx='15' fill='#00000022'/><circle cx='188' cy='301' r='5' fill='${trust >= 85 ? "#4ade80" : trust >= 60 ? "#facc15" : "#f87171"}'/><text x='202' y='307' font-size='15' font-weight='700' fill='${st.text}'>纯净 ${trust}</text>`;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${Math.round(w * 340 / 720)}" viewBox="0 0 720 340" role="img" aria-label="IP 信息卡片">
<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="${st.bg[0]}"/><stop offset="1" stop-color="${st.bg[1]}"/></linearGradient></defs>
<rect width="720" height="340" rx="28" fill="url(#bg)"/>${ring}${stars}
<circle cx="668" cy="40" r="17" fill="none" stroke="${st.accent}" stroke-width="2" opacity="0.9"/>
<ellipse cx="668" cy="40" rx="8" ry="17" fill="none" stroke="${st.accent}" stroke-width="1.6" opacity="0.8"/>
<path d="M651 40h34M656 29h24M656 51h24" stroke="${st.accent}" stroke-width="1.6" fill="none" opacity="0.8"/>${stickerSvg}
<text x="52" y="64" font-size="15" font-weight="700" letter-spacing="4" fill="${st.sub}" font-family="${mono}">你的 IP</text>
<text x="50" y="122" font-size="${ipSize}" font-weight="800" fill="${st.text}" font-family="${mono}">${xmlEsc(ip || "未知")}</text>
<text x="52" y="166" font-size="13" font-weight="700" letter-spacing="3" fill="${st.sub}" font-family="${mono}">位置</text>
<text x="52" y="196" font-size="19" font-weight="600" fill="${st.text}" font-family="${mono}">${flag} ${xmlEsc(place || "未知地区")}</text>
<text x="52" y="238" font-size="13" font-weight="700" letter-spacing="3" fill="${st.sub}" font-family="${mono}">网络</text>
<text x="52" y="266" font-size="16" font-weight="600" fill="${st.text}" font-family="${mono}">${xmlEsc(netline)}</text>
${typePill}${trustPill}
<text x="668" y="318" font-size="13" font-weight="700" fill="${st.sub}" text-anchor="end" font-family="${mono}">NetProbe</text>
</svg>`;
  const out = { svg, ct: "image/svg+xml; charset=utf-8" };
  cardCache.set(cacheKey, out);
  return out;
}

export { cardSvg, CARD_STYLES, CARD_STICKERS };
