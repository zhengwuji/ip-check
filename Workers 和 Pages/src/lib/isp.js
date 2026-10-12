/* ============================================================
   lib/isp.js — ISP 家宽（住宅宽带）判定
   多信号加权：PeeringDB 自报网络类型 + ip-api 机房/移动标志 +
   运营商名称启发式 + 反向 DNS 命名习惯 + ASN 归属
   每个信号都带权重与命中说明，前端可展示判定依据。
   依赖：util、caches
   ============================================================ */
"use strict";
import { fetchJson } from "./util.js";
import { makeCache } from "./caches.js";
import { ipApiOne } from "./ipapi.js";
import { DATACENTER_ASN, DATACENTER_ORG, RESIDENTIAL_HINT } from "./geo.js";

/* PeeringDB 自报网络类型（无需鉴权，但必须带 User-Agent，否则 403），按 ASN 缓存 7 天 */
const PDB_UA = { "Accept": "application/json", "User-Agent": "NetProbe/1.0 (site tool)" };
const pdbCache = makeCache("peeringdb", 7 * 86400000, 5000);
export async function peeringdbNet(asn) {
  if (!asn) return null;
  const hit = pdbCache.get(asn);
  if (hit !== undefined) return hit;
  let d = null;
  try {
    const r = await fetchJson("https://www.peeringdb.com/api/net?asn=" + encodeURIComponent(asn), PDB_UA, 10000);
    const n = r && r.data && r.data[0];
    if (n) {
      const types = Array.isArray(n.info_types) && n.info_types.length ? n.info_types : (n.info_type ? [n.info_type] : []);
      d = {
        name: n.name || "",
        infoType: n.info_type || "",
        infoTypes: types,
        traffic: n.info_traffic || "",
        scope: n.info_scope || "",
        ratio: n.info_ratio || "",
      };
    }
  } catch (e) { d = null; }
  pdbCache.set(asn, d);
  return d;
}

/* 反向 DNS 命名习惯：家宽接入常见词 vs 机房常见词 */
export const HOME_PTR = /(^|[-._])(dsl|adsl|vdsl|ppp|pppoe|ppp0|dynamic|dyn|broadband|bb|pool|dhcp|cable|cmts|hfc|fiber|ftth|fttp|ont|residential|home|client|cust|user|subscriber)([-._]|$)/i;
export const DC_PTR = /(^|[-._])(server|srv|host|hosting|vps|cloud|colo|dedicated|dedi|vm|node|cdn|edge|relay|proxy|backbone|core|peer|ix|transit|static)([-._]|$)/i;

export const MOBILE_HINT = /mobile|wireless|cellular|4g|5g|lte|umts|gsm|移动|无线/i;

/* 各信号权重：正值偏家宽，负值偏机房 */
function collectSignals(ctx) {
  const sig = [];
  const { risk, deep, pdb, ptr } = ctx;
  const org = [risk.org, risk.isp, risk.asname].filter(Boolean).join(" ");

  if (pdb && pdb.infoTypes.length) {
    const t = pdb.infoTypes.join(" / ");
    if (/cable\/dsl\/isp/i.test(t)) sig.push({ key: "peeringdb", w: 45, hit: true, text: "PeeringDB 自报 " + t + "（接入型 ISP，典型家宽运营商）" });
    else if (/nsp/i.test(t)) sig.push({ key: "peeringdb", w: 12, hit: true, text: "PeeringDB 自报 " + t + "（骨干网络服务商，同时经营接入业务）" });
    else if (/content/i.test(t)) sig.push({ key: "peeringdb", w: -45, hit: true, text: "PeeringDB 自报 " + t + "（内容/CDN 网络，非接入 ISP）" });
    else if (/enterprise|network services|cable/i.test(t)) sig.push({ key: "peeringdb", w: -10, hit: true, text: "PeeringDB 自报 " + t });
    else sig.push({ key: "peeringdb", w: 0, hit: true, text: "PeeringDB 自报 " + t });
  } else {
    sig.push({ key: "peeringdb", w: 0, hit: false, text: "PeeringDB 无该 ASN 的自报类型记录" });
  }

  if (risk.hosting === true) sig.push({ key: "hosting", w: -50, hit: true, text: "ip-api 标记为 hosting（机房/托管网段）" });
  else if (risk.hosting === false) sig.push({ key: "hosting", w: 15, hit: true, text: "ip-api 未标记 hosting（非机房网段）" });
  else sig.push({ key: "hosting", w: 0, hit: false, text: "ip-api 无 hosting 标记" });

  if (risk.mobile === true) sig.push({ key: "mobile", w: 0, hit: true, text: "ip-api 标记为 mobile（移动蜂窝网络）" });

  if (DATACENTER_ASN.has(risk.asn)) sig.push({ key: "dc-asn", w: -45, hit: true, text: "AS" + risk.asn + " 在已知机房/云 ASN 名单中" });
  else if (risk.asn) sig.push({ key: "dc-asn", w: 5, hit: false, text: "AS" + risk.asn + " 不在已知机房/云 ASN 名单中" });

  /* 名称特征词互斥判定：接入型 ISP 的名字里常同时出现云/机房词
     （如 "China Telecom Cloud"、"Comcast Cable Communications"），
     若两条都计权会互相抵消，故以家宽特征词优先。 */
  const orgIsHome = !!(org && RESIDENTIAL_HINT.test(org));
  const orgIsDc = !!(org && !orgIsHome && DATACENTER_ORG.test(org));
  if (orgIsDc) sig.push({ key: "dc-org", w: -40, hit: true, text: "运营商名称命中机房/云特征词：" + org.slice(0, 60) });
  if (orgIsHome) sig.push({ key: "home-org", w: 25, hit: true, text: "运营商名称命中家宽/电信运营商特征词：" + org.slice(0, 60) });

  if (ptr && HOME_PTR.test(ptr)) sig.push({ key: "ptr-home", w: 20, hit: true, text: "反向 DNS 命名符合家宽接入习惯：" + ptr });
  if (ptr && DC_PTR.test(ptr)) sig.push({ key: "ptr-dc", w: -20, hit: true, text: "反向 DNS 命名符合机房习惯：" + ptr });
  if (!ptr) sig.push({ key: "ptr", w: 0, hit: false, text: "无反向 DNS 记录" });

  return sig;
}

/* 综合判定：返回结论 + 置信度 + 完整依据链 */
function decide(sig, risk) {
  let score = 0;
  sig.forEach((s) => (score += s.w));

  const mobile = risk.mobile === true || (risk.isp && MOBILE_HINT.test(risk.isp) && !risk.is_datacenter);
  const agreeing = sig.filter((s) => s.hit && Math.abs(s.w) >= 20).length;

  let grade, label, isResidential;
  if (mobile && score > -30) {
    grade = "mobile"; label = "移动网络"; isResidential = false;
  } else if (score >= 55) {
    grade = "residential"; label = "ISP 家宽"; isResidential = true;
  } else if (score >= 20) {
    grade = "access"; label = "宽带接入（可能家宽）"; isResidential = true;
  } else if (score <= -30) {
    grade = "datacenter"; label = "机房 / 托管"; isResidential = false;
  } else {
    grade = "unknown"; label = "无法确定"; isResidential = false;
  }

  /* 置信度：依据链中强信号越多越可信，冲突信号降权 */
  const strong = sig.filter((s) => s.hit && Math.abs(s.w) >= 20);
  const pos = strong.filter((s) => s.w > 0).length;
  const neg = strong.filter((s) => s.w < 0).length;
  let conf = Math.min(92, 28 + Math.max(pos, neg) * 16 - Math.min(pos, neg) * 12);
  if (grade === "unknown") conf = Math.min(conf, 35);
  if (agreeing === 0) conf = Math.min(conf, 25);

  return { score, grade, label, isResidential, confidence: Math.max(5, conf) };
}

/* 主入口：ispCheck(ip, riskData, deep)
   riskData = geo.geoLookup 的原始结果（可空，为空时自动补取 ip-api） */
export async function ispCheck(ip, riskData, deep) {
  let d = riskData;
  if (!d || (!d.org && !d.isp)) {
    const api = await ipApiOne(ip).catch(() => null);
    if (api) d = Object.assign({}, api, d || {});
  }
  d = d || {};
  const risk = {
    asn: d.asn || null,
    asname: d.asname || "",
    org: d.org || "",
    isp: d.isp || "",
    hosting: d.hosting === true ? true : d.hosting === false ? false : null,
    mobile: d.mobile === true,
    is_datacenter: d.hosting === true,
  };
  const ptr = (deep && deep.ptr) || d.reverse || d.ptr || "";
  const pdb = risk.asn ? await peeringdbNet(risk.asn).catch(() => null) : null;

  const sig = collectSignals({ risk, deep: deep || {}, pdb, ptr });
  const verdict = decide(sig, risk);

  /* 人话结论 */
  const why = sig.filter((s) => s.hit && s.w !== 0).map((s) => s.text);
  let note;
  if (verdict.grade === "residential") note = "该 IP 属于 ISP 家用宽带接入网段，家庭用户直接使用。";
  else if (verdict.grade === "access") note = "该 IP 属于宽带接入网段，可能是家宽，也可能是企业专线/固定 IP。";
  else if (verdict.grade === "mobile") note = "该 IP 属于移动蜂窝网络出口，非固定家宽。";
  else if (verdict.grade === "datacenter") note = "该 IP 属于机房/云/托管网段，不是家宽。";
  else note = "信号不足或相互冲突，无法可靠判定是否为家宽。";

  return {
    ip,
    asn: risk.asn,
    asname: risk.asname,
    org: risk.org,
    isp: risk.isp,
    isResidential: verdict.isResidential,
    grade: verdict.grade,
    label: verdict.label,
    confidence: verdict.confidence,
    score: verdict.score,
    peeringdb: pdb,
    ptr,
    signals: sig,
    reasons: why,
    note,
    disclaimer: "基于 PeeringDB 自报类型、ip-api 机房标志与运营商命名习惯的启发式判定，仅供参考。",
  };
}
