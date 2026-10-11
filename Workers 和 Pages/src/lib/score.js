/* ============================================================
   lib/score.js — IP 评分全家桶编排（Workers 版）
   子请求数优化（免费版每请求上限 50）：
   - dnsblCheck 的 spamcop/dronebl 从 dnsblFull 派生（省 2 次 DoH）
   - PTR 查询经 doh.js 内存缓存去重（ipDeep 与 relatedDomains 共享）
   - 同网段样本 8 个、关联域名邻居 4 个
   ============================================================ */
"use strict";
import { isBogon } from "./util.js";
import * as geo from "./geo.js";
import * as dnsbl from "./dnsbl.js";
import * as ripe from "./ripe.js";
import { ipDeep } from "./ipdeep.js";

export async function ipScore(ip) {
  const [riskData, deep] = await Promise.all([geo.geoLookup(ip).catch(() => null), ipDeep(ip)]);
  const risk = riskData ? geo.classifyRisk(riskData) : null;
  if (riskData && riskData.asn) {
    deep.asn = riskData.asn;
    deep.asname = riskData.asname || "";
    deep.org = riskData.org || riskData.isp || "";
    deep.bogon = isBogon(ip);
  }
  const asn = risk && risk.asn ? await ripe.asnInfo(risk.asn).catch(() => null) : null;
  if (asn && asn.date) deep.asnRegDate = asn.date;
  const [db, rp, sources, route, dbll, domains, sample, neighbours] = await Promise.all([
    dnsbl.dnsblCheck(ip).catch(() => null),
    ripe.rpkiCheck(ip, risk && risk.asn).catch(() => null),
    geo.geoMulti(ip).catch(() => []),
    ripe.routeTopology(ip, risk && risk.asn).catch(() => null),
    dnsbl.dnsblFull(ip).catch(() => null),
    geo.relatedDomains(ip).catch(() => null),
    geo.subnetSample(ip).catch(() => null),
    risk && risk.asn ? ripe.asnNeighbours(risk.asn).catch(() => null) : Promise.resolve(null),
  ]);
  geo.recordGeoHistory(ip, riskData);
  return { ip, risk, deep, asn, dnsbl: db, rpki: rp, sources, route, dnsblFull: dbll, domains, sample, neighbours, geoHistory: geo.geoHistoryFor(ip) };
}
