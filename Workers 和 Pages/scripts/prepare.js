/* 准备脚本：从主项目复制 public/，并把 ?v=AUTO 烘焙成内容 hash 版本号
   （Workers 无文件系统，运行时无法扫描资源，因此在部署前生成） */
"use strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import crypto from "node:crypto";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, "..");
const srcPublic = path.join(root, "..", "ipcheck", "public");
const dstPublic = path.join(root, "public");

// 1) 复制（排除 sw/manifest? 不排除，全部照搬）
//
// 注意：这里刻意不用 fs.rmSync / fs.cpSync。
// 在 Windows + Node 24 上，当路径中出现「CJK 字符紧跟空格」时
// （本项目目录名即 `Workers 和 Pages`），rmSync / cpSync 会在原生层
// 直接快速失败，进程以 exit code -1073740791（0xC0000409
// STATUS_STACK_BUFFER_OVERRUN）终止且没有任何输出，而 unlinkSync /
// rmdirSync / copyFileSync 等基础调用在同一路径下工作正常。
// 因此改用仅依赖基础 API 的等价实现，保证脚本可移植。
function rmrf(p) {
  let st;
  try { st = fs.lstatSync(p); } catch (e) { return; }
  if (st.isDirectory()) {
    for (const n of fs.readdirSync(p)) rmrf(path.join(p, n));
    fs.rmdirSync(p);
  } else {
    fs.unlinkSync(p);
  }
}

function cprf(src, dst) {
  const st = fs.statSync(src);
  if (st.isDirectory()) {
    fs.mkdirSync(dst, { recursive: true });
    for (const n of fs.readdirSync(src)) cprf(path.join(src, n), path.join(dst, n));
  } else {
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    fs.copyFileSync(src, dst);
  }
}

rmrf(dstPublic);
cprf(srcPublic, dstPublic);

// 2) 资源版本 hash：基于 assets/ 与 favicon 的路径+大小+mtime
function walkHash(dir, acc) {
  let items = [];
  try { items = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
  for (const it of items.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const p = path.join(dir, it.name);
    if (it.isDirectory()) walkHash(p, acc);
    else {
      const st = fs.statSync(p);
      acc.update(p + ":" + st.size + ":" + Math.floor(st.mtimeMs / 1000) + ";");
    }
  }
}
const hash = crypto.createHash("sha1");
walkHash(path.join(dstPublic, "assets"), hash);
try { const st = fs.statSync(path.join(dstPublic, "favicon.svg")); hash.update("favicon:" + st.size + ":" + Math.floor(st.mtimeMs / 1000)); } catch (e) {}
const ver = hash.digest("hex").slice(0, 8);

// 3) 烘焙 HTML
let n = 0;
function walkHtml(dir) {
  for (const f of fs.readdirSync(dir)) {
    const p = path.join(dir, f);
    const st = fs.statSync(p);
    if (st.isDirectory()) walkHtml(p);
    else if (f.endsWith(".html")) {
      let s = fs.readFileSync(p, "utf8");
      if (s.includes("?v=AUTO")) { fs.writeFileSync(p, s.replaceAll("?v=AUTO", "?v=" + ver)); n++; }
    }
  }
}
walkHtml(dstPublic);
console.log("prepare: public/ 复制完成，资源版本 " + ver + "，烘焙 " + n + " 个 HTML");
