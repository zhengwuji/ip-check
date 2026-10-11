/* 本地测试架：直接加载 src/worker.js（与线上完全相同的代码），
   用磁盘 mock ASSETS 绑定，起一个本地 HTTP 服务验证全部路由。
   用法：node dev-server.mjs [端口]（默认 8787） */
"use strict";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import worker from "./src/worker.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(here, "public");
const PORT = parseInt(process.argv[2] || "8787", 10);

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml; charset=utf-8",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

const env = {
  ASSETS: {
    async fetch(urlOrRequest) {
      const url = urlOrRequest instanceof URL ? urlOrRequest : new URL(urlOrRequest.url);
      let p = decodeURIComponent(url.pathname);
      if (p === "/" || p === "") p = "/index.html";
      const filePath = path.join(PUBLIC_DIR, path.normalize(p).replace(/^(\.\.[/\\])+/, ""));
      if (!filePath.startsWith(PUBLIC_DIR)) return new Response("Forbidden", { status: 403 });
      let target = filePath;
      try { const st = fs.statSync(target); if (st.isDirectory()) target = path.join(target, "index.html"); } catch (e) {}
      try {
        const buf = fs.readFileSync(target);
        const ct = MIME[path.extname(target).toLowerCase()] || "application/octet-stream";
        return new Response(buf, { status: 200, headers: { "Content-Type": ct, "Cache-Control": "no-cache" } });
      } catch (e) {
        return new Response("Not Found", { status: 404 });
      }
    },
  },
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://" + (req.headers.host || "localhost"));
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    try { headers[k] = Array.isArray(v) ? v.join(",") : String(v); } catch (e) {}
  }
  if (!headers["cf-connecting-ip"] && !headers["x-forwarded-for"]) headers["cf-connecting-ip"] = req.socket.remoteAddress?.replace(/^::ffff:/, "") || "127.0.0.1";
  const method = req.method;
  let body;
  if (method === "POST" || method === "PUT") {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    body = Buffer.concat(chunks);
  }
  const request = new Request(url.href, {
    method,
    headers,
    body: body && body.length ? body : undefined,
  });
  const resp = await worker.fetch(request, env, { waitUntil: () => {}, passThroughOnException: () => {} });
  const outHeaders = {};
  resp.headers.forEach((v, k) => { outHeaders[k] = v; });
  res.writeHead(resp.status, outHeaders);
  const buf = Buffer.from(await resp.arrayBuffer());
  res.end(buf);
});

server.listen(PORT, () => {
  console.log("NetProbe Workers dev-server: http://127.0.0.1:" + PORT);
});
