/* 生成 PWA 图标（纯 Node，zlib + PNG 格式手工编码）
   输出：public/assets/icons/icon-192.png / icon-512.png / icon-maskable-512.png
   图形：深蓝渐变底 + 白色经纬球 + 白色 "N"（几何线条光栅化） */
"use strict";
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

function crc32(buf) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c;
    }
  }
  let c = 0 ^ -1;
  for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ table[(c ^ buf[i]) & 0xff];
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function encodePNG(w, h, rgba) {
  // filter 0 (None) 每行
  const stride = w * 4;
  const raw = Buffer.alloc((stride + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function drawIcon(size, maskable) {
  const px = Buffer.alloc(size * size * 4);
  const s = size;
  const cx = s / 2, cy = s / 2;
  // 内容缩放：maskable 需要 20% 安全边距
  const scale = maskable ? 0.62 : 0.78;
  const R = s * 0.36 * scale / 0.78; // 球半径
  function set(x, y, r, g, b, a) {
    if (x < 0 || y < 0 || x >= s || y >= s) return;
    const i = (y * s + x) * 4;
    const na = a / 255;
    px[i] = Math.round(px[i] * (1 - na) + r * na);
    px[i + 1] = Math.round(px[i + 1] * (1 - na) + g * na);
    px[i + 2] = Math.round(px[i + 2] * (1 - na) + b * na);
    px[i + 3] = Math.max(px[i + 3], Math.round(a));
  }
  for (let y = 0; y < s; y++) {
    for (let x = 0; x < s; x++) {
      // 背景：#0f172a → #1e3a8a 对角渐变（maskable 全幅）
      const t = (x + y) / (2 * s);
      const r = Math.round(15 + (30 - 15) * t);
      const g = Math.round(23 + (58 - 23) * t);
      const b = Math.round(42 + (138 - 42) * t);
      if (maskable) { set(x, y, r, g, b, 255); }
      else {
        // 普通图标：圆角矩形底（圆角 = 22%）
        const rad = s * 0.22;
        const dx = Math.min(x, s - 1 - x), dy = Math.min(y, s - 1 - y);
        const inside = (x >= 0 && x < s && y >= 0 && y < s) &&
          (dx >= rad || dy >= rad || (rad - dx) * (rad - dx) + (rad - dy) * (rad - dy) <= rad * rad);
        if (inside) set(x, y, r, g, b, 255);
      }
    }
  }
  // 经纬球（线框）
  const gr = R;
  for (let a = 0; a < 360 * 3; a++) {
    const rad = a * Math.PI / 540;
    set(Math.round(cx + gr * Math.cos(rad)), Math.round(cy + gr * Math.sin(rad)), 255, 255, 255, 235);
  }
  for (let a = 0; a < 180; a++) {
    const rad = a * Math.PI / 180;
    // 赤道 + 两条纬线
    for (const latF of [0, 0.5, -0.5]) {
      const yy = cy + gr * Math.sin(rad) * (1 - Math.abs(latF) * 0);
      // 简化：三条水平弦线
    }
  }
  // 水平线（赤道/纬线）
  for (const f of [-0.55, 0, 0.55]) {
    const halfW = Math.sqrt(Math.max(0, gr * gr - (f * gr) * (f * gr)));
    for (let x = Math.round(cx - halfW); x <= Math.round(cx + halfW); x++) {
      set(x, Math.round(cy + f * gr), 255, 255, 255, 200);
    }
  }
  // 垂直经线（椭圆近似：三个宽度）
  for (const wf of [0.35, 0.7]) {
    const halfH = gr;
    for (let t = 0; t < 360; t++) {
      const rad = t * Math.PI / 180;
      set(Math.round(cx + wf * gr * Math.cos(rad)), Math.round(cy + halfH * Math.sin(rad)), 255, 255, 255, 170);
    }
  }
  // 字母 N（两竖一斜）
  const Nw = gr * 0.72, Nh = gr * 0.9, Nx = cx - Nw / 2, Ny = cy - Nh / 2, lw = Math.max(2, s * 0.035);
  function fillRect(x0, y0, x1, y1, alpha) {
    for (let y = Math.round(y0); y <= Math.round(y1); y++)
      for (let x = Math.round(x0); x <= Math.round(x1); x++) set(x, y, 255, 255, 255, alpha);
  }
  fillRect(Nx, Ny, Nx + lw, Ny + Nh, 255);
  fillRect(Nx + Nw - lw, Ny, Nx + Nw, Ny + Nh, 255);
  for (let i = 0; i <= 100; i++) {
    const t = i / 100;
    const x = Nx + lw + t * (Nw - 2 * lw);
    const y = Ny + (1 - t) * (Nh - lw) ;
    fillRect(x - lw / 2, y, x + lw / 2, y + lw, 255);
  }
  return encodePNG(s, s, px);
}

const outDir = path.join(__dirname, "..", "public", "assets", "icons");
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "icon-192.png"), drawIcon(192, false));
fs.writeFileSync(path.join(outDir, "icon-512.png"), drawIcon(512, false));
fs.writeFileSync(path.join(outDir, "icon-maskable-512.png"), drawIcon(512, true));
console.log("icons generated in", outDir);
