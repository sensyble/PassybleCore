#!/usr/bin/env node
// Passyble logo: the single source of truth for every app, tray, installer, extension and Android icon.
//
//   node Core/desktop-app/scripts/make-icons.mjs          # writes everything listed below
//   (cd extension && npm run icons)                   # extension outputs only (thin wrapper)
//
// The mark is the "y" of the Passyble wordmark ("Pass", the lime "y", "ble"; passyble.com and
// ui/lib.js wordmark()): Sensyble's stylised lowercase "y" (see scripts/brand/README.md) turned into a
// key. The ring is the key's bow, the long curved stroke and its descender are the shaft, and the
// short thick arm is the bit, with a ward slot cut into its end. It stands as in the wordmark: the
// bow at the bottom left, the shaft rising to the right, the bit at the top right. The source
// geometry below is the "y" as drawn in the 1254x1254 reference artwork (straight edges as lines, the
// curve as two fitted cubic Beziers, the ring as two circles); keyMark() turns it and cuts the slot.
// Everything else (SVG, Android vector pathData and the rasterized PNG/ICO files) is produced from
// those same contours.
//
// No tile, no background: the mark is the wordmark's lime (#c6f432) with a dark green border (#4f6b00)
// on transparent, so it reads the same on dark surfaces (the lime) and on light ones (the border). The
// border is drawn outside the lime and counted in the mark's size (the lime shrinks to make room). The
// in-page marks (the wordmark's "y", the extension's note, the Android in-app logo) are the same
// two-colour mark in both themes; only the monochrome icons (Android notification and themed icon,
// the macOS menu bar template) are the bare mark in one colour.
//
// Outputs:
//   Core/desktop-app/ui/logo.svg, Extension/icons/icon.svg, src-tauri/src/passkey_provider/logo.svg
//                                              (the icon: lime mark, dark green border, 24x24 viewBox)
//   Core/desktop-app/src-tauri/icons/32x32.png, 128x128.png, 128x128@2x.png (256), icon.png (512)
//   Core/desktop-app/src-tauri/icons/16x16.png, 24x24.png, 48x48.png, 64x64.png (Linux icon theme sizes)
//   Core/desktop-app/src-tauri/icons/icon.ico  (16, 20, 24, 32, 40, 48, 64, 256; PNG-encoded entries;
//                                          also the installer icon and, via the default window
//                                          icon, the Windows tray icon)
//   Extension/icons/icon-16.png, icon-32.png, icon-48.png, icon-128.png
//   Extension/src/shared/logo.js               (the wordmark's "y" and its border as path data for the
//                                               in-page UI; ui/lib.js wordmark() and the websites'
//                                               wordmarks use wordmarkSvg())
//   Android/app/src/main/res/drawable/ic_launcher_foreground.xml   (adaptive foreground: the icon)
//   Android/app/src/main/res/drawable/ic_launcher_background.xml   (adaptive background: transparent)
//   Android/app/src/main/res/drawable/ic_launcher_monochrome.xml   (Android 13+ themed icon layer)
//   Android/app/src/main/res/drawable/ic_stat_pass.xml             (notification / QS tile silhouette)
//   Android/app/src/main/res/drawable/ic_pass_mark.xml             (in-app mark: lime, dark green border)
//   Core/desktop-app/scripts/brand/passyble-icon.svg, passyble-wordmark-y.svg, passyble-key-mono.svg,
//                                  sensyble-mark.svg
//
// Small sizes (<= 48 px) are hinted: the border is at least 1.5 px wide, the margin goes at <= 32 px,
// the ring is drawn heavier with a larger hole and the ward slot is dropped at <= 20 px (a 1 px slot
// only adds mush), and the mark's sub-pixel position is searched for the crispest result (lime and
// border together) on that pixel grid.
// Rendering: exact horizontal span coverage x 4..16 sub-rows per pixel (non-zero winding), written as
// 8-bit RGBA PNG with node:zlib. No npm dependencies.
import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..', '..');

const VIEW = 24; // icon geometry is in a 24x24 coordinate space

// Brand (docs/BRAND.md, "Logo"). lime is the mark's fill; edge its border (4.8:1 against the lime,
// 6.1:1 on white, so the mark keeps its shape on light taskbars, toolbars, tab bars and pages, and
// 2.9:1 on the dark surfaces, where it still shows as a green rim); limeMark is --lime-mark on light
// (status dots and small accents, not the logo); mark the monochrome (white) silhouette for
// notification and themed icons.
export const COLORS = {
  lime: '#c6f432',
  limeMark: '#6e9a00',
  edge: '#4f6b00',
  mark: '#ffffff',
};

// ---- Sensyble "y" (source geometry) ----------------------------------------------------------------
// Units: pixels of the 1254x1254 reference artwork, y down. Straight edges are x = m * y + c.
const Y = {
  top: 359, // flat cut at the top of the left arm
  foot: 1051, // flat cut at the bottom of the descender
  armL: [0.60787, -81.58], // left arm, outer edge
  armR: [0.59714, 140.81], // left arm, inner edge (meets the stem in the crotch)
  stemL: [-0.53112, 908.17], // stem, upper-left edge below the curve
  descL: [-0.52315, 897.27], // descender, left edge (below the arm)
  stemR: [-0.50933, 1037.02], // stem + descender, right edge
  // The stem curving right into the ring: upper and lower edges, each a cubic from the straight edge.
  upper: [[562.94, 650], [651.32, 483.6], [689.52, 420.52], [843.62, 380.77]],
  lower: [[670.3, 720], [738.31, 586.47], [763.04, 522.71], [877.17, 492.03]],
  ring: { cx: 995.49, cy: 395.66, r1: 152.6, r0: 76.7 },
};

const xAt = ([m, c], y) => m * y + c;
const meet = ([m1, c1], [m2, c2]) => { const y = (c2 - c1) / (m1 - m2); return [m1 * y + c1, y]; };

// A contour is { start: [x, y], segs: [{ p }, { c1, c2, p }, ...] } (lines and cubics), implicitly closed.
const contour = (start) => ({ start, segs: [] });
const lineTo = (k, p) => (k.segs.push({ p }), k);
const curveTo = (k, c1, c2, p) => (k.segs.push({ c1, c2, p }), k);

// Circle as four cubic arcs; ccw = true for a hole.
function circleContour(cx, cy, r, ccw = false) {
  const q = 0.5522847498 * r;
  const s = ccw ? -1 : 1;
  const k = contour([cx + r, cy]);
  curveTo(k, [cx + r, cy + s * q], [cx + q, cy + s * r], [cx, cy + s * r]);
  curveTo(k, [cx - q, cy + s * r], [cx - r, cy + s * q], [cx - r, cy]);
  curveTo(k, [cx - r, cy - s * q], [cx - q, cy - s * r], [cx, cy - s * r]);
  curveTo(k, [cx + q, cy - s * r], [cx + r, cy - s * q], [cx + r, cy]);
  return k;
}

/**
 * The "y" in source units, optionally modified into the key (defaults reproduce the "y" exactly):
 *   top:   y of the arm's flat end cut (larger = shorter arm, i.e. a shorter key bit)
 *   foot:  y of the descender's flat end cut (smaller = shorter shaft tip)
 *   ring:  { grow, hole }: the ring scaled by `grow` about the point where the stroke joins it (so
 *          the joint keeps its shape), with an inner radius of `hole` x the outer radius
 *   slot:  [from, to, depth] ward slot cut into the arm's end (fractions of the end face, depth in
 *          source units along the arm), a list of them (left to right), or null
 */
export function yContours({ top = Y.top, foot = Y.foot, ring = {}, slot = null } = {}) {
  const { grow = 1, hole = Y.ring.r0 / Y.ring.r1 } = ring;
  const join = (163 * Math.PI) / 180; // direction from the ring's centre to the joint
  const ax = Y.ring.cx + Y.ring.r1 * Math.cos(join), ay = Y.ring.cy + Y.ring.r1 * Math.sin(join);
  const r1 = Y.ring.r1 * grow;
  const cx = ax + (Y.ring.cx - ax) * grow, cy = ay + (Y.ring.cy - ay) * grow;
  const t1 = [xAt(Y.armL, top), top];
  const t2 = [xAt(Y.armR, top), top];
  const main = contour(t1);
  const slots = !slot ? [] : Array.isArray(slot[0]) ? slot : [slot];
  const dir = (Y.armL[0] + Y.armR[0]) / 2; // the arm's dx per unit y
  const at = (f) => t1[0] + (t2[0] - t1[0]) * f;
  for (const [f0, f1, depth] of slots) {
    lineTo(main, [at(f0), top]);
    lineTo(main, [at(f0) + dir * depth, top + depth]);
    lineTo(main, [at(f1) + dir * depth, top + depth]);
    lineTo(main, [at(f1), top]);
  }
  lineTo(main, t2);
  lineTo(main, meet(Y.armR, Y.stemL)); // crotch
  lineTo(main, Y.upper[0]);
  curveTo(main, Y.upper[1], Y.upper[2], Y.upper[3]);
  lineTo(main, Y.lower[3]); // chord across the ring band (stays clear of the hole)
  curveTo(main, Y.lower[2], Y.lower[1], Y.lower[0]);
  lineTo(main, [xAt(Y.stemR, foot), foot]);
  lineTo(main, [xAt(Y.descL, foot), foot]);
  lineTo(main, meet(Y.descL, Y.armL));
  return [main, circleContour(cx, cy, r1), circleContour(cx, cy, r1 * hole, true)];
}

// ---- the key ------------------------------------------------------------------------------------

// Design parameters (the chosen variant), see yContours() for top / foot / ring / slot. rotate:
// degrees applied to the source (y down, so positive turns clockwise on screen).
export const KEY = {
  rotate: 152, // the wordmark's "y": bow at the bottom left, shaft rising right, bit at the top right
  top: 470, // bit about 3/4 of the arm's length
  foot: 1000, // shaft tip just past the bit
  ring: { grow: 1.75, hole: 0.63 }, // a bow big enough to read as one; the hole stays open inside the border
  slot: [0.32, 0.68, 90], // one ward slot (the border fills it as a dark notch), so the bit reads as two teeth
  tiny: { slot: null, ring: { grow: 2.1, hole: 0.76 } }, // <= 20 px: no slot (only mush), a heavier bow whose hole survives the 1.5 px border
};

// The icon (lime mark, dark green border, transparent): border width and margin in 24-unit view
// units. The border is 1.2 units, about 6% of the lime mark's height (19.6 units); it is never thinner
// than minPx pixels (1.5 px at 16 to 24 px). The margin goes at <= 32 px (tray, toolbar, favicon).
export const ICON = { edge: 1.2, pad: 1, minPx: 1.5 };

/** The border's width as a share of the lime mark's height; every bordered mark uses it. */
export const EDGE_RATIO = ICON.edge / (VIEW - 2 * (ICON.pad + ICON.edge));

// Per-size options (pixel size -> keyMark options); size = null is canonical.
function keyOptions(size, key = KEY) {
  return size != null && size <= 20 ? { ...key, ...key.tiny } : { ...key };
}

// ---- contour maths ----------------------------------------------------------------------------------

const mapPt = (m, [x, y]) => [m[0] * x + m[1] * y + m[2], m[3] * x + m[4] * y + m[5]];
const mapContours = (ks, m) => ks.map((k) => ({
  start: mapPt(m, k.start),
  segs: k.segs.map((s) => (s.c1 ? { c1: mapPt(m, s.c1), c2: mapPt(m, s.c2), p: mapPt(m, s.p) } : { p: mapPt(m, s.p) })),
}));

function flattenCubic(p0, c1, c2, p3, tol, out, depth = 0) {
  const d = (q) => {
    const dx = p3[0] - p0[0], dy = p3[1] - p0[1];
    const len = Math.hypot(dx, dy) || 1e-9;
    return Math.abs((q[0] - p0[0]) * dy - (q[1] - p0[1]) * dx) / len;
  };
  if (depth > 18 || Math.max(d(c1), d(c2)) <= tol) { out.push(p3); return; }
  const mid = (a, b) => [(a[0] + b[0]) / 2, (a[1] + b[1]) / 2];
  const a = mid(p0, c1), b = mid(c1, c2), c = mid(c2, p3), ab = mid(a, b), bc = mid(b, c), m = mid(ab, bc);
  flattenCubic(p0, a, ab, m, tol, out, depth + 1);
  flattenCubic(m, bc, c, p3, tol, out, depth + 1);
}

export function flatten(ks, tol) {
  return ks.map((k) => {
    const pts = [k.start];
    let cur = k.start;
    for (const s of k.segs) {
      if (s.c1) flattenCubic(cur, s.c1, s.c2, s.p, tol, pts); else pts.push(s.p);
      cur = s.p;
    }
    return pts;
  });
}

const area = (pts) => pts.reduce((a, p, i) => { const q = pts[(i + 1) % pts.length]; return a + p[0] * q[1] - q[0] * p[1]; }, 0) / 2;

function reverse(k) {
  const pts = [k.start, ...k.segs.map((s) => s.p)];
  const segs = [];
  for (let i = k.segs.length - 1; i >= 0; i--) {
    const s = k.segs[i];
    segs.push(s.c1 ? { c1: s.c2, c2: s.c1, p: pts[i] } : { p: pts[i] });
  }
  return { start: k.segs.length ? k.segs[k.segs.length - 1].p : k.start, segs };
}

// Orients contours for non-zero filling: the first `outer` contours clockwise (on screen), the rest
// counter-clockwise (holes).
function orient(ks, outer) {
  return ks.map((k, i) => {
    const a = area(flatten([k], 1)[0]);
    return (i < outer) === (a > 0) ? k : reverse(k);
  });
}

export function bbox(ks) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const pts of flatten(ks, 0.25)) for (const [x, y] of pts) {
    x0 = Math.min(x0, x); y0 = Math.min(y0, y); x1 = Math.max(x1, x); y1 = Math.max(y1, y);
  }
  return { x0, y0, x1, y1 };
}

/**
 * The key mark placed in a target space: turned by `rotate` degrees, scaled so its bounding box's
 * longer side (the height, as the mark stands) is `box`, centred on (cx, cy) plus `shift`. Returns
 * oriented contours.
 */
export function keyMark({ rotate = KEY.rotate, top, foot, slot, ring, box, cx, cy, shift = [0, 0] }) {
  const a = (rotate * Math.PI) / 180, cs = Math.cos(a), sn = Math.sin(a);
  const rotated = mapContours(yContours({ top, foot, slot, ring }), [cs, -sn, 0, sn, cs, 0]);
  const b = bbox(rotated);
  const s = box / Math.max(b.x1 - b.x0, b.y1 - b.y0);
  const tx = cx + shift[0] - ((b.x0 + b.x1) / 2) * s;
  const ty = cy + shift[1] - ((b.y0 + b.y1) / 2) * s;
  return orient(mapContours(rotated, [s, 0, tx, 0, s, ty]), 2);
}

/**
 * The wordmark's "y" as placed in the wordmark (ui/lib.js wordmark(), passyble.com), in the
 * coordinates of WORDMARK_VIEW, and the width of its border (view units). The lime mark and its
 * border together fill the place the bare mark had (16.246 units tall, with the wordmark's own
 * margins), so the wordmark's spacing is unchanged.
 */
export const WORDMARK_VIEW = '4.705 3.160 14.935 17.171';
export function wordmarkY() {
  // The wordmark was drawn as the earlier tilted key (turned -131 degrees, 17 units, nudged right
  // and down) turned a further 283 degrees about the centre of its 24-unit view.
  const k = keyMark({ ...KEY, rotate: KEY.rotate - 283, box: 17, cx: 12.35, cy: 12.45 });
  const a = (283 * Math.PI) / 180, cs = Math.cos(a), sn = Math.sin(a);
  const placed = mapContours(k, [cs, -sn, 12 - 12 * cs + 12 * sn, sn, cs, 12 - 12 * sn - 12 * cs]);
  const b = bbox(placed);
  const h = b.y1 - b.y0, x = (b.x0 + b.x1) / 2, y = (b.y0 + b.y1) / 2;
  const s = 1 / (1 + 2 * EDGE_RATIO);
  return { shape: mapContours(placed, [s, 0, x - s * x, 0, s, y - s * y]), edge: EDGE_RATIO * h * s };
}

/**
 * The wordmark's "y" as inline SVG markup: the border (a round-joined stroke under the fill) and the
 * lime. `attrs` go on the <svg> element (class, aria-hidden and so on).
 */
export function wordmarkSvg(attrs = '') {
  const { shape, edge } = wordmarkY();
  const d = pathData(shape);
  return `<svg${attrs ? ' ' + attrs : ''} viewBox="${WORDMARK_VIEW}">`
    + `<path d="${d}" fill="${COLORS.edge}" stroke="${COLORS.edge}" stroke-width="${f(2 * edge)}" stroke-linejoin="round"/>`
    + `<path d="${d}" fill="${COLORS.lime}"/></svg>`;
}

const f = (n) => { const s = (+n.toFixed(3)).toString(); return s === '-0' ? '0' : s; };
export function pathData(ks) {
  return ks.map((k) => `M${f(k.start[0])} ${f(k.start[1])}` + k.segs.map((s) => (s.c1
    ? `C${f(s.c1[0])} ${f(s.c1[1])} ${f(s.c2[0])} ${f(s.c2[1])} ${f(s.p[0])} ${f(s.p[1])}`
    : `L${f(s.p[0])} ${f(s.p[1])}`)).join('') + 'Z').join('');
}

// ---- scenes -------------------------------------------------------------------------------------
// A scene is { view, layers: [{ shape, paint, grow?, mark? }] }: `grow` (view units) draws the shape
// outlined by that much (a round-joined stroke in SVG, a dilation in the rasterizer); `mark` flags the
// layer the small-size hinting positions.

/**
 * The app icon for a pixel size (size = null is canonical): the dark green border under the lime mark,
 * on transparent. The border is at least ICON.minPx pixels wide.
 */
export function iconScene(size = null, key = KEY, shift = [0, 0]) {
  const o = keyOptions(size, key);
  const edge = size == null ? ICON.edge : Math.max(ICON.edge, (ICON.minPx * VIEW) / size);
  const pad = size != null && size <= 32 ? 0 : ICON.pad;
  const mark = keyMark({ ...o, box: VIEW - 2 * (pad + edge), cx: VIEW / 2, cy: VIEW / 2, shift });
  return {
    view: VIEW,
    layers: [
      { shape: mark, paint: COLORS.edge, grow: edge },
      { shape: mark, paint: COLORS.lime, mark: true },
    ],
  };
}

/** The bare mark (no edge) in `color`, its height filling a `view`-unit square less `pad` units of margin. */
export function markScene({ size = null, color = COLORS.limeMark, view = VIEW, pad = 1, key = KEY, shift = [0, 0] } = {}) {
  const o = keyOptions(size, key);
  return { view, layers: [{ shape: keyMark({ ...o, box: view - 2 * pad, cx: view / 2, cy: view / 2, shift }), paint: color, mark: true }] };
}

// ---- SVG ----------------------------------------------------------------------------------------

export function sceneSvg(scene, px = 128, { comment = true, viewBox } = {}) {
  const body = scene.layers.map((l) => (l.grow
    ? `  <path d="${pathData(l.shape)}" fill="${l.paint}" stroke="${l.paint}" stroke-width="${f(2 * l.grow)}" stroke-linejoin="round"/>`
    : `  <path d="${pathData(l.shape)}" fill="${l.paint}"/>`));
  const vb = viewBox || `0 0 ${scene.view} ${scene.view}`;
  const [, , vw, vh] = vb.split(' ').map(Number);
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vb}" width="${Math.round((px * vw) / Math.max(vw, vh))}" height="${Math.round((px * vh) / Math.max(vw, vh))}">`,
    ...(comment ? ['  <!-- Generated by Core/desktop-app/scripts/make-icons.mjs; edit the geometry there. -->'] : []),
    ...body,
    '</svg>',
    '',
  ].join('\n');
}

/** The icon as SVG (canonical geometry). */
export const svg = (opts) => sceneSvg(iconScene(), 128, opts);

// ---- raster -------------------------------------------------------------------------------------

/** Coverage (0..1) of the non-zero fill of `polys` (pixel units) on a w x h grid. */
function coverage(polys, w, h, ss) {
  const acc = new Float32Array(w * h);
  const edges = [];
  for (const pts of polys) for (let i = 0; i < pts.length; i++) {
    const [x0, y0] = pts[i], [x1, y1] = pts[(i + 1) % pts.length];
    if (y0 === y1) continue;
    edges.push(y0 < y1 ? [y0, y1, x0, (x1 - x0) / (y1 - y0), 1] : [y1, y0, x1, (x0 - x1) / (y0 - y1), -1]);
  }
  const xs = [];
  for (let j = 0; j < h; j++) {
    for (let s = 0; s < ss; s++) {
      const y = j + (s + 0.5) / ss;
      xs.length = 0;
      for (const e of edges) if (y >= e[0] && y < e[1]) xs.push([e[2] + (y - e[0]) * e[3], e[4]]);
      xs.sort((a, b) => a[0] - b[0]);
      let wnd = 0;
      for (let k = 0; k < xs.length - 1; k++) {
        wnd += xs[k][1];
        if (wnd !== 0) span(acc, j * w, w, xs[k][0], xs[k + 1][0], 1 / ss);
      }
    }
  }
  return acc;
}
function span(acc, row, w, xa, xb, wt) {
  xa = Math.max(0, xa); xb = Math.min(w, xb);
  if (xb <= xa) return;
  const ia = Math.floor(xa), ib = Math.floor(xb);
  if (ia === ib) { acc[row + ia] += (xb - xa) * wt; return; }
  acc[row + ia] += (ia + 1 - xa) * wt;
  for (let i = ia + 1; i < ib; i++) acc[row + i] += wt;
  if (ib < w) acc[row + ib] += (xb - ib) * wt;
}

/**
 * Coverage of `polys` grown by `r` pixels (the shape with a round-joined outline of that width, as
 * SVG draws a round-joined stroke under the fill): the shape's own coverage, plus every pixel by the
 * share of its 4 x 4 sub-samples that lie within `r` of the outline.
 */
function grownCoverage(polys, w, h, ss, r) {
  const acc = coverage(polys, w, h, ss);
  const segs = [];
  for (const pts of polys) for (let i = 0; i < pts.length; i++) segs.push([...pts[i], ...pts[(i + 1) % pts.length]]);
  const dist2 = (x, y) => {
    let best = Infinity;
    for (const [ax, ay, bx, by] of segs) {
      const dx = bx - ax, dy = by - ay, l = dx * dx + dy * dy;
      const t = l ? Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / l)) : 0;
      const ex = ax + t * dx - x, ey = ay + t * dy - y, d = ex * ex + ey * ey;
      if (d < best) best = d;
    }
    return best;
  };
  const n = 4, r2 = r * r;
  for (let j = 0; j < h; j++) for (let i = 0; i < w; i++) {
    const p = j * w + i;
    if (acc[p] >= 1) continue;
    const d = Math.sqrt(dist2(i + 0.5, j + 0.5));
    if (d > r + 0.75) continue;
    let c = 1;
    if (d > r - 0.75) {
      c = 0;
      for (let sy = 0; sy < n; sy++) for (let sx = 0; sx < n; sx++) if (dist2(i + (sx + 0.5) / n, j + (sy + 0.5) / n) <= r2) c++;
      c /= n * n;
    }
    if (c > acc[p]) acc[p] = c;
  }
  return acc;
}

const hex = (s) => {
  const h = s.length === 4 ? s.replace(/[0-9a-f]/gi, (d) => d + d) : s; // #rgb -> #rrggbb
  return [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
};

const scaleContours = (ks, k) => mapContours(ks, [k, 0, 0, 0, k, 0]);

/** Renders a scene to straight-alpha RGBA bytes. */
export function rasterize(scene, size) {
  const k = size / scene.view;
  const ss = Math.max(4, Math.min(16, Math.ceil(256 / size)));
  const prem = new Float32Array(size * size * 4);
  for (const { shape, paint, grow } of scene.layers) {
    const polys = flatten(scaleContours(shape, k), 0.02);
    const cov = grow ? grownCoverage(polys, size, size, ss, grow * k) : coverage(polys, size, size, ss);
    const c = hex(paint);
    for (let p = 0; p < size * size; p++) {
      const a = Math.min(1, cov[p]);
      if (a <= 0) continue;
      const o = p * 4;
      for (let n = 0; n < 3; n++) prem[o + n] = c[n] * a + prem[o + n] * (1 - a);
      prem[o + 3] = a + prem[o + 3] * (1 - a);
    }
  }
  const out = Buffer.alloc(size * size * 4);
  for (let p = 0; p < size * size; p++) {
    const a = prem[p * 4 + 3];
    if (a <= 0) continue;
    for (let n = 0; n < 3; n++) out[p * 4 + n] = Math.round(Math.min(255, prem[p * 4 + n] / a));
    out[p * 4 + 3] = Math.round(a * 255);
  }
  return out;
}

// Small-size hinting: tries sub-pixel positions of the mark (1/8 px steps within +-1/2 px) and keeps
// the one whose coverage is closest to fully on/off pixels (the crispest).
function hintedShift(makeScene, size) {
  if (size > 48) return [0, 0];
  let best = null;
  const unit = VIEW / size;
  for (let dy = -4; dy < 4; dy++) for (let dx = -4; dx < 4; dx++) {
    const shift = [(dx / 8) * unit, (dy / 8) * unit];
    const scene = makeScene(shift);
    let blur = 0;
    for (const l of scene.layers) {
      const polys = flatten(scaleContours(l.shape, size / scene.view), 0.02);
      const cov = l.grow ? grownCoverage(polys, size, size, 16, (l.grow * size) / scene.view) : coverage(polys, size, size, 16);
      for (const c of cov) blur += Math.min(c, 1 - c);
    }
    blur += Math.abs(dx) * 0.01 + Math.abs(dy) * 0.01; // prefer the centred position on ties
    if (!best || blur < best.blur) best = { blur, shift };
  }
  return best.shift;
}

/** The app icon at `size` px, hinted, as RGBA bytes. */
export function renderIcon(size, key = KEY) {
  const shift = hintedShift((s) => iconScene(size, key, s), size);
  return rasterize(iconScene(size, key, shift), size);
}

/** The bare mark in `color` on transparent, hinted like the icon (menu bar, sheets, docs). */
export function renderMark(size, { color = COLORS.limeMark, key = KEY, pad = 1 } = {}) {
  const make = (shift) => markScene({ size, color, key, pad, view: VIEW, shift });
  return rasterize(make(hintedShift(make, size)), size);
}

export function render(size) {
  return png(size, size, renderIcon(size));
}

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
export function png(w, h, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA; compression, filter, interlace = 0
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; y++) rgba.copy(raw, y * (w * 4 + 1) + 1, y * w * 4, (y + 1) * w * 4);
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0))]);
}

// ICO with PNG-encoded entries (supported since Windows Vista).
export function ico(images) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(images.length, 4);
  const dir = Buffer.alloc(16 * images.length);
  let offset = 6 + dir.length;
  images.forEach(([size, blob], i) => {
    const e = i * 16;
    dir[e] = size >= 256 ? 0 : size; dir[e + 1] = size >= 256 ? 0 : size;
    dir[e + 2] = 0; dir[e + 3] = 0;
    dir.writeUInt16LE(1, e + 4); dir.writeUInt16LE(32, e + 6);
    dir.writeUInt32LE(blob.length, e + 8); dir.writeUInt32LE(offset, e + 12);
    offset += blob.length;
  });
  return Buffer.concat([header, dir, ...images.map(([, blob]) => blob)]);
}

// ---- Android vector drawables -------------------------------------------------------------------

const GENERATED_XML = '<!-- Generated by Core/desktop-app/scripts/make-icons.mjs; edit the geometry there. -->';

// paths: [fill, pathData] or [fill, pathData, strokeWidth] (a round-joined outline in the fill colour).
function vectorXml({ dp, view, paths, tint }) {
  return [
    '<?xml version="1.0" encoding="utf-8"?>',
    GENERATED_XML,
    '<vector xmlns:android="http://schemas.android.com/apk/res/android"',
    `    android:width="${dp}dp"`,
    `    android:height="${dp}dp"`,
    ...(tint ? [`    android:tint="${tint}"`] : []),
    `    android:viewportWidth="${view}"`,
    `    android:viewportHeight="${view}">`,
    ...paths.map(([fill, d, stroke]) => [
      '    <path',
      `        android:fillColor="${fill}"`,
      ...(stroke ? [`        android:strokeColor="${fill}"`, `        android:strokeWidth="${f(stroke)}"`, '        android:strokeLineJoin="round"'] : []),
      `        android:pathData="${d}" />`,
    ].join('\n')),
    '</vector>',
    '',
  ].join('\n');
}

const argb = (c) => `#FF${c.slice(1).toUpperCase()}`;

// The adaptive icon's 108 dp canvas: the launcher shows the middle 72 dp through its mask and keeps
// the middle 66 dp circle whatever the mask's shape. The mark is sized so its farthest point,
// edge included, is FG_REACH dp from the centre.
const FG_REACH = 31;

/**
 * The foreground mark (108 dp canvas) and its border width in dp. With `edge` false: the bare mark at
 * the same reach (the themed icon, which has no border).
 */
function androidMark(edge = true) {
  const probe = keyMark({ ...KEY, box: 100, cx: 54, cy: 54 });
  let reach = 0;
  for (const pts of flatten(probe, 0.05)) for (const [x, y] of pts) reach = Math.max(reach, Math.hypot(x - 54, y - 54));
  // Scale so reach * k + border = FG_REACH, with the border in the icon's proportion (EDGE_RATIO).
  const ratio = edge ? EDGE_RATIO : 0;
  const k = FG_REACH / (reach / 100 + ratio) / 100;
  const box = 100 * k;
  return { mark: keyMark({ ...KEY, box, cx: 54, cy: 54 }), edge: box * ratio };
}

/** Adaptive icon foreground (108 dp): the icon (lime mark, dark green border) inside the 66 dp safe circle. */
export function androidForeground() {
  const { mark, edge } = androidMark();
  return vectorXml({ dp: 108, view: 108, paths: [
    [argb(COLORS.edge), pathData(mark), 2 * edge],
    [argb(COLORS.lime), pathData(mark)],
  ] });
}

/** Adaptive icon background (108 dp): transparent, so the launcher shows the mark on the wallpaper. */
export function androidBackground() {
  return vectorXml({ dp: 108, view: 108, paths: [['#00000000', 'M0,0h108v108h-108z']] });
}

/**
 * Android 13+ themed icon layer (108 dp): the bare mark in one colour (the launcher tints it), as far
 * out as the foreground's border, so both icons are the same size.
 */
export function androidMonochrome() {
  const { mark } = androidMark(false);
  return vectorXml({ dp: 108, view: 108, paths: [['#FFFFFFFF', pathData(mark)]] });
}

/** Notification / quick-settings small icon (24 dp): white silhouette on transparent. */
export function androidStatIcon() {
  const scene = markScene({ size: 24, view: 24, pad: 1, color: COLORS.mark });
  return vectorXml({ dp: 24, view: 24, tint: '#FFFFFFFF', paths: [['@android:color/white', pathData(scene.layers[0].shape)]] });
}

/** The in-app mark (24 dp, 2 dp margin): the lime mark with its dark green border, the same in both themes (PassLogo). */
export function androidMark24() {
  const box = (24 - 2 * 2) / (1 + 2 * EDGE_RATIO);
  const mark = keyMark({ ...KEY, box, cx: 12, cy: 12 });
  return vectorXml({ dp: 24, view: 24, paths: [
    [argb(COLORS.edge), pathData(mark), 2 * EDGE_RATIO * box],
    [argb(COLORS.lime), pathData(mark)],
  ] });
}

// ---- outputs ------------------------------------------------------------------------------------

const cache = new Map();
const get = (size) => { if (!cache.has(size)) cache.set(size, render(size)); return cache.get(size); };

function write(file, data) {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, data);
  console.log(path.relative(REPO, file).replaceAll('\\', '/'));
}

/** The in-page logo for the extension's content scripts (no innerHTML there, so path data, not markup). */
function extensionLogoModule() {
  return [
    '// Generated by Core/desktop-app/scripts/make-icons.mjs; edit the geometry there.',
    '// The Passyble mark: the wordmark\'s "y" (a key), as path data in the wordmark\'s viewBox (see',
    '// wordmarkNote() in shared/svg-icon.js). Pages draw it like the toolbar icons, in both themes: the',
    '// lime mark over its dark green border (a round-joined stroke `stroke` units wide in `edge`).',
    'export const LOGO = Object.freeze({',
    `  view: '${WORDMARK_VIEW}',`,
    `  mark: '${pathData(wordmarkY().shape)}',`,
    `  stroke: ${f(2 * wordmarkY().edge)},`,
    `  lime: '${COLORS.lime}',`,
    `  limeMark: '${COLORS.limeMark}',`,
    `  edge: '${COLORS.edge}',`,
    '});',
    '',
  ].join('\n');
}

export function writeExtensionIcons() {
  const dir = path.join(REPO, 'Extension', 'icons');
  write(path.join(dir, 'icon.svg'), svg());
  for (const size of [16, 32, 48, 128]) write(path.join(dir, `icon-${size}.png`), get(size));
  write(path.join(REPO, 'Extension', 'src', 'shared', 'logo.js'), extensionLogoModule());
}

export function writeDesktopIcons() {
  write(path.join(REPO, 'Core', 'desktop-app', 'ui', 'logo.svg'), svg());
  write(path.join(REPO, 'Core', 'desktop-app', 'src-tauri', 'src', 'passkey_provider', 'logo.svg'), svg({ comment: false }));
  const dir = path.join(REPO, 'Core', 'desktop-app', 'src-tauri', 'icons');
  for (const [name, size] of [['32x32.png', 32], ['128x128.png', 128], ['128x128@2x.png', 256], ['icon.png', 512]]) {
    write(path.join(dir, name), get(size));
  }
  write(path.join(dir, 'icon.ico'), ico([16, 20, 24, 32, 40, 48, 64, 256].map((s) => [s, get(s)])));
  writeLinuxIcons();
}

/** The hinted small sizes a Linux desktop's icon theme (hicolor) has besides 32, 128, 256 and 512:
 * Linux/installer/tauri.linux.conf.json lists them, so the .deb, .rpm and AppImage install them. */
export function writeLinuxIcons() {
  const dir = path.join(REPO, 'Core', 'desktop-app', 'src-tauri', 'icons');
  for (const size of [16, 24, 48, 64]) write(path.join(dir, `${size}x${size}.png`), get(size));
}

export function writeAndroidIcons() {
  const res = path.join(REPO, 'Android', 'app', 'src', 'main', 'res', 'drawable');
  write(path.join(res, 'ic_launcher_foreground.xml'), androidForeground());
  write(path.join(res, 'ic_launcher_background.xml'), androidBackground());
  write(path.join(res, 'ic_launcher_monochrome.xml'), androidMonochrome());
  write(path.join(res, 'ic_stat_pass.xml'), androidStatIcon());
  write(path.join(res, 'ic_pass_mark.xml'), androidMark24());
}

export function writeBrandFiles() {
  const dir = path.join(HERE, 'brand');
  write(path.join(dir, 'passyble-icon.svg'), svg());
  write(path.join(dir, 'passyble-wordmark-y.svg'), `${wordmarkSvg('xmlns="http://www.w3.org/2000/svg"')}\n`);
  write(path.join(dir, 'passyble-key-mono.svg'), sceneSvg(markScene({ pad: 0.5, color: COLORS.mark })));
  // Sensyble's own mark, unrotated and unmodified, as reference geometry (black, source units).
  const y = orient(yContours(), 2);
  write(path.join(dir, 'sensyble-mark.svg'), sceneSvg({ view: 1254, layers: [{ shape: y, paint: '#000000' }] }, 256));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  writeDesktopIcons();
  writeExtensionIcons();
  writeAndroidIcons();
  writeBrandFiles();
}
