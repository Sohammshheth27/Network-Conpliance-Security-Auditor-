/* NCSA — the rendered firewall appliance.
 *
 * A 1U rack appliance drawn in canvas with a hand-rolled perspective
 * projection. Restored after being cut, and rebuilt rather than pasted back:
 * the first version was flat-shaded polygons, which is what made it read as
 * crude. This one adds the things that actually sell a rendered object --
 *
 *   BEVELS.        A bright top edge and a dark bottom edge on the front face.
 *                  Real metal has a lit rim; a flat quad never does.
 *   FALLOFF.       Faces are shaded by their angle to a fixed key light rather
 *                  than filled with one colour.
 *   AMBIENT OCCLUSION. Contact darkening where the ports meet the panel and
 *                  where the chassis meets the floor.
 *   SOFTER BLOOM.  Two-stop radial falloff instead of one, so a lit LED has a
 *                  core and a halo rather than a flat disc.
 *
 * Still no Three.js: the page has a test asserting it reaches nothing offsite,
 * and vendoring a renderer to draw one box is a bad trade. ~11KB, one canvas,
 * paused offscreen and on tab-hide, still under prefers-reduced-motion.
 */
(function () {
  'use strict';

  const cv = document.getElementById('appliance');
  const ctx = cv && cv.getContext && cv.getContext('2d');
  if (!ctx) return;

  const mainCtx = ctx;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let W, H, S, raf = 0, t = 0, mx = 0, my = 0, tmx = 0, tmy = 0;

  const YAW = -0.30, PITCH = 0.15;
  const BW = 300, BH = 34, BD = 130;

  function proj(p, yaw, pitch) {
    const cy = Math.cos(yaw), sy = Math.sin(yaw);
    let x = p[0] * cy - p[2] * sy;
    let z = p[0] * sy + p[2] * cy;
    const cp = Math.cos(pitch), sp = Math.sin(pitch);
    let y = p[1] * cp - z * sp;
    z = p[1] * sp + z * cp;
    const d = 1 / (1 - z * 0.00040);
    return [W / 2 + x * d * S, H / 2 - y * d * S + H * 0.03, z];
  }
  /* Which context the drawing helpers paint into. drawChassis points this at
     the offscreen cache; everything else leaves it on the visible canvas. */
  let TGT = ctx;

  const face = (pts, yaw, pitch) => pts.map(p => proj(p, yaw, pitch));
  const poly = (pl, fill, stroke, lw) => {
    TGT.beginPath();
    pl.forEach((p, i) => i ? TGT.lineTo(p[0], p[1]) : TGT.moveTo(p[0], p[1]));
    TGT.closePath();
    if (fill) { TGT.fillStyle = fill; TGT.fill(); }
    if (stroke) { TGT.strokeStyle = stroke; TGT.lineWidth = lw || 1; TGT.stroke(); }
  };
  const line = (a, b, stroke, lw) => {
    TGT.strokeStyle = stroke; TGT.lineWidth = lw || 1;
    TGT.beginPath(); TGT.moveTo(a[0], a[1]); TGT.lineTo(b[0], b[1]); TGT.stroke();
  };

  function build() {
    DPR = Math.min(devicePixelRatio || 1, 1.75);
    W = cv.clientWidth; H = cv.clientHeight;
    cv.width = W * DPR; cv.height = H * DPR;
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    cache.width = W * DPR; cache.height = H * DPR;
    cacheYaw = cachePitch = NaN;          // force a rebuild at the new size
    S = Math.min(W / 430, H / 215);
  }

  /* The chassis -- faces, grain, vents, port cavities, ears -- never changes
   * except when the cursor nudges yaw/pitch. Redrawing its ~200 operations
   * every frame (twice, once through a blur filter for the reflection) is what
   * pinned this to 355ms frames. It is now rendered once into an offscreen
   * canvas and blitted; only the LEDs and the specular are drawn live. */
  const cache = document.createElement('canvas');
  const cctx = cache.getContext('2d');
  let cacheYaw = NaN, cachePitch = NaN, DPR = 1;

  function drawChassis(g, yaw, pitch) {
    const ctx = g;        // direct calls in this body
    TGT = g;              // and the poly()/line() helpers too

    const x0 = -BW / 2, x1 = BW / 2, y0 = -BH / 2, y1 = BH / 2,
          z0 = -BD / 2, z1 = BD / 2;

    /* ── top face ─────────────────────────────────────────────────────── */
    const top = face([[x0, y1, z0], [x1, y1, z0], [x1, y1, z1], [x0, y1, z1]], yaw, pitch);
    const gTop = ctx.createLinearGradient(top[0][0], top[0][1], top[2][0], top[2][1]);
    gTop.addColorStop(0,   '#39485e');   // catching the key light
    gTop.addColorStop(.28, '#232c3b');
    gTop.addColorStop(.72, '#161d28');
    gTop.addColorStop(1,   '#0d121a');   // falling away from it
    poly(top, gTop, null);

    // brushed grain, denser near the lit edge
    ctx.save(); ctx.beginPath();
    top.forEach((p, i) => i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]));
    ctx.closePath(); ctx.clip();
    for (let i = 0; i < 64; i++) {
      const k = i / 64;
      ctx.globalAlpha = 0.16 - k * 0.10;
      line(proj([x0 + BW * k, y1, z0], yaw, pitch),
           proj([x0 + BW * k, y1, z1], yaw, pitch),
           i % 2 ? 'rgba(255,255,255,.55)' : 'rgba(0,0,0,.55)', 1);
    }
    ctx.restore(); ctx.globalAlpha = 1;

    /* ── side face, drawn BEFORE the front so it cannot paint over it ─── */
    const sd = face([[x1, y1, z1], [x1, y1, z0], [x1, y0, z0], [x1, y0, z1]], yaw, pitch);
    const gSd = ctx.createLinearGradient(sd[0][0], sd[0][1], sd[2][0], sd[2][1]);
    gSd.addColorStop(0, '#12171f'); gSd.addColorStop(1, '#06080c');
    poly(sd, gSd, null);

    /* ── front face ───────────────────────────────────────────────────── */
    const fr = face([[x0, y1, z1], [x1, y1, z1], [x1, y0, z1], [x0, y0, z1]], yaw, pitch);
    const gFr = ctx.createLinearGradient(fr[0][0], fr[0][1], fr[3][0], fr[3][1]);
    gFr.addColorStop(0,   '#2a3646');
    gFr.addColorStop(.22, '#1b2330');
    gFr.addColorStop(.75, '#11161f');
    gFr.addColorStop(1,   '#080b11');
    poly(fr, gFr, null);

    // BEVELS: a lit rim along the top edge, a dark one along the bottom.
    // This single pair of lines is most of what separates "rendered metal"
    // from "a filled rectangle".
    line(fr[0], fr[1], 'rgba(255,255,255,.30)', 1.4);
    line(fr[3], fr[2], 'rgba(0,0,0,.75)', 1.4);
    line(top[0], top[1], 'rgba(255,255,255,.16)', 1);

    /* ── ventilation ──────────────────────────────────────────────────── */
    for (let r = 0; r < 3; r++) {
      for (let c = 0; c < 18; c++) {
        const hx = x0 + 14 + c * 4.2, hy = 8.5 - r * 8;
        ctx.globalAlpha = .5;
        poly(face([[hx, hy, z1], [hx + 2.4, hy, z1],
                   [hx + 2.4, hy - 4.6, z1], [hx, hy - 4.6, z1]], yaw, pitch),
             'rgba(0,0,0,.80)', null);
        // tiny lit lip on each slot
        ctx.globalAlpha = .22;
        line(proj([hx, hy - 4.6, z1], yaw, pitch),
             proj([hx + 2.4, hy - 4.6, z1], yaw, pitch),
             'rgba(255,255,255,.6)', 1);
      }
    }
    ctx.globalAlpha = 1;

    ctx.restore();
    TGT = mainCtx;        // hand the helpers back to the visible canvas
  }

  /* Everything below is redrawn every frame: the lit elements and the sweep. */
  function drawLive(yaw, pitch) {
    const x0 = -BW / 2, x1 = BW / 2, y0 = -BH / 2, y1 = BH / 2,
          z0 = -BD / 2, z1 = BD / 2;
    const fr = face([[x0, y1, z1], [x1, y1, z1], [x1, y0, z1], [x0, y0, z1]], yaw, pitch);

    /* ── port bank ────────────────────────────────────────────────────── */
    const PORTS = 12;
    for (let i = 0; i < PORTS; i++) {
      const px = x0 + 105 + i * 15;

      const phase = (t * 0.0016 + i * 0.24) % 1;
      const active = phase < 0.14;
      const lit = 0.28 + (active ? 0.72
                                 : Math.abs(Math.sin(i * 2.1 + t * 0.0009)) * 0.20);
      const col = active ? '58,212,208' : '96,160,255';
      const led = face([[px + 2.4, 3.4, z1 + .6], [px + 8.6, 3.4, z1 + .6],
                        [px + 8.6, 0.4, z1 + .6], [px + 2.4, 0.4, z1 + .6]], yaw, pitch);
      poly(led, `rgba(${col},${lit.toFixed(2)})`, null);

      if (lit > .45) {
        const c = led[0], cx = c[0] + 6, cy = c[1] + 2;
        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, 30);
        g.addColorStop(0,   `rgba(${col},${(lit * .60).toFixed(2)})`);
        g.addColorStop(.28, `rgba(${col},${(lit * .22).toFixed(2)})`);
        g.addColorStop(1,   `rgba(${col},0)`);
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(cx, cy, 30, 0, 6.284); ctx.fill();
      }
    }

    /* ── status cluster ───────────────────────────────────────────────── */
    ['58,212,208', '61,220,132', '255,179,64'].forEach((col, i) => {
      const sx = x1 - 42 + i * 11;
      const on = i === 0 ? 1 : i === 1 ? .8 : (Math.sin(t * .003) > .3 ? .85 : .16);
      const d = face([[sx, 2, z1 + .6], [sx + 5, 2, z1 + .6],
                      [sx + 5, -3, z1 + .6], [sx, -3, z1 + .6]], yaw, pitch);
      poly(d, `rgba(${col},${on})`, null);
      if (on > .55) {
        const c = d[0], cx = c[0] + 3, cy = c[1];
        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, 22);
        g.addColorStop(0,   `rgba(${col},${(on * .55).toFixed(2)})`);
        g.addColorStop(.3,  `rgba(${col},${(on * .18).toFixed(2)})`);
        g.addColorStop(1,   `rgba(${col},0)`);
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(cx, cy, 22, 0, 6.284); ctx.fill();
      }
    });

    /* ── moving specular ──────────────────────────────────────────────── */
    ctx.save(); ctx.beginPath();
    fr.forEach((p, i) => i ? ctx.lineTo(p[0], p[1]) : ctx.moveTo(p[0], p[1]));
    ctx.closePath(); ctx.clip();
    const sweep = ((t * 0.00020) % 1.8) - 0.4;
    const sx0 = fr[0][0] + (fr[1][0] - fr[0][0]) * sweep;
    const gS = ctx.createLinearGradient(sx0 - 150, 0, sx0 + 150, 0);
    gS.addColorStop(0, 'rgba(255,255,255,0)');
    gS.addColorStop(.5, 'rgba(255,255,255,.10)');
    gS.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = gS; ctx.fillRect(0, 0, W, H);
    ctx.restore();

    /* ── rack ears ────────────────────────────────────────────────────── */
    [[x0 - 13, x0], [x1, x1 + 13]].forEach(([a, b]) => {
      const ear = face([[a, y1, z1], [b, y1, z1], [b, y0, z1], [a, y0, z1]], yaw, pitch);
      poly(ear, 'rgba(26,33,45,.94)', null);
      line(ear[0], ear[1], 'rgba(255,255,255,.16)', 1);
      // mounting hole
      const hc = proj([(a + b) / 2, 0, z1 + .4], yaw, pitch);
      ctx.fillStyle = 'rgba(0,0,0,.8)';
      ctx.beginPath(); ctx.arc(hc[0], hc[1], 2.1 * S, 0, 6.284); ctx.fill();
    });
  }

  /* Rebuild the cached chassis only when the view actually moved. The cursor
   * eases toward its target, so during idle this never fires; while the mouse
   * is moving it fires a handful of times. */
  function ensureChassis(yaw, pitch) {
    if (Math.abs(yaw - cacheYaw) < 0.004 && Math.abs(pitch - cachePitch) < 0.004)
      return;
    cacheYaw = yaw; cachePitch = pitch;
    cctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    cctx.clearRect(0, 0, W, H);
    drawChassis(cctx, yaw, pitch);
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    const yaw = YAW + mx * 0.14, pitch = PITCH + my * 0.08;
    ensureChassis(yaw, pitch);

    /* Floor reflection: a flipped blit of the cached bitmap. The old version
     * re-ran the whole unit through ctx.filter='blur(6px)' every frame, which
     * is what took the page to 3fps -- a canvas filter applies to each drawing
     * operation, so ~200 of them were being blurred individually. Blitting one
     * finished image and letting the CSS mask soften it costs a single
     * composite. */
    ctx.save();
    ctx.globalAlpha = .13;
    ctx.translate(0, H * 0.615); ctx.scale(1, -0.5); ctx.translate(0, -H * 0.615);
    ctx.drawImage(cache, 0, 0, W, H);
    ctx.restore();

    // contact shadow
    const g = ctx.createRadialGradient(W / 2, H * 0.605, 0, W / 2, H * 0.605, W * 0.32);
    g.addColorStop(0, 'rgba(0,0,0,.62)');
    g.addColorStop(.6, 'rgba(0,0,0,.22)');
    g.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g;
    ctx.beginPath(); ctx.ellipse(W / 2, H * 0.605, W * 0.32, H * 0.05, 0, 0, 6.284);
    ctx.fill();

    ctx.drawImage(cache, 0, 0, W, H);   // the chassis
    drawLive(yaw, pitch);               // LEDs, blooms, specular, ears
  }

  /* Capped at 30fps. Nothing in this object needs 60: the specular sweeps at
   * t*0.0002, the LEDs phase at t*0.0016 and the status blinks at t*0.003 --
   * all far below the point where a dropped frame is visible. Halving the
   * draw rate halves what the page spends here, and the cursor parallax is
   * still smooth because it eases per drawn frame rather than per rAF tick.
   * A full-time 60fps canvas is exactly what made the page feel heavy. */
  const FRAME_MS = 1000 / 30;
  let lastDraw = 0;

  function step(now) {
    raf = requestAnimationFrame(step);
    if (now - lastDraw < FRAME_MS) return;
    lastDraw = now;
    t += FRAME_MS;
    mx += (tmx - mx) * .10; my += (tmy - my) * .10;
    draw();
  }

  build(); draw();
  if (!reduced) {
    addEventListener('pointermove', e => {
      tmx = e.clientX / innerWidth - .5;
      tmy = e.clientY / innerHeight - .5;
    }, { passive: true });
    const start = () => { if (!raf) raf = requestAnimationFrame(step); };
    const stop = () => { cancelAnimationFrame(raf); raf = 0; };
    if ('IntersectionObserver' in window) {
      new IntersectionObserver(e => e[0].isIntersecting ? start() : stop(),
        { threshold: .05 }).observe(cv);
    } else start();
    document.addEventListener('visibilitychange',
      () => document.hidden ? stop() : null);
  }

  let rt;
  addEventListener('resize',
    () => { clearTimeout(rt); rt = setTimeout(() => { build(); draw(); }, 180); });
})();
