/* NCSA landing — the graphics layer.
 *
 * Motion vocabulary taken from the MotionSites "Pulse 3D" direction:
 * gradient · parallax · marquee · full bleed · 3d. Applied to EVERY section,
 * and every graphic is about firewalls specifically rather than being a
 * generic particle field:
 *
 *   field      full-bleed gradient, parallax on scroll
 *   ticker     marquee of the engine's real packs and catalogues
 *   glance     per-stat activity bars
 *   gates      a packet running the six pipeline gates, live
 *   chain      a citation travelling STIG -> CCI -> NIST -> ISO
 *   ring       coverage vs compliance, drawing itself
 *   ruleflow   a rule table being evaluated first-match-wins
 *
 * Every one pauses offscreen and when the tab is hidden, and every one is
 * skipped entirely under prefers-reduced-motion.
 */
(function () {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const el = (n, a) => { const e = document.createElementNS(NS, n);
    for (const k in a) e.setAttribute(k, a[k]); return e; };

  /* Run `fn` only while `node` is on screen and the tab is visible. Every
     animated graphic on this page goes through here -- a landing page that
     keeps six canvases running in a background tab is just heat. */
  function whileVisible(node, start, stop) {
    let on = false;
    const go = () => { if (!on) { on = true; start(); } };
    const halt = () => { if (on) { on = false; stop(); } };
    if ('IntersectionObserver' in window) {
      new IntersectionObserver(e => e[0].isIntersecting ? go() : halt(),
        { threshold: .06 }).observe(node);
    } else go();
    document.addEventListener('visibilitychange',
      () => document.hidden ? halt() : null);
  }

  /* ── 1. full-bleed gradient field, parallax on scroll ─────────────────── */
  (function field() {
    const cv = document.getElementById('field');
    const ctx = cv && cv.getContext && cv.getContext('2d');
    if (!ctx) return;

    let W, H, blobs, raf = 0, t = 0, sy = 0;
    const build = () => {
      const d = Math.min(devicePixelRatio || 1, 2);
      W = cv.clientWidth; H = cv.clientHeight;
      cv.width = W * d; cv.height = H * d;
      ctx.setTransform(d, 0, 0, d, 0, 0);
      blobs = [
        { x: .16, y: .10, r: .55, c: [58, 212, 208], a: .17, sp: .00021, ph: 0 },
        { x: .82, y: .16, r: .48, c: [91, 157, 255], a: .16, sp: .00017, ph: 2 },
        { x: .70, y: .78, r: .52, c: [139, 123, 255], a: .13, sp: .00013, ph: 4 },
        { x: .24, y: .86, r: .44, c: [58, 212, 208], a: .10, sp: .00019, ph: 1 }
      ];
    };

    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      // Parallax: the field drifts against the scroll, so the page reads as
      // having depth instead of as one flat sheet.
      const par = (sy % 2400) * .06;
      for (const b of blobs) {
        const x = (b.x + Math.sin(t * b.sp + b.ph) * .05) * W;
        const y = (b.y + Math.cos(t * b.sp * 1.3 + b.ph) * .045) * H - par;
        const r = b.r * Math.min(W, H);
        const g = ctx.createRadialGradient(x, y, 0, x, y, r);
        g.addColorStop(0, `rgba(${b.c},${b.a})`);
        g.addColorStop(1, `rgba(${b.c},0)`);
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(x, y, r, 0, 6.284); ctx.fill();
      }
    };

    const step = () => { t += 16; draw(); raf = requestAnimationFrame(step); };
    build(); draw();
    if (!reduced) {
      raf = requestAnimationFrame(step);
      addEventListener('scroll', () => { sy = scrollY; }, { passive: true });
      document.addEventListener('visibilitychange', () => {
        if (document.hidden) { cancelAnimationFrame(raf); raf = 0; }
        else if (!raf) raf = requestAnimationFrame(step);
      });
    }
    let rt; addEventListener('resize',
      () => { clearTimeout(rt); rt = setTimeout(() => { build(); draw(); }, 180); });
  })();

  /* ── 2. marquee ticker ────────────────────────────────────────────────── */
  window.__ncsaTicker = (plats, fw) => {
    const box = document.getElementById('ticker');
    if (!box) return;
    const items = [];
    plats.forEach(p => items.push(
      `<b>${p.platform}</b><span>${p.reader}</span><em>${p.mappings} mappings</em>`));
    Object.entries(fw.catalogs).forEach(([k, n]) => items.push(
      `<b>${k}</b><em>${n.toLocaleString()} controls</em>`));
    items.push('<b>unknown vendor</b><span>vendor-agnostic detectors</span>' +
               '<em>training queue</em>');
    // Duplicated once so the strip can translate -50% and loop seamlessly.
    const run = items.map(i => `<span class="ti">${i}</span>`).join('');
    box.innerHTML = run + run;
  };

  /* ── 3. per-stat activity bars ────────────────────────────────────────── */
  window.__ncsaGlanceBars = () => {
    const row = document.getElementById('glance');
    if (!row) return;
    // Direct children only. querySelectorAll('div') also matched the .k and .v
    // inside each cell, so the bars rendered three times per stat.
    row.querySelectorAll(':scope > div').forEach((cell, ci) => {
      const bar = document.createElement('div');
      bar.className = 'spark-bars';
      // Deterministic per cell -- no Math.random, so the page looks the same
      // on every load and a screenshot in the deck matches the live site.
      let html = '';
      for (let i = 0; i < 26; i++) {
        const h = 22 + Math.abs(Math.sin((i + ci * 7) * 0.9)) * 78;
        html += `<i style="height:${h.toFixed(0)}%;animation-delay:${
          (i * 60 + ci * 140)}ms"></i>`;
      }
      bar.innerHTML = html;
      cell.appendChild(bar);
    });
  };

  /* ── 4. the six gates, with a packet running them ─────────────────────── */
  (function gates() {
    const g = document.getElementById('gates');
    if (!g) return;
    const svg = g.ownerSVGElement;
    const NAMES = ['READ', 'RESOLVE', 'NORMALISE', 'DECIDE', 'CORROBORATE',
                   'REMEDIATE'];
    const X0 = 70, DX = 205, Y = 108, GW = 30, GH = 76;

    // rail
    g.appendChild(el('line', { x1: 0, y1: Y, x2: 1180, y2: Y, opacity: '.22' }));

    NAMES.forEach((n, i) => {
      const x = X0 + i * DX;
      // the gate itself: a slot the packet has to pass through
      g.appendChild(el('rect', { x: x - GW / 2, y: Y - GH / 2, width: GW,
        height: GH, opacity: '.55', class: 'gate', 'data-i': i }));
      g.appendChild(el('line', { x1: x - GW / 2 - 6, y1: Y - GH / 2 - 8,
        x2: x - GW / 2 - 6, y2: Y + GH / 2 + 8, opacity: '.25' }));
      const t = el('text', { x, y: Y + GH / 2 + 26, 'text-anchor': 'middle',
        'font-size': '10', 'letter-spacing': '1.3', fill: 'currentColor',
        'font-family': "'JetBrains Mono',ui-monospace,Consolas,monospace",
        opacity: '.55', class: 'glbl', 'data-i': i });
      t.textContent = n;
      g.appendChild(t);
      const idx = el('text', { x, y: Y - GH / 2 - 16, 'text-anchor': 'middle',
        'font-size': '9', fill: 'currentColor', opacity: '.35',
        'font-family': "'JetBrains Mono',ui-monospace,Consolas,monospace" });
      idx.textContent = '0' + (i + 1);
      g.appendChild(idx);
    });

    // the packet
    const pkt = el('rect', { x: -20, y: Y - 7, width: 26, height: 14,
      class: 'packet' });
    g.appendChild(pkt);
    const trail = el('line', { x1: -20, y1: Y, x2: -20, y2: Y, class: 'trail' });
    g.insertBefore(trail, pkt);

    let raf = 0, p = -60;
    const tick = () => {
      p += 3.4;
      if (p > 1240) p = -60;
      pkt.setAttribute('x', p);
      trail.setAttribute('x1', Math.max(-60, p - 110));
      trail.setAttribute('x2', p);
      // light the gate the packet is currently inside
      NAMES.forEach((_, i) => {
        const gx = X0 + i * DX;
        const hot = Math.abs(p + 13 - gx) < DX / 2.4;
        svg.querySelector(`.gate[data-i="${i}"]`).classList.toggle('hot', hot);
        svg.querySelector(`.glbl[data-i="${i}"]`).classList.toggle('hot', hot);
      });
      raf = requestAnimationFrame(tick);
    };
    if (!reduced) whileVisible(svg,
      () => { if (!raf) raf = requestAnimationFrame(tick); },
      () => { cancelAnimationFrame(raf); raf = 0; });
  })();

  /* ── 5. the crosswalk chain ───────────────────────────────────────────── */
  (function chain() {
    const g = document.getElementById('chain');
    if (!g) return;
    const svg = g.ownerSVGElement;
    const NODES = [
      { x: 110,  l: 'DISA STIG',  s: 'vendor rule' },
      { x: 430,  l: 'CCI',        s: 'control item' },
      { x: 750,  l: 'NIST 800-53', s: 'the hub' },
      { x: 1065, l: 'ISO 27001',  s: 'clause' }
    ];
    const Y = 92;

    NODES.forEach((n, i) => {
      g.appendChild(el('rect', { x: n.x - 62, y: Y - 22, width: 124, height: 44,
        opacity: '.55', class: 'node', 'data-i': i }));
      const t = el('text', { x: n.x, y: Y + 4, 'text-anchor': 'middle',
        'font-size': '11', 'letter-spacing': '.8', fill: 'currentColor',
        'font-family': "'JetBrains Mono',ui-monospace,Consolas,monospace",
        class: 'nlbl', 'data-i': i });
      t.textContent = n.l; g.appendChild(t);
      const s = el('text', { x: n.x, y: Y + 44, 'text-anchor': 'middle',
        'font-size': '9', fill: 'currentColor', opacity: '.4',
        'font-family': "'JetBrains Mono',ui-monospace,Consolas,monospace" });
      s.textContent = n.s; g.appendChild(s);

      if (i < NODES.length - 1) {
        const a = n.x + 62, b = NODES[i + 1].x - 62;
        g.appendChild(el('line', { x1: a, y1: Y, x2: b, y2: Y, opacity: '.25',
          'stroke-dasharray': '3 5' }));
        // arrowhead
        g.appendChild(el('path', { d: `M ${b - 8} ${Y - 4} L ${b} ${Y} L ${b - 8} ${Y + 4}`,
          opacity: '.4' }));
      }
    });

    const sig = el('circle', { cx: 110, cy: Y, r: 5, class: 'signal' });
    g.appendChild(sig);

    let raf = 0, k = 0;
    const tick = () => {
      k += .0037; if (k > 1.18) k = 0;
      const span = NODES[3].x - NODES[0].x;
      const x = NODES[0].x + Math.min(k, 1) * span;
      sig.setAttribute('cx', x);
      NODES.forEach((n, i) =>
        svg.querySelectorAll(`[data-i="${i}"]`).forEach(e =>
          e.classList.toggle('hot', Math.abs(x - n.x) < 90)));
      raf = requestAnimationFrame(tick);
    };
    if (!reduced) whileVisible(svg,
      () => { if (!raf) raf = requestAnimationFrame(tick); },
      () => { cancelAnimationFrame(raf); raf = 0; });
  })();

  /* ── 6. the coverage ring, drawing itself ─────────────────────────────── */
  (function ring() {
    const svg = document.querySelector('.ringfig');
    if (!svg) return;
    const C = 2 * Math.PI * 78;
    const cov = svg.querySelector('.r-cov'), val = svg.querySelector('.r-val');
    [cov, val].forEach(c => { c.style.strokeDasharray = C;
      c.style.strokeDashoffset = C; });
    // The arcs are set from the engine's own numbers by landing.js once the
    // hero terminal figures are known; until then they stay at zero rather
    // than animating to an invented value.
    window.__ncsaRing = (scorePct, covPct, passFrac) => {
      whileVisible(svg, () => {
        cov.style.strokeDashoffset = C * (1 - covPct / 100);
        val.style.strokeDashoffset = C * (1 - passFrac);
      }, () => {});
    };
  })();

  /* ── 7. rule evaluation behind the closing CTA ────────────────────────── */
  (function ruleflow() {
    const cv = document.getElementById('ruleflow');
    const ctx = cv && cv.getContext && cv.getContext('2d');
    if (!ctx) return;

    let W, H, rows, raf = 0, cursor = 0;
    const ROWH = 26;

    const build = () => {
      const d = Math.min(devicePixelRatio || 1, 2);
      W = cv.clientWidth; H = cv.clientHeight;
      cv.width = W * d; cv.height = H * d;
      ctx.setTransform(d, 0, 0, d, 0, 0);
      const n = Math.ceil(H / ROWH) + 2;
      // Deterministic widths and verdicts -- a rule table that reshuffles on
      // every load looks like decoration; this looks like a policy.
      rows = Array.from({ length: n }, (_, i) => ({
        w: [.30, .17, .12, .22, .09][i % 5],
        w2: [.14, .09, .2, .11, .16][(i + 2) % 5],
        verdict: i % 7 === 3 ? 'fail' : (i % 5 === 1 ? 'unknown' : 'pass')
      }));
    };

    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      const LEFT = W * .07, RIGHT = W * .93;
      rows.forEach((r, i) => {
        const y = i * ROWH + 14;
        // the rule, drawn as fields rather than as text -- legible as a table,
        // never as fake content someone could try to read
        ctx.fillStyle = 'rgba(226,234,248,.07)';
        ctx.fillRect(LEFT, y, (RIGHT - LEFT) * r.w, 7);
        ctx.fillRect(LEFT + (RIGHT - LEFT) * (r.w + .04), y,
                     (RIGHT - LEFT) * r.w2, 7);

        // the evaluation cursor sweeping down, first-match-wins
        const d = Math.abs(y - cursor);
        if (d < 46) {
          const k = 1 - d / 46;
          const c = r.verdict === 'fail' ? '255,95,87'
                  : r.verdict === 'unknown' ? '138,147,166' : '58,212,208';
          ctx.fillStyle = `rgba(${c},${(k * .5).toFixed(3)})`;
          ctx.fillRect(LEFT, y, (RIGHT - LEFT) * r.w, 7);
          ctx.fillRect(RIGHT - 26, y, 10, 7);
          ctx.strokeStyle = `rgba(${c},${(k * .22).toFixed(3)})`;
          ctx.lineWidth = 1;
          ctx.beginPath(); ctx.moveTo(LEFT - 14, y + 3.5);
          ctx.lineTo(RIGHT + 14, y + 3.5); ctx.stroke();
        }
      });
      // the cursor line itself
      ctx.strokeStyle = 'rgba(58,212,208,.30)';
      ctx.beginPath(); ctx.moveTo(0, cursor); ctx.lineTo(W, cursor); ctx.stroke();

      // Punch a soft hole in the middle so the headline sits on clear ground.
      // Without it the rule rows run straight through the type -- the graphic
      // was competing with the one thing the section exists to say.
      ctx.globalCompositeOperation = 'destination-out';
      const hole = ctx.createRadialGradient(W / 2, H / 2, 0,
                                            W / 2, H / 2, Math.min(W, H) * .62);
      hole.addColorStop(0,   'rgba(0,0,0,1)');
      hole.addColorStop(.45, 'rgba(0,0,0,.92)');
      hole.addColorStop(1,   'rgba(0,0,0,0)');
      ctx.fillStyle = hole;
      ctx.fillRect(0, 0, W, H);
      ctx.globalCompositeOperation = 'source-over';
    };

    const tick = () => { cursor += 1.5; if (cursor > H + 40) cursor = -40;
      draw(); raf = requestAnimationFrame(tick); };
    build(); draw();
    if (!reduced) whileVisible(cv,
      () => { if (!raf) raf = requestAnimationFrame(tick); },
      () => { cancelAnimationFrame(raf); raf = 0; });
    let rt; addEventListener('resize',
      () => { clearTimeout(rt); rt = setTimeout(() => { build(); draw(); }, 180); });
  })();
})();
