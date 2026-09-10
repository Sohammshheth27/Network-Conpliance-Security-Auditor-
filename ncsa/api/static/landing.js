/* NCSA landing — behaviour for the Bifrost-derived design.
 *
 * Four things: the two line-art figures, the live figures, the platform wall,
 * and one-shot reveals. Everything is drawn as SVG geometry rather than shipped
 * as an asset, so the page has no image dependencies at all.
 */
(function () {
  'use strict';

  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const NS = 'http://www.w3.org/2000/svg';
  const el = (n, a) => { const e = document.createElementNS(NS, n);
    for (const k in a) e.setAttribute(k, a[k]); return e; };

  /* ── live figures ─────────────────────────────────────────────────────
   * Every number on this page is fetched from the running engine. A landing
   * page carrying its own copy of a figure drifts the moment the engine
   * changes, and then the product's front page is the thing stating a number
   * nobody measured. If the API is unreachable, the sections are removed
   * rather than shown with placeholders.
   */
  Promise.all([
    fetch('/frameworks').then(r => r.json()),
    fetch('/platforms').then(r => r.json())
  ]).then(([fw, plats]) => {
    const controls = Object.values(fw.catalogs).reduce((a, b) => a + b, 0);
    const maps = plats.reduce((a, p) => a + p.mappings, 0);

    // $KEY / value cells, in Bifrost's "numbers at a glance" form
    const glance = document.getElementById('glance');
    if (glance) {
      glance.innerHTML = [
        ['$FRAMEWORK_CONTROLS', controls],
        ['$FRAMEWORKS_MAPPED', Object.keys(fw.catalogs).length],
        ['$PLATFORM_PACKS', plats.length],
        ['$VENDOR_MAPPINGS', maps]
      ].map(([k, v]) =>
        `<div><div class="k">${k}</div><div class="v" data-to="${v}">0</div></div>`
      ).join('');
      countUp(glance);
      if (window.__ncsaGlanceBars) window.__ncsaGlanceBars();
    }
    if (window.__ncsaTicker) window.__ncsaTicker(plats, fw);

    // the platform wall
    const wall = document.getElementById('wall');
    if (wall) {
      // Two packs can share a platform key and differ only by reader; show the
      // reader on those so the wall does not look like it lists a duplicate.
      const dupes = new Set(plats.map(p => p.platform)
        .filter((v, i, a) => a.indexOf(v) !== i));
      wall.innerHTML = plats.map(p =>
        `<span>${p.platform}${dupes.has(p.platform)
          ? ` <em>${p.reader}</em>` : ''}</span>`).join('') +
        `<span><em>your vendor</em> &rarr; TRAINING QUEUE</span>`;
    }

    // framework cells, with the real per-catalogue counts
    const grid = document.getElementById('fwGrid');
    if (grid) {
      const notes = {
        nist_800_53: 'Control catalogue. The hub every other mapping resolves through.',
        disa_stig: 'Vendor-specific hardening. Reaches NIST via published CCI mappings.',
        cis: 'Cited by recommendation number and benchmark title only.',
        iso_27001_2022: 'Clause number and short title only, derived via the NIST crosswalk.',
        nist_800_171_r3: 'CUI requirements. Reached from NIST 800-53 through the crosswalk NIST ships inside its own catalogue.',
        pci_dss_4: 'Requirement numbers only. The text is copyrighted and is never stored.',
        cmmc: 'Level 2 is defined against 800-171 Rev 2; populated when that catalogue is supplied.',
        nerc_cip: 'Populated when a control list is supplied.'
      };
      const titles = {
        nist_800_53: 'NIST SP 800-53', disa_stig: 'DISA STIG',
        cis: 'CIS BENCHMARKS', iso_27001_2022: 'ISO/IEC 27001:2022',
        nist_800_171_r3: 'NIST SP 800-171', pci_dss_4: 'PCI DSS 4.0.1',
        cmmc: 'CMMC', nerc_cip: 'NERC CIP'
      };
      if (Object.keys(fw.catalogs).some(k => !titles[k])) {
        console.warn('NCSA landing: no display title for catalogue key(s)',
          Object.keys(fw.catalogs).filter(k => !titles[k]));
      }
      // A proportional bar per catalogue. The real spread is extreme -- CIS is
      // roughly thirty times ISO -- and showing that honestly is what makes the
      // figure look like data rather than like four identical cards.
      const max = Math.max(...loaded.map(([, n]) => n));
      // A framework showing zero on a marketing page reads as broken. The
      // engine still reports it, and /frameworks explains why it is empty --
      // but the page shows only what actually loaded.
      const loaded = Object.entries(fw.catalogs).filter(([, n]) => n > 0);
      grid.innerHTML = loaded.map(([k, n]) =>
        `<div class="fw-cell"><b>${titles[k] || k.toUpperCase()}</b>
           <div class="n" data-to="${n}">0</div>
           <div class="fw-bar"><i style="--w:${(n / max * 100).toFixed(1)}%"></i></div>
           <div class="d">${notes[k] || ''}</div></div>`).join('');
      countUp(grid);
      // grow the bars once the grid is in view
      if ('IntersectionObserver' in window) {
        const io2 = new IntersectionObserver(e => {
          if (!e[0].isIntersecting) return;
          grid.querySelectorAll('.fw-bar i').forEach(b => b.classList.add('on'));
          io2.disconnect();
        }, { threshold: .25 });
        io2.observe(grid);
      } else {
        grid.querySelectorAll('.fw-bar i').forEach(b => b.classList.add('on'));
      }
    }
    // The floating card over the product shot is derived from the SAME hero
    // figures, never written into the markup. Those figures are checked against
    // a real assessment by test_the_hero_terminal_shows_a_real_assessment, so
    // this card inherits that guarantee instead of needing its own exemption.
    (function floatCard() {
      const card = document.getElementById('floatCard');
      const note = document.querySelector('.hero-note');
      if (!card || !note) return;
      const m = note.textContent.match(/(\d+) controls.*?(\d+) decided/s);
      if (!m) return;
      const total = +m[1], decided = +m[2];
      document.getElementById('fcNum').innerHTML =
        (decided / total * 100).toFixed(1) + '<i>%</i>';
      document.getElementById('fcNote').textContent =
        `of ${total} controls could be assessed`;
      card.hidden = false;
    })();

    // The honesty ring is driven by the same figures the hero terminal states,
    // read out of the DOM rather than restated -- so the ring cannot disagree
    // with the number beside it, and the terminal's test covers both.
    if (window.__ncsaRing) {
      const term = document.querySelector('.term');
      const m = term && term.textContent.match(
        /(\d+) controls .*?(\d+) decided.*?([\d.]+)% of what/s);
      if (m) {
        const total = +m[1], decided = +m[2], score = parseFloat(m[3]);
        window.__ncsaRing(score, decided / total * 100,
                          (decided * score / 100) / total);
      }
    }
  }).catch(() => {
    ['glance', 'wall', 'fwGrid'].forEach(id => {
      const n = document.getElementById(id);
      if (n && n.closest('section')) n.closest('section').remove();
    });
  });

  function countUp(root) {
    const els = root.querySelectorAll('[data-to]');
    const run = () => els.forEach(e => {
      const target = +e.dataset.to;
      if (!isFinite(target) || reduced) {
        e.textContent = (+e.dataset.to).toLocaleString(); return;
      }
      const t0 = performance.now(), D = 900;
      const tick = t => {
        const k = Math.min(1, (t - t0) / D);
        e.textContent = Math.round(target * (1 - Math.pow(1 - k, 3))).toLocaleString();
        if (k < 1) requestAnimationFrame(tick);
        else e.textContent = target.toLocaleString();
      };
      requestAnimationFrame(tick);
    });
    if ('IntersectionObserver' in window) {
      const io = new IntersectionObserver(en => {
        if (en[0].isIntersecting) { run(); io.disconnect(); }
      }, { threshold: .25 });
      io.observe(root);
    } else run();
  }

  /* ── one-shot reveals ────────────────────────────────────────────────── */
  const targets = document.querySelectorAll(
    '.sec-head, .cells article, .steps li, .fig, .two > div, .end > *, ' +
    '.glance-row, .wall-grid, .fw-grid, .fine');
  // Preset stagger is .08s, and the preset warns not to stagger more than ~8
  // children -- past that the last item feels laggy. Capped at 6.
  targets.forEach((e, i) => {
    e.classList.add('rv');
    e.style.transitionDelay = (Math.min(i % 6, 5) * 80) + 'ms';
  });
  if ('IntersectionObserver' in window) {
    const io = new IntersectionObserver(entries => {
      entries.forEach(en => {
        if (!en.isIntersecting) return;
        en.target.classList.add('on');
        io.unobserve(en.target);           // fires once; never re-animates
      });
      // preset fires at "top 85%"
    }, { rootMargin: '0px 0px -15% 0px', threshold: .1 });
    targets.forEach(e => io.observe(e));
  } else {
    targets.forEach(e => e.classList.add('on'));
  }
})();
