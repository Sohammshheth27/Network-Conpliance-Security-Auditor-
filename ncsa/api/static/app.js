/* NCSA console.
 *
 * The UI enforces the same invariants the schema does, because a dashboard can
 * undo the product's credibility in ways the engine cannot:
 *
 *   1. A score is never shown without its coverage. "60% compliant" means
 *      nothing if 46% of the device was assessed.
 *   2. UNKNOWN is never green and never counted as a pass. It is the honest
 *      statement that we could not tell, and it is what makes the other
 *      numbers trustworthy.
 *   3. Every finding can be opened to its evidence: file, line, raw text.
 */
'use strict';

const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const state = { assessment: null, findings: [], filter: null };

/* ── shell ───────────────────────────────────────────────────────────── */
$$('.tab').forEach(t => t.onclick = () => show(t.dataset.view));

function show(view) {
  $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.view === view));
  $$('.view').forEach(v => v.classList.toggle('active', v.id === `view-${view}`));
  if (state.assessment) {
    if (view === 'hygiene')   loadHygiene();
    if (view === 'training')  loadTraining();
    if (view === 'remediate') loadRemediation();
  }
}

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}

(async function boot() {
  const el = $('#apiStatus');
  try {
    const h = await api('/health');
    el.innerHTML = `<span class="dot up"></span><span>engine ready · ${h.assessments} assessed</span>`;
    const plats = await api('/platforms');
    // Two packs can share a platform key and differ only by reader (SonicOS has
    // both an exported-settings and a CLI form). Showing the bare key twice
    // looks like a duplicate; the reader is what actually distinguishes them.
    const dupes = new Set(plats.map(p => p.platform)
      .filter((v, i, arr) => arr.indexOf(v) !== i));
    $('#platformList').innerHTML = plats
      .map(p => `<span class="chip">${esc(p.platform)}${
        dupes.has(p.platform) ? ` <em>${esc(p.reader)}</em>` : ''
      } · ${p.mappings} mappings</span>`)
      .join('');
    // Real figures from the running engine. A hero that states capability in
    // measured numbers is more persuasive than one that asserts it in adjectives.
    const fw = await api('/frameworks');
    const total = Object.values(fw.catalogs).reduce((a, b) => a + b, 0);
    const maps = plats.reduce((a, p) => a + p.mappings, 0);
    $('#heroStats').innerHTML = [
      [total.toLocaleString(), 'framework controls'],
      [plats.length, 'platform packs'],
      [maps, 'vendor mappings'],
      ['4', 'frameworks mapped']
    ].map(([n, l]) => `<div><b>${n}</b><span>${esc(l)}</span></div>`).join('');

    // Rehydrate. The server holds the session's assessments, so a page reload
    // should not present an empty Results tab while the status line says four
    // devices were assessed -- that reads as data loss and is exactly the kind
    // of "absence shown as a result" this project keeps having to design out.
    const prior = await api('/assessments');
    if (prior.length) {
      await openAssessment(prior[prior.length - 1].assessment_id, { stay: true });
    }
  } catch {
    el.innerHTML = '<span class="dot down"></span><span>engine unreachable</span>';
  }
})();

/* ── ingest ──────────────────────────────────────────────────────────── */
const dz = $('#dropzone'), fi = $('#fileInput');
dz.onclick = () => fi.click();
dz.ondragover = e => { e.preventDefault(); dz.classList.add('over'); };
dz.ondragleave = () => dz.classList.remove('over');
dz.ondrop = e => { e.preventDefault(); dz.classList.remove('over'); upload(e.dataTransfer.files); };
fi.onchange = () => upload(fi.files);

async function upload(files) {
  if (!files || !files.length) return;
  const log = $('#uploadLog');
  const fd = new FormData();
  [...files].forEach(f => fd.append('files', f));
  log.innerHTML = `<div class="log-row"><span>Assessing ${files.length} file(s)…</span></div>`;

  try {
    const redact = $('#redact').checked ? 'true' : 'false';
    const out = await api(`/assess?redact=${redact}`, { method: 'POST', body: fd });
    log.innerHTML = out.map(a => {
      const i = a.identity, c = a.coverage;
      if (!a.supported) {
        // A refusal is a RESULT, with a reason. Not an error to hide.
        return `<div class="log-row err"><span class="name">${esc(i.source_file)}</span>
          <span class="muted">${esc(a.notes[0] || 'not supported')}</span></div>`;
      }
      return `<div class="log-row">
        <span class="name">${esc(i.hostname || i.source_file)}</span>
        <span class="pill ${c.score_pct === null ? 'UNKNOWN' : 'SCORE'}">${
          c.score_pct === null ? 'nothing decided' : c.score_pct + '%'}</span>
        <span class="muted">${esc(i.vendor)} · assessed ${c.assessed_pct}% of controls</span>
        <button class="btn" data-open="${esc(a.assessment_id)}">Open</button></div>`;
    }).join('');

    $$('[data-open]', log).forEach(b => b.onclick = () => openAssessment(b.dataset.open));
    const first = out.find(a => a.supported);
    if (first) openAssessment(first.assessment_id);
  } catch (e) {
    log.innerHTML = `<div class="log-row err"><span>${esc(e.message)}</span></div>`;
  }
}

/* ── results ─────────────────────────────────────────────────────────── */
async function openAssessment(id, opts = {}) {
  state.assessment = await api(`/assessment/${id}`);
  state.findings = state.assessment.findings;
  // Open on what can be ACTED ON. The wall of UNKNOWN is honest and stays one
  // click away, but a reviewer opening a device wants the failures first --
  // 39 undecided rows above 12 failures buries the only actionable content.
  const hasFail = state.findings.some(f => f.state === 'FAIL');
  state.filter = hasFail ? 'FAIL' : null;
  renderResults();
  // On boot we hydrate but stay on Ingest: yanking someone to Results because
  // a previous session's device is still in memory is the tool deciding where
  // they should be looking.
  if (!opts.stay) show('results');
}

function renderResults() {
  const a = state.assessment, i = a.identity, c = a.coverage, r = a.records;
  $('#resultsEmpty').hidden = true;
  $('#resultsBody').hidden = false;

  const kv = (k, v, none) =>
    `<div><div class="k">${k}</div><div class="v${none ? ' none' : ''}">${esc(v)}</div></div>`;
  // A serial the config does not state stays "not stated" — never a placeholder.
  $('#deviceBar').innerHTML =
    kv('device', i.hostname || i.source_file) +
    kv('vendor', i.vendor) + kv('platform', i.platform) +
    kv('model', i.model || 'not stated', !i.model) +
    kv('serial', i.serial || 'not stated', !i.serial) +
    kv('os / version', [i.os, i.version].filter(Boolean).join(' ') || 'not stated',
       !(i.os || i.version));

  renderSummary(a, c);

  const risk = a.risk_worst || 'NONE';
  const riskCls = { CRITICAL: 'crit', HIGH: 'fail', MEDIUM: 'warn' }[risk] || '';
  // Score and coverage are NOT repeated here. They live in the summary figure
  // above, drawn as one nested object -- restating them as two independent
  // cards is what lets someone quote "45.5% compliant" with the coverage
  // cropped off. These cards carry what the figure cannot: counts and verdicts.
  $('#scoreCards').innerHTML = `
    <div class="card fail">
      <div class="label">Failures</div>
      <div class="num">${a.counts.FAIL || 0}</div>
      <div class="note">${a.counts.PARTIAL || 0} partial</div></div>
    <div class="card ${riskCls}">
      <div class="label">Risk</div><div class="num">${esc(risk)}</div>
      <div class="note">total ${a.risk_total}</div></div>
    <div class="card">
      <div class="label">Undecided</div>
      <div class="num">${c.controls_undecided}</div>
      <div class="note">${c.not_applicable} n/a · not the same as passing</div></div>
    <div class="card">
      <div class="label">Corroborated</div>
      <div class="num">${a.consensus ? a.consensus.confirmed + '/' + a.consensus.total : '—'}</div>
      <div class="note">${a.consensus && a.consensus.disputed ?
        a.consensus.disputed + ' disputed' : 'two independent methods'}</div></div>`;

  const rec = (k, v) => `<div class="rec"><div class="k">${k}</div><div class="v">${v.toLocaleString()}</div></div>`;
  $('#recordsGrid').innerHTML =
    rec('source records', r.source_records) + rec('parsed', r.parsed_records) +
    rec('unreadable', r.unreadable_records) + rec('mapped to schema', r.mapped_to_schema) +
    rec('parsed, not mapped', r.parsed_not_mapped) +
    rec('security-relevant unmapped', r.security_relevant_unmapped) +
    rec('objects', a.objects) + rec('relationships', a.relationships);

  const order = ['FAIL', 'PARTIAL', 'UNKNOWN', 'PASS', 'NOT_APPLICABLE'];
  const counts = {};
  state.findings.forEach(f => counts[f.state] = (counts[f.state] || 0) + 1);
  $('#stateFilters').innerHTML = order.filter(s => counts[s])
    .map(s => `<button data-st="${s}" class="${state.filter === s ? 'on' : ''}">${s} ${counts[s]}</button>`)
    .join('') + `<button data-st="" class="${state.filter ? '' : 'on'}">all ${
      state.findings.length}</button>`;
  $$('#stateFilters button').forEach(b => b.onclick = () => {
    state.filter = b.dataset.st || null; renderResults();
  });

  const rank = s => order.indexOf(s) < 0 ? 99 : order.indexOf(s);
  const rows = state.findings
    .filter(f => !state.filter || f.state === state.filter)
    .sort((a, b) => rank(a.state) - rank(b.state) ||
                    (b.risk?.score || 0) - (a.risk?.score || 0));

  $('#findingsTable tbody').innerHTML = rows.map((f, n) => {
    const ev = f.evidence[0];
    return `<tr class="clickable sev-${f.state}" data-f="${n}">
      <td class="cid">${esc(f.control_id)}</td>
      <td>${esc(f.title)}</td>
      <td><span class="pill ${f.state}">${f.state}</span></td>
      <td>${f.risk ? `<span class="pill ${f.risk.band}">${f.risk.band}</span>` : ''}</td>
      <td class="ev">${esc(JSON.stringify(f.observed ?? '—')).slice(0, 40)}</td>
      <td class="ev">${ev ? `<span class="ln">L${ev.line ?? '—'}</span> ${esc(ev.raw).slice(0, 46)}`
                          : '<span class="ln">no evidence — absence</span>'}</td></tr>`;
  }).join('');

  $$('#findingsTable tbody tr').forEach(tr =>
    tr.onclick = () => openDrawer(rows[+tr.dataset.f]));
}

/* ── the summary figure ──────────────────────────────────────────────── */
/* Score and coverage drawn as ONE object. They are meaningless apart: a ring
 * at 45% on a track that only covers 27% of the device says something a pair
 * of separate numbers does not, and it cannot be screenshotted misleadingly. */
function renderSummary(a, c) {
  const R = 78, C = 2 * Math.PI * R;
  const score = c.score_pct ?? 0;
  const cov = c.assessed_pct ?? 0;
  const decided = c.controls_decided, total = c.controls_total;
  /* The blue arc is NESTED inside the grey one, not drawn over the same scale.
   * score_pct is a percentage of the DECIDED subset; plotting it against the
   * full circle would draw 45% compliance as a longer arc than 27% coverage --
   * a picture saying we passed more than we assessed. The blue arc is
   * passed/total, so grey is always at least as long as blue, and the white
   * remainder is honestly the part of the device we could not read. */
  const passFrac = total ? (a.counts.PASS || 0) / total : 0;

  const seg = (n, cls) => n ? `<div class="seg ${cls}" style="flex:${n}">
      <b>${n}</b></div>` : '';

  $('#summary').innerHTML = `
    <div class="ring-wrap">
      <svg class="ring" viewBox="0 0 200 200" role="img"
           aria-label="compliance ${score}% over ${cov}% coverage">
        <defs>
          <linearGradient id="g1" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stop-color="#4da3ff"/><stop offset="100%" stop-color="#7c5cff"/>
          </linearGradient>
        </defs>
        <circle class="ring-bg" cx="100" cy="100" r="${R}"/>
        <circle class="ring-cov" cx="100" cy="100" r="${R}"
                stroke-dasharray="${C}" stroke-dashoffset="${C * (1 - cov / 100)}"/>
        <circle class="ring-val" cx="100" cy="100" r="${R}"
                stroke-dasharray="${C}" stroke-dashoffset="${C * (1 - passFrac)}"/>
      </svg>
      <div class="ring-mid">
        <div class="ring-num">${c.score_pct === null ? '—' : score + '<i>%</i>'}</div>
        <div class="ring-lab">of ${decided} decided</div>
      </div>
    </div>
    <div class="summary-side">
      <h2>${esc(a.identity.hostname || a.identity.source_file)}</h2>
      <p class="muted">
        <b>${score}%</b> of the <b>${decided}</b> controls we could decide —
        which is <b>${cov}%</b> of ${total}. The remaining
        <b>${c.controls_undecided}</b> are undecided, not passing.</p>
      <div class="segbar">
        ${seg(a.counts.PASS, 'PASS')}${seg(a.counts.FAIL, 'FAIL')}
        ${seg(a.counts.PARTIAL, 'PARTIAL')}${seg(a.counts.UNKNOWN, 'UNKNOWN')}
        ${seg(a.counts.NOT_APPLICABLE, 'NOT_APPLICABLE')}
      </div>
      <div class="ringkey">
        <span><i class="k val"></i>${a.counts.PASS} passing</span>
        <span><i class="k cov"></i>${decided} assessed</span>
        <span><i class="k bg"></i>${c.controls_undecided} undecided</span>
      </div>
      <div class="seglegend">
        <span><i class="k PASS"></i>pass</span><span><i class="k FAIL"></i>fail</span>
        <span><i class="k PARTIAL"></i>partial</span><span><i class="k UNKNOWN"></i>undecided</span>
        <span><i class="k NOT_APPLICABLE"></i>n/a</span>
      </div>
    </div>`;
}

/* ── evidence drawer ─────────────────────────────────────────────────── */
function openDrawer(f) {
  $('#drawerTitle').textContent = f.control_id;
  const fw = f.frameworks || {};
  const chips = [
    ...(fw.nist_800_53 || []).map(x => `NIST ${x}`),
    ...(fw.stig_ids || []).map(x => `STIG ${x}`),
    ...(fw.cis_ids || []).map(x => `CIS ${x}`),
    ...(fw.iso_27001 || []).map(x => `ISO ${x}`)
  ].map(x => `<span class="chip">${esc(x)}</span>`).join('') ||
    '<span class="muted small">no framework label mapped</span>';

  const kv = (k, v) => `<div class="kv"><div class="k">${k}</div><div class="v">${v}</div></div>`;
  $('#drawerBody').innerHTML =
    kv('title', esc(f.title)) +
    kv('state', `<span class="pill ${f.state}">${f.state}</span>` +
       (f.risk ? ` <span class="pill ${f.risk.band}">${f.risk.band} · ${f.risk.score}</span>` : '')) +
    kv('field', `<span class="cid">${esc(f.field)}</span>`) +
    kv('observed', `<span class="ev">${esc(JSON.stringify(f.observed))}</span>`) +
    kv('expected', `<span class="ev">${esc(JSON.stringify(f.expected))}</span>`) +
    (f.reason ? kv('reason', esc(f.reason)) : '') +
    kv('evidence', f.evidence.length
        ? f.evidence.map(e => `<div class="evbox">${e.line ? `line ${e.line} · ` : ''}${
            esc(e.file)}<br>${esc(e.raw)}${
            e.record_id ? `<br><span class="ln">${esc(e.record_id)}</span>` : ''}</div>`).join('')
        : '<span class="muted small">No evidence — this finding is a provable ' +
          'absence, not a value we read.</span>') +
    (f.risk ? kv('how the risk was scored',
        `<ul class="small">${f.risk.rationale.map(x => `<li>${esc(x)}</li>`).join('')}</ul>`) : '') +
    kv('framework citations', `<div class="fw">${chips}</div>`);

  $('#drawer').classList.add('on'); $('#scrim').classList.add('on');
}
$('#drawerClose').onclick = $('#scrim').onclick = () => {
  $('#drawer').classList.remove('on'); $('#scrim').classList.remove('on');
};

/* ── hygiene ─────────────────────────────────────────────────────────── */
async function loadHygiene() {
  const id = state.assessment.assessment_id;
  try {
    const h = await api(`/assessment/${id}/hygiene`);
    $('#hygieneEmpty').hidden = true; $('#hygieneBody').hidden = false;
    const s = h.summary;
    $('#hygieneCards').innerHTML = Object.entries(s.by_kind || {})
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => `<div class="card"><div class="label">${esc(k.replace(/_/g, ' '))}</div>
        <div class="num">${v}</div></div>`).join('') +
      `<div class="card"><div class="label">unevaluable</div><div class="num">${s.unevaluable}</div>
       <div class="note">reported, not assumed clean</div></div>`;
    $('#hygieneTable tbody').innerHTML = h.findings.slice(0, 300).map(f =>
      `<tr><td><span class="pill ${(f.severity || '').toUpperCase()}">${esc(f.kind.replace(/_/g, ' '))}</span></td>
        <td>${esc(f.severity)}</td><td class="ev">${esc(f.rule)}</td>
        <td class="small">${esc(f.detail).slice(0, 190)}</td></tr>`).join('');
  } catch (e) {
    $('#hygieneEmpty').hidden = false;
    $('#hygieneEmpty').innerHTML = `<p>${esc(e.message)}</p>`;
  }
}

/* ── training ────────────────────────────────────────────────────────── */
async function loadTraining() {
  const id = state.assessment.assessment_id;
  $('#trainEmpty').hidden = true; $('#trainBody').hidden = false;
  $('#trainTable tbody').innerHTML =
    '<tr><td colspan="6" class="muted">building queue…</td></tr>';
  const q = await api(`/assessment/${id}/training?limit=60&suggest=true`);
  render(q);

  function render(rows) {
    $('#trainTable tbody').innerHTML = rows.map((c, n) => `
      <tr><td class="ev">${esc(c.name)}</td>
        <td>${c.occurrences}</td>
        <td class="ev">${esc(JSON.stringify(c.sample_values[0] ?? '')).slice(0, 22)}</td>
        <td class="cid">${esc(c.suggested_field || '—')}</td>
        <td>${c.suggested_field ? (c.suggestion_score).toFixed(2) : ''}</td>
        <td>${c.suggested_field
              ? `<button class="btn" data-i="${n}">Approve</button>`
              : '<span class="muted small">no proposal</span>'}</td></tr>`).join('');

    $$('#trainTable [data-i]').forEach(b => b.onclick = async () => {
      const c = rows[+b.dataset.i];
      const who = $('#approver').value.trim();
      if (!who) { alert('An approval must record who made it.'); return; }
      b.disabled = true; b.textContent = 'checking…';
      try {
        const res = await api('/training/approve', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ setting_name: c.name, field: c.suggested_field,
                                 platform: state.assessment.identity.platform,
                                 approved_by: who })
        });
        // A refusal carries the verified expectation that broke. Show it.
        b.outerHTML = res.accepted
          ? '<span class="pill PASS">approved</span>'
          : `<span class="pill FAIL" title="${esc(res.reason)}">refused</span>`;
        if (!res.accepted) console.warn('approval refused:', res);
      } catch (e) { b.disabled = false; b.textContent = 'Approve'; alert(e.message); }
    });
  }
}

/* ── remediation ─────────────────────────────────────────────────────── */
async function loadRemediation() {
  const id = state.assessment.assessment_id;
  $('#remEmpty').hidden = true; $('#remBody').hidden = false;
  const p = await api(`/assessment/${id}/remediation`);
  $('#remScript').textContent = p.script || '(no remediation available)';
  // Steps that would sever the only management path are shown SEPARATELY --
  // they are never part of the runnable script.
  $('#remDeferred').innerHTML = p.deferred.length ? `<div class="warnbox">
      <h4>Held back — would cut your management path</h4>
      ${p.deferred.map(s => `<div><strong>${esc(s.control_id)}</strong> ${esc(s.title)}<br>
        <span class="muted small">${esc(s.lockout_warning)}</span></div>`).join('')}
    </div>` : '';
  $('#remUnavailable').textContent = p.unavailable.length
    ? `${p.unavailable.length} failing control(s) have no remediation written yet: `
      + p.unavailable.slice(0, 12).join(', ')
    : '';
}
