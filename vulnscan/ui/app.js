/* vulnscan UI — vanilla JS, no build step. */
'use strict';
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const I18N = {
  ar: {
    sev: {critical: 'حرج', high: 'عالٍ', medium: 'متوسط', low: 'منخفض', info: 'معلوماتي'},
    'nav.dashboard': 'لوحة التحكم', 'nav.scan': 'فحص جديد', 'nav.findings': 'النتائج', 'nav.reports': 'التقارير', 'nav.rules': 'القواعد', 'nav.settings': 'الإعدادات',
    'dash.title': 'لوحة التحكم', 'dash.sub': 'نظرة عامة على آخر فحص والاتجاه العام.', 'dash.empty': 'لا توجد فحوصات بعد', 'dash.emptyHint': 'ابدأ بفحص مجلد مشروع أو ارفع ملفًا مضغوطًا.',
    'dash.donut': 'توزيع الخطورة (آخر فحص)', 'dash.trend': 'اتجاه النتائج عبر الفحوصات الأخيرة', 'dash.topRules': 'أكثر الثغرات تكرارًا', 'dash.topFiles': 'أكثر الملفات تأثرًا', 'dash.recent': 'الفحوصات الأخيرة',
    'scan.title': 'فحص جديد', 'scan.sub': 'افحص مجلدًا على هذا الجهاز، أو ارفع برنامجًا مضغوطًا أو ملفات، أو افحص عنوان ويب تملكه.',
    'scan.tabPath': 'مسار على الجهاز', 'scan.tabUpload': 'رفع ملفات / أرشيف', 'scan.tabUrl': 'عنوان ويب', 'scan.pathLabel': 'مسار المجلد أو الملف أو الأرشيف', 'scan.start': 'ابدأ الفحص',
    'scan.pathHint': 'يُفحص المجلد بكل محتوياته (تُتجاهل node_modules و .git و build تلقائيًا).', 'scan.drop': 'اسحب وأفلت هنا برنامجًا مضغوطًا (zip / apk / jar / tar.gz / whl) أو أي ملفات',
    'scan.chooseFiles': 'اختر ملفات', 'scan.chooseFolder': 'اختر مجلدًا كاملًا', 'scan.uploadStart': 'ارفع وافحص', 'scan.urlLabel': 'عنوان الموقع (فحص سلبي: طلب واحد فقط)',
    'scan.authorize': 'أقرّ بأنني مالك هذا الموقع أو لديّ تصريح كتابي بفحصه', 'scan.legal': 'فحص أنظمة الآخرين دون إذن قد يكون مخالفًا للقانون.', 'scan.viewResults': 'عرض النتائج',
    'scan.running': 'جارٍ الفحص…', 'scan.done': 'اكتمل الفحص', 'scan.failed': 'فشل الفحص', 'scan.needAuth': 'يجب تأكيد الصلاحية أولًا', 'scan.selected': 'ملف محدد', 'scan.uploading': 'جارٍ الرفع…',
    'find.title': 'النتائج', 'find.sub': 'مرتبة من الأعلى خطورة إلى الأقل. اضغط على أي نتيجة لعرض التفاصيل وطريقة الإصلاح.', 'find.search': 'ابحث في الملف أو القاعدة أو النص…', 'find.allSources': 'كل المصادر',
    'find.none': 'لا نتائج مطابقة.', 'find.files': 'ملفًا مفحوصًا', 'find.advice': 'طريقة الإصلاح', 'find.snippet': 'المقتطف', 'find.ref': 'المرجع',
    'rep.title': 'التقارير', 'rep.sub': 'سجل كل الفحوصات، تنزيل التقارير، ومقارنة فحصين لمعرفة ما أُصلح وما استجد.', 'rep.compare': 'مقارنة فحصين', 'rep.compareBtn': 'قارن', 'rep.fixed': '✅ أُصلحت (اختفت)', 'rep.new': '🆕 جديدة (ظهرت)',
    'rep.target': 'الهدف', 'rep.date': 'التاريخ', 'rep.status': 'الحالة', 'rep.total': 'الإجمالي', 'rep.actions': 'إجراءات', 'rep.delete': 'حذف', 'rep.view': 'عرض', 'rep.nothing': 'لا شيء',
    'rules.title': 'القواعد المدمجة', 'rules.search': 'ابحث في القواعد…', 'rules.count': 'قاعدة', 'rules.id': 'المعرّف', 'rules.sev': 'الخطورة', 'rules.name': 'الثغرة', 'rules.langs': 'الملفات', 'rules.advice': 'الإصلاح',
    'set.title': 'الإعدادات', 'set.sub': 'تُحفظ على هذا الجهاز وتُطبَّق على كل الفحوصات القادمة.', 'set.minSev': 'أدنى خطورة تُعرض', 'set.failOn': 'إفشال CI عند خطورة', 'set.exclude': 'مسارات مستثناة (سطر لكل نمط)',
    'set.ignore': 'قواعد متجاهَلة (معرّف لكل سطر)', 'set.authTargets': 'عناوين ويب مُصرَّح بفحصها (سطر لكل عنوان)', 'set.osv': 'الاستعلام من OSV.dev عن ثغرات الاعتماديات (يحتاج إنترنت)',
    'set.external': 'دمج نتائج الأدوات الخارجية المثبّتة', 'set.keep': 'عدد الفحوصات المحفوظة', 'set.save': 'حفظ', 'set.saved': 'تم الحفظ ✓', 'set.home': 'مجلد البيانات', 'set.none': 'لا توجد أدوات مثبّتة',
    status: {running: 'جارٍ', done: 'مكتمل', error: 'خطأ'},
  },
  en: {
    sev: {critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info'},
    'nav.dashboard': 'Dashboard', 'nav.scan': 'New scan', 'nav.findings': 'Findings', 'nav.reports': 'Reports', 'nav.rules': 'Rules', 'nav.settings': 'Settings',
    'dash.title': 'Dashboard', 'dash.sub': 'Overview of the latest scan and the trend.', 'dash.empty': 'No scans yet', 'dash.emptyHint': 'Scan a project folder or upload an archive.',
    'dash.donut': 'Severity distribution (latest scan)', 'dash.trend': 'Findings trend across recent scans', 'dash.topRules': 'Most frequent issues', 'dash.topFiles': 'Most affected files', 'dash.recent': 'Recent scans',
    'scan.title': 'New scan', 'scan.sub': 'Scan a folder on this machine, upload an archive or files, or passively check a website you own.',
    'scan.tabPath': 'Local path', 'scan.tabUpload': 'Upload files / archive', 'scan.tabUrl': 'Web URL', 'scan.pathLabel': 'Folder, file or archive path', 'scan.start': 'Start scan',
    'scan.pathHint': 'The whole folder is scanned (node_modules, .git and build are skipped).', 'scan.drop': 'Drop an archive (zip / apk / jar / tar.gz / whl) or any files here',
    'scan.chooseFiles': 'Choose files', 'scan.chooseFolder': 'Choose a folder', 'scan.uploadStart': 'Upload & scan', 'scan.urlLabel': 'Site URL (passive: one request only)',
    'scan.authorize': 'I own this site or have written permission to test it', 'scan.legal': 'Testing systems without permission may be illegal.', 'scan.viewResults': 'View findings',
    'scan.running': 'Scanning…', 'scan.done': 'Scan complete', 'scan.failed': 'Scan failed', 'scan.needAuth': 'Please confirm authorization first', 'scan.selected': 'file(s) selected', 'scan.uploading': 'Uploading…',
    'find.title': 'Findings', 'find.sub': 'Ordered from highest to lowest severity. Click a finding for details and remediation.', 'find.search': 'Search file, rule or text…', 'find.allSources': 'All sources',
    'find.none': 'No matching findings.', 'find.files': 'files scanned', 'find.advice': 'Remediation', 'find.snippet': 'Snippet', 'find.ref': 'Reference',
    'rep.title': 'Reports', 'rep.sub': 'Scan history, report downloads, and a diff between two scans.', 'rep.compare': 'Compare two scans', 'rep.compareBtn': 'Compare', 'rep.fixed': '✅ Fixed (gone)', 'rep.new': '🆕 New (appeared)',
    'rep.target': 'Target', 'rep.date': 'Date', 'rep.status': 'Status', 'rep.total': 'Total', 'rep.actions': 'Actions', 'rep.delete': 'Delete', 'rep.view': 'View', 'rep.nothing': 'Nothing',
    'rules.title': 'Built-in rules', 'rules.search': 'Search rules…', 'rules.count': 'rules', 'rules.id': 'ID', 'rules.sev': 'Severity', 'rules.name': 'Issue', 'rules.langs': 'Files', 'rules.advice': 'Remediation',
    'set.title': 'Settings', 'set.sub': 'Saved on this machine and applied to every new scan.', 'set.minSev': 'Minimum severity shown', 'set.failOn': 'Fail CI at severity', 'set.exclude': 'Excluded paths (one glob per line)',
    'set.ignore': 'Ignored rules (one ID per line)', 'set.authTargets': 'Authorized web targets (one per line)', 'set.osv': 'Query OSV.dev for vulnerable dependencies (needs internet)',
    'set.external': 'Merge installed external scanners', 'set.keep': 'Scans to keep', 'set.save': 'Save', 'set.saved': 'Saved ✓', 'set.home': 'Data folder', 'set.none': 'none installed',
    status: {running: 'Running', done: 'Done', error: 'Error'},
  },
};
let lang = localStorage.getItem('vs.lang') || 'ar';
const t = (k) => I18N[lang][k] ?? I18N.ar[k] ?? k;
const sevName = (s) => I18N[lang].sev[s];
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const fmtDate = (ts) => ts ? new Date(ts * 1000).toLocaleString(lang === 'ar' ? 'ar-EG' : 'en-GB') : '—';
const api = async (path, opts = {}) => {
  const r = await fetch(path, {headers: {'Content-Type': 'application/json'}, ...opts});
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
};
const setHTML = (el, html) => { el.innerHTML = html; }; // nosec — every value is escaped with esc() before reaching here
const toast = (msg) => { const el = $('#toast'); el.textContent = msg; el.classList.remove('hidden'); clearTimeout(el._t); el._t = setTimeout(() => el.classList.add('hidden'), 2800); };
const total = (s) => SEV.reduce((a, k) => a + (s[k] || 0), 0);
const badge = (s) => `<span class="badge ${s}">${esc(sevName(s))}</span>`;
const tiles = (summary, cls = '') => SEV.map((s) => `<div class="tile bg-${s}" data-sev="${s}"><div class="n">${summary[s] || 0}</div><div class="l">${esc(sevName(s))} <small>${s}</small></div></div>`).join('');

/* ---------------------------------------------------------------- i18n/theme */
function applyLang() {
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
  $$('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
  $$('[data-i18n-ph]').forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
  $('#lang-btn').textContent = lang === 'ar' ? 'EN' : 'ع';
  $('#source-filter').options[0].textContent = t('find.allSources');
}
$('#lang-btn').onclick = () => { lang = lang === 'ar' ? 'en' : 'ar'; localStorage.setItem('vs.lang', lang); applyLang(); route(); };
$('#theme-btn').onclick = () => {
  const cur = document.documentElement.dataset.theme || 'auto';
  const next = cur === 'dark' ? 'light' : cur === 'light' ? 'auto' : 'dark';
  if (next === 'auto') delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = next;
  localStorage.setItem('vs.theme', next);
};
{ const th = localStorage.getItem('vs.theme'); if (th && th !== 'auto') document.documentElement.dataset.theme = th; }

/* ------------------------------------------------------------------ routing */
const pages = {dashboard: loadDashboard, scan: () => {}, findings: loadFindings, reports: loadReports, rules: loadRules, settings: loadSettings};
function route() {
  const [name, arg] = (location.hash.slice(1) || 'dashboard').split('/');
  const page = pages[name] ? name : 'dashboard';
  $$('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + page));
  $$('nav a').forEach((a) => a.classList.toggle('active', a.dataset.nav === page));
  pages[page](arg);
}
window.addEventListener('hashchange', route);

/* ---------------------------------------------------------------- dashboard */
async function loadDashboard() {
  const st = await api('/api/stats');
  const empty = !st.latest;
  $('#dash-empty').classList.toggle('hidden', !empty);
  $('#dash-body').classList.toggle('hidden', empty);
  if (empty) return;
  const sum = st.latest.summary;
  setHTML($('#tiles'), tiles(sum));
  $$('#tiles .tile').forEach((el) => el.onclick = () => { location.hash = `findings/${st.latest.id}?sev=${el.dataset.sev}`; });
  drawDonut($('#donut'), $('#donut-legend'), sum);
  drawTrend($('#trend'), st.trend);
  setHTML($('#top-rules'), st.top_rules.map((r) => `<li><span>${badge(r.severity)} <code>${esc(r.rule_id)}</code> ${esc(lang === 'ar' ? r.title_ar : r.title)}</span><span class="cnt">${r.count}</span></li>`).join('') || `<li class="muted">${t('rep.nothing')}</li>`);
  setHTML($('#top-files'), st.top_files.map(([f, n]) => `<li><span class="mono" dir="ltr">${esc(f)}</span><span class="cnt">${n}</span></li>`).join('') || `<li class="muted">${t('rep.nothing')}</li>`);
  const scans = await api('/api/scans');
  setHTML($('#recent-table'), scanRows(scans.slice(0, 6)));
}
function drawDonut(svg, legend, sum) {
  const tot = total(sum) || 1; let a = 0; const r = 44, c = 60; const parts = [];
  const colors = {critical: '#991b1b', high: '#ea580c', medium: '#d97706', low: '#0891b2', info: '#71717a'};
  SEV.forEach((s) => {
    const v = sum[s] || 0; if (!v) return;
    const a2 = a + (v / tot) * Math.PI * 2;
    const x1 = c + r * Math.cos(a), y1 = c + r * Math.sin(a), x2 = c + r * Math.cos(a2), y2 = c + r * Math.sin(a2);
    parts.push(`<path d="M${x1} ${y1} A${r} ${r} 0 ${a2 - a > Math.PI ? 1 : 0} 1 ${x2} ${y2}" fill="none" stroke="${colors[s]}" stroke-width="16"><title>${sevName(s)}: ${v}</title></path>`);
    a = a2;
  });
  if (!parts.length) parts.push(`<circle cx="60" cy="60" r="44" fill="none" stroke="var(--border)" stroke-width="16"/>`);
  setHTML(svg, `<g transform="rotate(-90 60 60)">${parts.join('')}</g><text x="60" y="58" text-anchor="middle" font-size="22" font-weight="700" fill="currentColor">${total(sum)}</text><text x="60" y="76" text-anchor="middle" font-size="9" fill="var(--muted)">${lang === 'ar' ? 'نتيجة' : 'findings'}</text>`);
  setHTML(legend, SEV.map((s) => `<div><span class="dot" style="background:${colors[s]}"></span>${esc(sevName(s))}: <b>${sum[s] || 0}</b></div>`).join(''));
}
function drawTrend(svg, trend) {
  const W = 600, H = 220, P = 30; const colors = {critical: '#991b1b', high: '#ea580c', medium: '#d97706', low: '#0891b2', info: '#71717a'};
  if (!trend.length) { setHTML(svg, ''); return; }
  const max = Math.max(1, ...trend.map(total));
  const bw = (W - P * 2) / trend.length; let out = `<line x1="${P}" y1="${H - P}" x2="${W - P}" y2="${H - P}" stroke="var(--border)"/>`;
  trend.forEach((s, i) => {
    let y = H - P; const x = P + i * bw + bw * 0.15;
    SEV.forEach((k) => { const h = ((s[k] || 0) / max) * (H - P * 2); if (!h) return; y -= h; out += `<rect x="${x}" y="${y}" width="${bw * 0.7}" height="${h}" fill="${colors[k]}" rx="2"><title>${esc(s.target)} — ${sevName(k)}: ${s[k]}</title></rect>`; });
    out += `<text x="${x + bw * 0.35}" y="${H - P + 14}" font-size="9" text-anchor="middle" fill="var(--muted)">${total(s)}</text>`;
  });
  setHTML(svg, out);
}
function scanRows(scans) {
  const head = `<tr><th>${t('rep.target')}</th><th>${t('rep.date')}</th><th>${t('rep.status')}</th>${SEV.map((s) => `<th>${esc(sevName(s))}</th>`).join('')}<th>${t('rep.total')}</th><th>${t('rep.actions')}</th></tr>`;
  return head + scans.map((s) => `<tr>
    <td class="mono" dir="ltr">${esc(s.label || s.target)}</td><td>${fmtDate(s.finished_at || s.started_at)}</td>
    <td>${s.status === 'running' ? '<span class="spinner" style="width:14px;height:14px;display:inline-block"></span> ' : ''}${esc(I18N[lang].status[s.status])}${s.error ? ` <small class="muted">${esc(s.error)}</small>` : ''}</td>
    ${SEV.map((k) => `<td><b style="color:var(--${k})">${s.summary[k] || 0}</b></td>`).join('')}<td><b>${total(s.summary)}</b></td>
    <td class="row gap"><a class="btn sm" href="#findings/${s.id}">${t('rep.view')}</a><a class="btn sm" href="/api/scans/${s.id}/report.html" download>HTML</a><button class="btn sm danger" data-del="${s.id}">${t('rep.delete')}</button></td></tr>`).join('');
}
document.addEventListener('click', async (e) => {
  const b = e.target.closest('[data-del]'); if (!b) return;
  if (!confirm(lang === 'ar' ? 'حذف هذا الفحص؟' : 'Delete this scan?')) return;
  await api(`/api/scans/${b.dataset.del}`, {method: 'DELETE'}); route();
});

/* --------------------------------------------------------------------- scan */
$$('#scan-tabs .tab').forEach((b) => b.onclick = () => {
  $$('#scan-tabs .tab').forEach((x) => x.classList.toggle('active', x === b));
  $$('.tab-pane').forEach((p) => p.classList.toggle('hidden', p.dataset.pane !== b.dataset.tab));
});
async function startScan(body) {
  try { const scan = await api('/api/scan', {method: 'POST', body: JSON.stringify(body)}); watchScan(scan.id); }
  catch (err) { toast(err.message); }
}
$('#path-btn').onclick = () => { const v = $('#path-input').value.trim(); if (v) startScan({target: v}); };
$('#path-input').onkeydown = (e) => { if (e.key === 'Enter') $('#path-btn').click(); };
$('#url-btn').onclick = () => {
  const v = $('#url-input').value.trim(); if (!v) return;
  if (!$('#url-auth').checked) return toast(t('scan.needAuth'));
  startScan({target: v, authorized: true});
};
let pending = [];
const dz = $('#dropzone');
const setFiles = (files) => { pending = [...files]; $('#upload-list').textContent = pending.length ? `${pending.length} ${t('scan.selected')}: ${pending.slice(0, 5).map((f) => f.webkitRelativePath || f.name).join(', ')}${pending.length > 5 ? '…' : ''}` : ''; $('#upload-btn').classList.toggle('hidden', !pending.length); };
$('#file-input').onchange = (e) => setFiles(e.target.files);
$('#folder-input').onchange = (e) => setFiles(e.target.files);
['dragenter', 'dragover'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add('over'); }));
['dragleave', 'drop'].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove('over'); }));
dz.addEventListener('drop', (e) => setFiles(e.dataTransfer.files));
$('#upload-btn').onclick = () => {
  if (!pending.length) return;
  const fd = new FormData(); pending.forEach((f) => fd.append('file', f, f.webkitRelativePath || f.name));
  const xhr = new XMLHttpRequest(); xhr.open('POST', '/api/upload');
  const prog = $('#upload-progress'); prog.classList.remove('hidden');
  xhr.upload.onprogress = (e) => { if (e.lengthComputable) prog.firstElementChild.style.width = (e.loaded / e.total * 100) + '%'; };
  xhr.onload = () => { prog.classList.add('hidden'); prog.firstElementChild.style.width = '0'; if (xhr.status < 300) { watchScan(JSON.parse(xhr.responseText).id); setFiles([]); } else toast(xhr.responseText); };
  xhr.onerror = () => toast('upload failed');
  xhr.send(fd);
};
async function watchScan(id) {
  const box = $('#scan-status'); box.classList.remove('hidden'); $('#scan-status-result').classList.add('hidden'); $('#scan-spinner').classList.remove('hidden');
  $('#scan-status-title').textContent = t('scan.running');
  const poll = async () => {
    const s = await api(`/api/scans/${id}`);
    $('#scan-status-target').textContent = s.label || s.target;
    if (s.status === 'running') { $('#scan-status-title').textContent = `${t('scan.running')} ${s.files_scanned ? '(' + s.files_scanned + ')' : ''}`; return setTimeout(poll, 700); }
    $('#scan-spinner').classList.add('hidden');
    if (s.status === 'error') { $('#scan-status-title').textContent = `${t('scan.failed')}: ${s.error}`; return; }
    $('#scan-status-title').textContent = `${t('scan.done')} — ${s.files_scanned} ${t('find.files')}`;
    setHTML($('#scan-status-tiles'), tiles(s.summary));
    $('#scan-status-open').href = `#findings/${s.id}`;
    $('#scan-status-result').classList.remove('hidden');
  };
  poll();
}

/* ----------------------------------------------------------------- findings */
let cur = null; const sevOn = new Set(SEV);
setHTML($('#sev-filter'), SEV.map((s) => `<button class="on ${s}" data-sev="${s}">${esc(sevName(s))}</button>`).join(''));
$('#sev-filter').onclick = (e) => { const b = e.target.closest('button'); if (!b) return; const s = b.dataset.sev; sevOn.has(s) ? sevOn.delete(s) : sevOn.add(s); b.classList.toggle('on'); renderFindings(); };
$('#findings-search').oninput = renderFindings; $('#source-filter').onchange = renderFindings;
$('#findings-scan').onchange = (e) => { location.hash = `findings/${e.target.value}`; };
async function loadFindings(arg) {
  const [id, qs] = (arg || '').split('?'); const q = new URLSearchParams(qs || '');
  const scans = (await api('/api/scans')).filter((s) => s.status === 'done');
  const sel = $('#findings-scan'); setHTML(sel, scans.map((s) => `<option value="${s.id}">${esc(s.label || s.target)} — ${fmtDate(s.finished_at)}</option>`).join(''));
  const chosen = id || (scans[0] && scans[0].id);
  if (!chosen) { setHTML($('#findings-list'), `<div class="empty"><div class="empty-icon">🧾</div><p>${t('dash.empty')}</p></div>`); return; }
  sel.value = chosen; cur = await api(`/api/scans/${chosen}`);
  if (q.get('sev')) { sevOn.clear(); sevOn.add(q.get('sev')); $$('#sev-filter button').forEach((b) => b.classList.toggle('on', sevOn.has(b.dataset.sev))); }
  $$('#sev-filter button').forEach((b) => { b.textContent = `${sevName(b.dataset.sev)} ${cur.summary[b.dataset.sev] || 0}`; });
  const sources = [...new Set(cur.findings.map((f) => f.source))];
  setHTML($('#source-filter'), `<option value="">${t('find.allSources')}</option>` + sources.map((s) => `<option>${esc(s)}</option>`).join(''));
  ['md', 'json', 'html'].forEach((x) => { $(`#dl-${x}`).href = `/api/scans/${chosen}/report.${x}`; });
  setHTML($('#findings-notes'), [`${cur.files_scanned} ${t('find.files')} · ${fmtDate(cur.finished_at)}`, ...cur.notes].map((n) => `<div>ℹ ${esc(n)}</div>`).join(''));
  renderFindings();
}
function renderFindings() {
  if (!cur) return;
  const q = $('#findings-search').value.trim().toLowerCase(); const src = $('#source-filter').value;
  const list = cur.findings.filter((f) => sevOn.has(f.severity) && (!src || f.source === src) && (!q || [f.file, f.rule_id, f.title, f.title_ar, f.snippet, f.cwe].join(' ').toLowerCase().includes(q)));
  if (!list.length) { setHTML($('#findings-list'), `<p class="muted">${t('find.none')}</p>`); return; }
  let html = '', last = null;
  list.forEach((f, i) => {
    if (f.severity !== last) { last = f.severity; html += `<div class="sev-head">${badge(f.severity)} <span>${list.filter((x) => x.severity === f.severity).length}</span></div>`; }
    const loc = f.line ? `${f.file}:${f.line}` : f.file;
    html += `<div class="finding ${f.severity}" data-i="${i}"><div class="head"><code>${esc(f.rule_id)}</code><b>${esc(lang === 'ar' ? f.title_ar : f.title)}</b>${f.cwe ? `<small class="muted">${esc(f.cwe)}</small>` : ''}<small class="muted">${esc(f.source)}</small></div>
      <div class="loc">${esc(loc)}</div>
      <div class="body"><div class="muted">${esc(lang === 'ar' ? f.title : f.title_ar)}</div>${f.snippet ? `<div><b>${t('find.snippet')}</b><pre>${esc(f.snippet)}</pre></div>` : ''}<div class="advice"><b>💡 ${t('find.advice')}:</b> ${esc(f.advice)}</div>${f.extra && f.extra.url ? `<p><b>${t('find.ref')}:</b> <a href="${esc(f.extra.url)}" target="_blank" rel="noopener">${esc(f.extra.url)}</a></p>` : ''}</div></div>`;
  });
  setHTML($('#findings-list'), html);
  $$('#findings-list .finding').forEach((el) => el.onclick = () => el.classList.toggle('open'));
}

/* ------------------------------------------------------------------ reports */
async function loadReports() {
  const scans = await api('/api/scans');
  setHTML($('#reports-table'), scanRows(scans));
  const opts = scans.filter((s) => s.status === 'done').map((s) => `<option value="${s.id}">${esc(s.label || s.target)} — ${fmtDate(s.finished_at)}</option>`).join('');
  setHTML($('#cmp-a'), opts); setHTML($('#cmp-b'), opts); if ($('#cmp-a').options.length > 1) $('#cmp-a').selectedIndex = 1;
}
$('#cmp-btn').onclick = async () => {
  const a = await api(`/api/scans/${$('#cmp-a').value}`), b = await api(`/api/scans/${$('#cmp-b').value}`);
  const key = (f) => `${f.rule_id}|${f.file.replace(/^[^!]*!/, '')}|${f.snippet}`;
  const ka = new Set(a.findings.map(key)), kb = new Set(b.findings.map(key));
  const fixed = a.findings.filter((f) => !kb.has(key(f))), added = b.findings.filter((f) => !ka.has(key(f)));
  const diff = {}; SEV.forEach((s) => diff[s] = (b.summary[s] || 0) - (a.summary[s] || 0));
  setHTML($('#cmp-tiles'), SEV.map((s) => `<div class="tile bg-${s}"><div class="n">${diff[s] > 0 ? '+' : ''}${diff[s]}</div><div class="l">${esc(sevName(s))}</div></div>`).join(''));
  const li = (f) => `<li><span>${badge(f.severity)} <code>${esc(f.rule_id)}</code> <span class="mono" dir="ltr">${esc(f.file)}${f.line ? ':' + f.line : ''}</span></span></li>`;
  setHTML($('#cmp-fixed'), fixed.map(li).join('') || `<li class="muted">${t('rep.nothing')}</li>`);
  setHTML($('#cmp-new'), added.map(li).join('') || `<li class="muted">${t('rep.nothing')}</li>`);
  $('#cmp-result').classList.remove('hidden');
};

/* -------------------------------------------------------------------- rules */
let rulesCache = null;
async function loadRules() {
  rulesCache = rulesCache || await api('/api/rules');
  $('#rules-count').textContent = `${rulesCache.length} ${t('rules.count')}`;
  renderRules();
}
$('#rules-search').oninput = renderRules;
function renderRules() {
  const q = $('#rules-search').value.trim().toLowerCase();
  const rows = rulesCache.filter((r) => !q || [r.id, r.title, r.title_ar, r.cwe, ...r.langs].join(' ').toLowerCase().includes(q));
  setHTML($('#rules-table'), `<tr><th>${t('rules.id')}</th><th>${t('rules.sev')}</th><th>${t('rules.name')}</th><th>${t('rules.langs')}</th><th>${t('rules.advice')}</th></tr>` +
    rows.map((r) => `<tr><td><code>${esc(r.id)}</code><br><small class="muted">${esc(r.cwe)}</small></td><td>${badge(r.severity)}</td><td><b>${esc(r.title_ar)}</b><br><small class="muted">${esc(r.title)}</small></td><td class="mono" dir="ltr"><small>${esc(r.langs.slice(0, 8).join(' '))}${r.langs.length > 8 ? ' …' : ''}</small></td><td>${esc(r.advice)}</td></tr>`).join(''));
}

/* ----------------------------------------------------------------- settings */
async function loadSettings() {
  const [s, meta] = await Promise.all([api('/api/settings'), api('/api/meta')]);
  const f = $('#settings-form');
  f.min_severity.value = s.min_severity; f.fail_on.value = s.fail_on; f.keep_scans.value = s.keep_scans;
  f.exclude.value = s.exclude.join('\n'); f.ignore_rules.value = s.ignore_rules.join('\n'); f.authorized_targets.value = s.authorized_targets.join('\n');
  f.use_osv.checked = !!s.use_osv; f.use_external.checked = !!s.use_external;
  $('#ext-tools').textContent = `(${meta.external_tools.length ? meta.external_tools.join(', ') : t('set.none')})`;
  $('#settings-home').textContent = `${t('set.home')}: ${meta.home}`;
  $('#version').textContent = 'v' + meta.version;
}
$('#settings-form').onsubmit = async (e) => {
  e.preventDefault(); const f = e.target; const lines = (v) => v.split('\n').map((x) => x.trim()).filter(Boolean);
  await api('/api/settings', {method: 'POST', body: JSON.stringify({min_severity: f.min_severity.value, fail_on: f.fail_on.value, keep_scans: +f.keep_scans.value,
    exclude: lines(f.exclude.value), ignore_rules: lines(f.ignore_rules.value), authorized_targets: lines(f.authorized_targets.value), use_osv: f.use_osv.checked, use_external: f.use_external.checked})});
  $('#settings-saved').textContent = t('set.saved'); setTimeout(() => $('#settings-saved').textContent = '', 2000);
};

/* --------------------------------------------------------------------- boot */
api('/api/meta').then((m) => { $('#version').textContent = 'v' + m.version; });
applyLang(); route();
