// Open Graph cards (1200x630) for the landing page, rendered from HTML so text stays crisp.
// Run by make.py after the screenshots are installed (the card shows site/img/shots/trace-<lang>-dark.webp).
// Usage: node og.js <site dir> <out dir> <version>
const { chromium } = require('playwright');
const fs = require('fs');
const [SITE, OUT] = [process.argv[2], process.argv[3]];
const VER = process.argv[4];
if (!VER) throw new Error('usage: node og.js <site dir> <out dir> <version>');
const logo = fs.readFileSync(SITE + '/logo.svg', 'utf8');
const index = fs.readFileSync(SITE + '/index.html', 'utf8');
// the benchmark numbers come from the landing page itself, so the card never disagrees with it
const bench = (s) => (index.match(new RegExp(`data-bench-suite="${s}">([0-9.]+)`)) || [])[1];
const [PY, JAVA] = [bench('python'), bench('java')];
if (!PY || !JAVA) throw new Error('benchmark numbers not found in index.html');
const shot = (lang) => 'data:image/webp;base64,' + fs.readFileSync(`${SITE}/img/shots/trace-${lang}-dark.webp`).toString('base64');
const T = {
  en: { dir: 'ltr', name: 'Kashif', sub: 'vulnscan · open-source SAST', h1: 'Trace every vulnerability', h2: 'from input to impact.',
        pts: ['Dataflow analysis in 12 languages', `OWASP Benchmark: <bdi>Python ${PY}% · Java ${JAVA}%</bdi>`,
              'Autofix · compliance · attack surface', 'Free · offline · zero dependencies'] },
  ar: { dir: 'rtl', name: 'كاشِف', sub: 'vulnscan · فاحص أمان مفتوح المصدر', h1: 'تتبّع كل ثغرة', h2: 'من المُدخل حتى الأثر.',
        pts: ['تحليل تدفق البيانات في 12 لغة', `<bdi dir="ltr">OWASP Benchmark: Python ${PY}% · Java ${JAVA}%</bdi>`,
              'إصلاح آلي · امتثال · سطح الهجوم', 'مجاني · دون اتصال · بلا اعتماديات'] },
};
const html = (l) => `<!doctype html><html lang="${l}" dir="ltr"><head><meta charset="utf-8"><style>
*{box-sizing:border-box;margin:0}html{overflow:hidden}
body{width:1200px;height:630px;overflow:hidden;font-family:"Inter","Segoe UI",system-ui,-apple-system,"Noto Sans Arabic",Tahoma,sans-serif;
 background:radial-gradient(700px 420px at ${l === 'ar' ? '85%' : '15%'} 0%,rgba(10,143,74,.28),transparent 70%),#0b1020;color:#e6edf6;position:relative}
.wrap{position:absolute;top:0;bottom:0;padding:60px 64px 58px;display:flex;flex-direction:column;justify-content:space-between;width:600px;${l === 'ar' ? 'left:600px;' : 'left:0;'}}
.brand{display:flex;align-items:center;gap:16px}.brand svg{width:56px;height:56px;flex:none}
.brand b{font-size:34px;font-weight:800;letter-spacing:-.01em;display:flex;align-items:center;gap:12px}.brand small{font-size:17px;color:#93a4bd;display:block}
.ver{font-size:15px;font-weight:700;letter-spacing:0;color:#0b1020;background:linear-gradient(90deg,#3fc07c,#33b5ec);border-radius:999px;padding:3px 11px;direction:ltr;unicode-bidi:isolate}
h1{font-size:50px;line-height:1.08;font-weight:800;letter-spacing:-.02em}
h1 span{display:block;background:linear-gradient(90deg,#3fc07c,#33b5ec);-webkit-background-clip:text;background-clip:text;color:transparent}
ul{list-style:none;display:grid;gap:11px;font-size:18px;white-space:nowrap;color:#c9d4e3}
li{display:flex;align-items:center;gap:12px}li:before{content:"";width:10px;height:10px;border-radius:50%;background:#3fc07c;flex:none}
.shot{position:absolute;top:70px;${l === 'ar' ? 'left:-170px' : 'right:-170px'};width:740px;border-radius:16px;overflow:hidden;
 border:1px solid #26324a;box-shadow:0 30px 80px rgba(0,0,0,.55)}
.shot img{display:block;width:100%}
</style></head><body>
<div class="shot"><img src="${shot(l)}"></div>
<div class="wrap" dir="${T[l].dir}">
 <div class="brand">${logo}<div><b>${T[l].name}<span class="ver">v${VER}</span></b><small>${T[l].sub}</small></div></div>
 <h1>${T[l].h1}<span>${T[l].h2}</span></h1>
 <ul>${T[l].pts.map((x) => `<li><span>${x}</span></li>`).join('')}</ul>
</div></body></html>`;
(async () => {
  const b = await chromium.launch();
  for (const l of ['en', 'ar']) {
    const p = await b.newPage({ viewport: { width: 1200, height: 630 }, deviceScaleFactor: 1 });
    await p.setContent(html(l)); await p.waitForTimeout(400);
    await p.screenshot({ path: `${OUT}/og-${l}.png` });
    await p.close();
  }
  await b.close();
  console.log(JSON.stringify({ python: PY, java: JAVA, version: VER }));
})();
