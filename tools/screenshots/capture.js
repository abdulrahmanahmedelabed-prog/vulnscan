// Product screenshots for the landing page and README: 1440x900 viewport at 2x DPR, en/ar x light/dark, UTC.
// Run by make.py (python tools/screenshots/make.py), which starts the UI and writes the config.
// Usage: node capture.js <config.json> <outdir>
// config: {base, pid, path, scans: [oldest..newest ids], web, sql_line, only: [screen names]}
const { chromium } = require('playwright');
const fs = require('fs');
const C = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const OUT = process.argv[3];
const want = (n) => C.only.includes(n);
const sqlAt = new RegExp(`app\\.py:${C.sql_line}\\b`);

(async () => {
  const b = await chromium.launch();
  const errs = [];
  for (const lang of ['en', 'ar']) for (const theme of ['light', 'dark']) {
    const ctx = await b.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: theme,
      locale: lang === 'ar' ? 'ar' : 'en-GB', timezoneId: 'UTC' });
    // the dashboard follows the demo project (the web scan is a second project)
    await ctx.addInitScript(([l, th, pid]) => {
      try { localStorage.setItem('vs.lang', l); localStorage.setItem('vs.theme', th); localStorage.setItem('vs.project', pid); } catch (e) { /* about:blank */ }
    }, [lang, theme, C.pid]);
    const p = await ctx.newPage();
    const tag = `${lang}-${theme}`;
    p.on('pageerror', (e) => errs.push(`${tag} ${e}`));
    p.on('console', (m) => { if (m.type() === 'error') errs.push(`${tag} console ${m.text()}`); });
    const shot = async (name) => { await p.mouse.move(0, 899); await p.waitForTimeout(150); await p.screenshot({ path: `${OUT}/${name}-${tag}.png` }); };
    // about:blank first: a hash-only goto would keep the previous view's state (an expanded finding).
    const go = async (hash, wait = 1100) => { await p.goto('about:blank'); await p.goto(C.base + '/#' + hash); await p.waitForTimeout(wait); };
    // Scroll an element to `top` px below the viewport top (window or the scrolling main pane).
    const scrollTo = async (el, top) => {
      await el.evaluate((node, off) => {
        window.scrollTo({ top: node.getBoundingClientRect().top + window.scrollY - off, behavior: 'instant' });
        const main = document.querySelector('.content, main');
        if (main && main.scrollHeight > main.clientHeight) main.scrollTop += node.getBoundingClientRect().top - off;
      }, top);
      await p.waitForTimeout(300);
    };
    const findRow = async (re) => {
      for (const r of await p.$$('.f-row')) { const t = await r.innerText(); if (re.every((x) => x.test(t))) return r; }
      errs.push(`${tag} row not found ${re}`); return null;
    };
    const card = async (row) => (await row.evaluateHandle((el) => el.closest('.finding') || el)).asElement();
    const latest = C.scans[C.scans.length - 1];

    if (want('dashboard')) { await go('dashboard'); await shot('dashboard'); }
    if (want('scan')) { await go('scan', 700); await p.fill('#path-input', C.path).catch((e) => errs.push(`${tag} scan fill ${e}`)); await shot('scan'); }
    if (want('reports')) {
      await go('reports');
      try {
        await p.selectOption('#cmp-a', C.scans[0]);     // oldest scan as the base
        await p.selectOption('#cmp-b', latest);         // newest scan to compare with
        await p.click('#cmp-btn'); await p.waitForTimeout(900);
      } catch (e) { errs.push(`${tag} reports compare ${e}`); }
      await shot('reports');
    }
    if (want('findings')) { await go('findings/' + latest); await shot('findings'); }
    if (want('trace')) {
      await go('findings/' + latest);
      const r = await findRow([/DF004/, sqlAt]);
      if (r) { await r.click(); await p.waitForTimeout(400); await scrollTo(await card(r), 41); await shot('trace'); }
    }
    if (want('autofix')) {
      await go('findings/' + latest);
      const r = await findRow([/DF006/]);
      if (r) { await r.click(); await p.waitForTimeout(400); await scrollTo(await card(r), 0); await shot('autofix'); }
    }
    if (want('triage')) {
      await go('findings/' + latest);
      const r = await findRow([/DF004/, sqlAt]);
      if (r) { await r.click(); await p.waitForTimeout(500); const sec = await p.$('.d-sec.tri-sec');
        if (sec) await sec.$$eval('details', (ds) => ds.forEach((d) => { d.open = true; }));
        else errs.push(`${tag} triage section not found`);
        await p.waitForTimeout(200);
        await scrollTo(sec || await card(r), 120); await shot('triage'); }
    }
    if (want('export')) {
      await go('findings/' + latest);
      await p.click('#export-btn').catch((e) => errs.push(`${tag} export ${e}`)); await p.waitForTimeout(400);
      await p.screenshot({ path: `${OUT}/export-${tag}.png` });
    }
    if (want('compliance')) { await go('compliance/' + latest, 1400); await shot('compliance'); }
    if (want('surface')) {
      await go('projects/' + C.pid, 1600);
      const sf = await p.$('#sf-card .sf-stat');
      if (sf) { await scrollTo(await p.$('#sf-card'), 24); await shot('surface'); } else errs.push(`${tag} surface map not shown`);
    }
    if (want('web')) {
      await go('findings/' + C.web, 1800);
      const panel = await p.$('#findings-web > *');
      if (panel) await shot('web'); else errs.push(`${tag} web panel not shown`);
    }
    await ctx.close();
  }
  console.log(JSON.stringify(errs, null, 1));
  await b.close();
})();
