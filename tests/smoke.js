#!/usr/bin/env node
/* Browser smoke test for Cyber Attack Earth.
 *
 * Serves the repo root, opens the page on five screen sizes and checks:
 *  - no script errors, and nothing is fetched from a CDN (everything self-hosted)
 *  - the welcome screen becomes ready and closes, and is then out of the Tab order
 *  - the page is never wider than the screen
 *  - the data pack loads (tens of thousands of routes, not the ~90 embedded ones)
 *  - EuRepoC rows get real sectors and techniques (v94 fix)
 *  - the status chip does not say "Data OK" while exports are past their limit
 *  - on a folded Fold, a window's close button is not under the tool bar
 *
 * Every request to another site is blocked, so the test proves the page works
 * on its own files. Usage (from tests/):
 *   node smoke.js            all five screens
 *   node smoke.js --quick    laptop, folded Fold, phone
 *   node smoke.js --shots    also save screenshots to tests/out/
 *   node smoke.js --url=https://stuartokin.github.io/cyber-attack-earth/   test the live site
 */
const { chromium } = require("playwright");
const http = require("http");
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const args = process.argv.slice(2);
const QUICK = args.includes("--quick");
const SHOTS = args.includes("--shots");
const URL_ARG = (args.find(a => a.startsWith("--url=")) || "").slice(6);

const SCREENS = [
  { name: "desktop-1908x950", width: 1908, height: 950 },
  { name: "laptop-1366x768", width: 1366, height: 768 },
  { name: "phone-390x844", width: 390, height: 844, mobile: true },
  { name: "fold-folded-344x882", width: 344, height: 882, mobile: true },
  { name: "fold-open-884x1104", width: 884, height: 1104, mobile: true },
].filter(s => !QUICK || /laptop|folded|phone/.test(s.name));

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".json": "application/json",
  ".css": "text/css", ".png": "image/png", ".jpg": "image/jpeg", ".mp3": "audio/mpeg",
  ".csv": "text/csv" };

function serve() {
  return new Promise(resolve => {
    const srv = http.createServer((req, res) => {
      let p = decodeURIComponent(req.url.split("?")[0]);
      if (p.endsWith("/")) p += "index.html";
      const f = path.join(ROOT, p);
      if (!f.startsWith(ROOT) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) {
        res.writeHead(404); return res.end("not found");
      }
      res.writeHead(200, { "Content-Type": TYPES[path.extname(f)] || "application/octet-stream" });
      if (req.method === "HEAD") return res.end();
      fs.createReadStream(f).pipe(res);
    });
    srv.listen(0, "127.0.0.1", () => resolve(srv));
  });
}

let failures = 0;
function check(screen, ok, msg) {
  console.log(`  ${ok ? "ok  " : "FAIL"} [${screen}] ${msg}`);
  if (!ok) failures++;
}

(async () => {
  const srv = URL_ARG ? null : await serve();
  const base = URL_ARG || `http://127.0.0.1:${srv.address().port}/`;
  const host = new URL(base).host;
  const browser = await chromium.launch();
  if (SHOTS) fs.mkdirSync(path.join(__dirname, "out"), { recursive: true });

  for (const s of SCREENS) {
    const ctx = await browser.newContext({
      viewport: { width: s.width, height: s.height },
      isMobile: !!s.mobile, hasTouch: !!s.mobile, deviceScaleFactor: 1,
    });
    const page = await ctx.newPage();
    const errors = [], offsite = [];
    page.on("pageerror", e => errors.push(String(e.message || e)));
    await page.route("**/*", route => {
      const u = new URL(route.request().url());
      if (u.host === host) return route.continue();
      // Google Fonts may stay external; everything else must be self-hosted.
      if (!/fonts\.(googleapis|gstatic)\.com/.test(u.host)) offsite.push(u.host + u.pathname);
      return route.abort();
    });

    await page.goto(base, { waitUntil: "load" });
    try {
      await page.waitForFunction(() => {
        const b = document.getElementById("splashGo");
        return b && !b.disabled;
      }, null, { timeout: 60000 });
      check(s.name, true, "welcome screen became ready");
    } catch (e) {
      check(s.name, false, "welcome screen never became ready");
    }
    // the welcome button can be ready before the merge finishes; give the pack time
    await page.waitForFunction(() => typeof attacks !== "undefined" && attacks.length > 20000,
      null, { timeout: 60000 }).catch(() => {});
    const n = await page.evaluate(() => (typeof attacks !== "undefined" ? attacks.length : 0));
    check(s.name, n > 20000, `data pack loaded (${n.toLocaleString()} routes)`);

    await page.click("#splashGo").catch(() => {});
    await page.waitForTimeout(1200);
    const inert = await page.evaluate(() => document.getElementById("splash").inert === true);
    check(s.name, inert, "closed welcome screen is out of the Tab order (inert)");

    const wide = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, w: innerWidth }));
    check(s.name, wide.sw <= wide.w, `page not wider than the screen (${wide.sw} <= ${wide.w})`);

    // EuRepoC sectors and techniques
    const eu = await page.evaluate(() => {
      const rows = attacks.filter(a => /EuRepoC Global/.test(a.source || ""));
      const sectors = new Set(rows.map(a => a.sector));
      return {
        rows: rows.length,
        sectors: sectors.size,
        raw: [...sectors].filter(x => /^\[|'/.test(String(x))).length,
        notCat: rows.filter(a => a.type === "Not categorised").length,
      };
    });
    check(s.name, eu.rows > 1000, `EuRepoC rows mapped (${eu.rows})`);
    check(s.name, eu.sectors >= 6 && eu.raw === 0, `EuRepoC sectors are real (${eu.sectors} sectors, ${eu.raw} raw)`);
    check(s.name, eu.notCat < eu.rows * 0.2, `EuRepoC techniques named (${eu.notCat} of ${eu.rows} not categorised)`);

    // Status chip must not say OK while hand-downloaded exports are out of date
    const health = await page.evaluate(() => {
      const st = typeof staleExports === "function" ? staleExports().length : -1;
      return { stale: st, label: (document.getElementById("tbHealthLabel") || {}).textContent };
    });
    if (health.stale > 0) check(s.name, health.label !== "Data OK", `status chip is honest about stale exports ("${health.label}")`);
    else check(s.name, health.stale === 0, `no stale exports; chip says "${health.label}"`);

    // Coverage badge appears at the end of the timeline when only claims remain
    const badge = await page.evaluate(() => {
      timelineIndex = endTimelineIndex; update();
      const end = verifiedCoverageEnd();
      return { end, max: endTimelineIndex, shown: !document.getElementById("tlCoverage").classList.contains("hidden") };
    });
    if (badge.end >= 0 && badge.end < badge.max) check(s.name, badge.shown, "claims-only note shown past the end of verified sources");

    // Open Controls; its close button must be reachable (not under the tool bar)
    await page.evaluate(() => openFrame("controls"));
    await page.waitForTimeout(400);
    const reach = await page.evaluate(() => {
      const b = document.querySelector("#frame-controls .frameClose");
      if (!b) return "no button";
      const r = b.getBoundingClientRect();
      const el = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      return el && (el === b || b.contains(el)) ? "ok" : (el ? (el.id || el.className || el.tagName) : "nothing");
    });
    check(s.name, reach === "ok", `Controls close button reachable (${reach})`);

    if (SHOTS) await page.screenshot({ path: path.join(__dirname, "out", `${s.name}.png`) });

    check(s.name, errors.length === 0, `no script errors${errors.length ? ": " + errors.slice(0, 3).join(" | ") : ""}`);
    const cdn = offsite.filter(u => !/ransomware\.live/.test(u));
    check(s.name, cdn.length === 0, `nothing fetched from other sites except ransomware.live${cdn.length ? ": " + cdn.slice(0, 3).join(", ") : ""}`);
    await ctx.close();
  }
  await browser.close();
  if (srv) srv.close();
  console.log(`\n${failures ? "FAIL" : "PASS"}: ${failures} failure(s)`);
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
