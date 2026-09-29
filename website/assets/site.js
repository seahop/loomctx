(function () {
  "use strict";
  var root = document.documentElement;
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  function cssVar(name) { return getComputedStyle(root).getPropertyValue(name).trim(); }

  /* ---------------- theme toggle ---------------- */
  var themeBtn = document.getElementById("theme-toggle");
  function effectiveTheme() {
    if (root.dataset.theme) return root.dataset.theme;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  themeBtn.addEventListener("click", function () {
    var next = effectiveTheme() === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    try { localStorage.setItem("loomctx-theme", next); } catch (e) {}
    redrawAll();
  });
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () { redrawAll(); });

  /* ---------------- copy buttons ---------------- */
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var el = document.getElementById(btn.dataset.copy);
      var text = el.innerText;
      function done(label) { btn.textContent = label; setTimeout(function () { btn.textContent = "Copy"; }, 1600); }
      function fallback() {
        var r = document.createRange(); r.selectNodeContents(el);
        var sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(r);
        done("Selected, press Ctrl+C");
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { done("Copied"); }, fallback);
      } else { fallback(); }
    });
  });

  /* ---------------- the weave ----------------
     Weft threads = sources, running left→right through time (Jul → Sep).
     Knots = observations. The pack lifts a few of them out: the two sides of
     the runs_os conflict, and the facts that fit the rest of the budget.   */
  var canvas = document.getElementById("weave");
  var ctx = canvas.getContext("2d");
  var SOURCES = ["asset-inventory", "nmap-scan", "auth-log", "dhcp-log", "edr-alerts", "nvd", "cisa-kev"];
  var DENSITY = [3, 6, 26, 9, 7, 12, 4];
  var START = Date.UTC(2026, 6, 1), END = Date.UTC(2026, 8, 20), DAY = 864e5;

  // deterministic knots so the picture is identical on every load
  var seed = 7;
  function rand() { seed = (seed * 16807) % 2147483647; return (seed - 1) / 2147483646; }
  var knots = [];
  SOURCES.forEach(function (src, row) {
    for (var i = 0; i < DENSITY[row]; i++) {
      knots.push({ row: row, t: START + rand() * (END - START), kind: "obs" });
    }
  });
  // the planted conflict from the seed data: inventory (Jul 3) vs nmap (Aug 18)
  knots.push({ row: 0, t: START + 2 * DAY, kind: "conf" });
  knots.push({ row: 1, t: START + 48 * DAY, kind: "conf" });
  // a handful of packed facts: the ones that fit the rest of the budget
  [[1, 60], [1, 71], [2, 78], [2, 76], [4, 69], [5, 62]].forEach(function (p) {
    knots.push({ row: p[0], t: START + p[1] * DAY, kind: "sel" });
  });

  var anim = { start: 0, raf: 0 };
  function geom() {
    var w = canvas.clientWidth, h = canvas.clientHeight;
    var labelW = w < 460 ? 0 : 108;
    var top = 26, bottom = 50;
    var left = labelW + 12, right = w - 16;
    var rowH = (h - top - bottom) / (SOURCES.length - 1);
    return { w: w, h: h, left: left, right: right, top: top, rowH: rowH, labelW: labelW };
  }
  function xOf(g, t) { return g.left + (t - START) / (END - START) * (g.right - g.left); }
  function yOf(g, row) { return g.top + row * g.rowH; }
  function ease(x) { return 1 - Math.pow(1 - Math.min(Math.max(x, 0), 1), 3); }

  function drawWeave(ms) {
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var g = geom();
    if (canvas.width !== Math.round(g.w * dpr) || canvas.height !== Math.round(g.h * dpr)) {
      canvas.width = Math.round(g.w * dpr); canvas.height = Math.round(g.h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, g.w, g.h);

    var C = {
      line: cssVar("--line"), line2: cssVar("--line-2"), ink2: cssVar("--ink-2"), muted: cssVar("--muted"),
      woad: cssVar("--woad"), madder: cssVar("--madder"), weld: cssVar("--weld"), surface: cssVar("--surface")
    };
    var pThreads = ease(ms / 1100);          // threads draw in
    var pKnots = ease((ms - 500) / 900);     // observations appear
    var pPack = ease((ms - 1400) / 800);     // the pack lifts out

    // warp: faint vertical threads, one per week
    ctx.lineWidth = 1;
    for (var t = START; t <= END; t += 7 * DAY) {
      var x = xOf(g, t);
      ctx.strokeStyle = C.line;
      ctx.beginPath(); ctx.moveTo(x, g.top - 10); ctx.lineTo(x, yOf(g, SOURCES.length - 1) + 10); ctx.stroke();
    }

    // weft: one thread per source, passing over and under the warp
    var reach = g.left + (g.right - g.left) * pThreads;
    SOURCES.forEach(function (src, row) {
      var y = yOf(g, row);
      ctx.strokeStyle = C.line2; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.moveTo(g.left, y); ctx.lineTo(reach, y); ctx.stroke();
      // "under" crossings: let the warp show through on alternate weeks
      var k = 0;
      for (var t2 = START; t2 <= END; t2 += 7 * DAY, k++) {
        var xx = xOf(g, t2);
        if (xx > reach) break;
        if ((k + row) % 2 === 0) { ctx.fillStyle = C.surface; ctx.fillRect(xx - 1.5, y - 1.5, 3, 3); ctx.fillStyle = C.line; ctx.fillRect(xx - .5, y - 1.5, 1, 3); }
      }
      if (g.labelW) {
        ctx.fillStyle = C.muted; ctx.font = "500 10.5px " + cssVar("--f-mono");
        ctx.textAlign = "right"; ctx.textBaseline = "middle";
        ctx.fillText(src, g.labelW, y);
      }
    });

    // observations
    knots.forEach(function (kn) {
      var x = xOf(g, kn.t), y = yOf(g, kn.row);
      if (x > reach) return;
      if (kn.kind === "obs") {
        ctx.globalAlpha = pKnots * (1 - .55 * pPack);
        ctx.fillStyle = C.ink2;
        ctx.beginPath(); ctx.arc(x, y, 2.6, 0, Math.PI * 2); ctx.fill();
        ctx.globalAlpha = 1;
      }
    });

    // the pack: conflict pair joined, then packed facts
    var conf = knots.filter(function (k) { return k.kind === "conf"; });
    if (pKnots > 0) {
      var a = conf[0], b = conf[1];
      var ax = xOf(g, a.t), ay = yOf(g, a.row), bx = xOf(g, b.t), by = yOf(g, b.row);
      if (pPack > 0) {
        ctx.strokeStyle = C.madder; ctx.lineWidth = 1.5; ctx.setLineDash([4, 4]);
        ctx.globalAlpha = pPack;
        ctx.beginPath(); ctx.moveTo(ax, ay); ctx.bezierCurveTo(ax + 60, ay - 14, bx - 60, by + 14, bx, by); ctx.stroke();
        ctx.setLineDash([]); ctx.globalAlpha = 1;
        ctx.fillStyle = C.madder; ctx.font = "600 10.5px " + cssVar("--f-mono"); ctx.textAlign = "left"; ctx.textBaseline = "bottom";
        ctx.globalAlpha = pPack;
        ctx.fillText("runs_os: sources disagree", ax + 10, ay - 7);
        ctx.globalAlpha = 1;
      }
      [a, b].forEach(function (k) {
        var x = xOf(g, k.t), y = yOf(g, k.row);
        if (x > reach) return;
        var r = 3 + 2.5 * pPack;
        ctx.fillStyle = pPack > 0 ? C.madder : C.ink2; ctx.globalAlpha = Math.max(pKnots, .001);
        ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
        ctx.strokeStyle = C.surface; ctx.lineWidth = 2; ctx.stroke();
        ctx.globalAlpha = 1;
      });
    }
    knots.forEach(function (kn) {
      if (kn.kind !== "sel") return;
      var x = xOf(g, kn.t), y = yOf(g, kn.row);
      if (x > reach || pKnots <= 0) return;
      var r = 2.6 + 2.2 * pPack;
      ctx.globalAlpha = pKnots;
      ctx.fillStyle = pPack > 0 ? C.weld : C.ink2;
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill();
      ctx.strokeStyle = C.surface; ctx.lineWidth = 2; ctx.stroke();
      ctx.globalAlpha = 1;
    });

    // time axis + budget meter
    var axisY = g.h - 30;
    ctx.fillStyle = C.muted; ctx.font = "500 10px " + cssVar("--f-mono"); ctx.textBaseline = "alphabetic";
    [["Jul", Date.UTC(2026, 6, 1)], ["Aug", Date.UTC(2026, 7, 1)], ["Sep", Date.UTC(2026, 8, 1)]].forEach(function (m, i) {
      ctx.textAlign = i === 0 ? "left" : "center";
      ctx.fillText(m[0], xOf(g, m[1]), axisY);
    });
    var mW = g.right - g.left, mY = g.h - 16;
    ctx.fillStyle = C.line; roundRect(g.left, mY, mW, 5, 2.5); ctx.fill();
    var used = 351 / 400 * pPack;
    if (used > 0) { ctx.fillStyle = C.weld; roundRect(g.left, mY, Math.max(mW * used, 5), 5, 2.5); ctx.fill(); }
    if (g.labelW) {
      ctx.fillStyle = C.muted; ctx.textAlign = "right"; ctx.textBaseline = "middle";
      ctx.fillText("budget", g.labelW, mY + 2.5);
    }
  }
  function roundRect(x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
    ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
  }
  function play() {
    if (reduceMotion) { drawWeave(1e9); return; }
    cancelAnimationFrame(anim.raf);
    anim.start = performance.now();
    (function tick(now) {
      var ms = now - anim.start;
      drawWeave(ms);
      if (ms < 2400) anim.raf = requestAnimationFrame(tick);
    })(anim.start);
  }

  /* ---------------- retrieval scorecard: dot plot ---------------- */
  var ROWS = [
    { budget: "400", loomctx: 81, vector: 75, recency: 50 },
    { budget: "800", loomctx: 84, vector: 77, recency: 75 },
    { budget: "1,600", loomctx: 86, vector: 79, recency: 75 },
    { budget: "3,200", loomctx: 96, vector: 87, recency: 77 }
  ];
  var SERIES = [
    { key: "recency", name: "Most recent", fill: "var(--surface)", stroke: "var(--muted)", r: 5.5 },
    { key: "vector", name: "Vector top-k", fill: "var(--muted)", r: 6 },
    { key: "loomctx", name: "LoomCtx", fill: "var(--woad)", r: 7.5 }
  ];
  var svg = document.getElementById("scorechart");
  var tip = document.getElementById("chart-tip");
  function drawChart() {
    var W = 560, L = 76, R = 44, T = 18, rowGap = 46, lo = 40, hi = 100;
    var axisY = T + rowGap * ROWS.length;
    function x(v) { return L + (v - lo) / (hi - lo) * (W - L - R); }
    var out = [];
    out.push('<g class="grid">');
    for (var v = lo; v <= hi; v += 10) out.push('<line x1="' + x(v) + '" x2="' + x(v) + '" y1="' + (T - 6) + '" y2="' + axisY + '"/>');
    out.push("</g><g class=\"axis\">");
    for (var v2 = lo; v2 <= hi; v2 += 10) out.push('<text x="' + x(v2) + '" y="' + (axisY + 18) + '" text-anchor="middle">' + v2 + "%</text>");
    out.push("</g>");
    ROWS.forEach(function (row, i) {
      var y = T + 14 + i * rowGap;
      var vals = SERIES.map(function (s) { return row[s.key]; });
      out.push('<text class="row-lbl" x="' + (L - 12) + '" y="' + (y + 4) + '" text-anchor="end">' + row.budget + "</text>");
      out.push('<line class="span" x1="' + x(Math.min.apply(null, vals)) + '" x2="' + x(Math.max.apply(null, vals)) + '" y1="' + y + '" y2="' + y + '"/>');
      SERIES.forEach(function (s) {
        var cx = x(row[s.key]);
        out.push('<circle cx="' + cx + '" cy="' + y + '" r="' + s.r + '" style="fill:' + s.fill + ';stroke:' + (s.stroke || 'var(--surface)') + ';stroke-width:2"/>');
      });
      out.push('<text class="val" x="' + (x(row.loomctx) + 12) + '" y="' + (y + 4) + '">' + row.loomctx + "%</text>");
      SERIES.forEach(function (s) {
        out.push('<circle class="hit" style="fill:transparent" cx="' + x(row[s.key]) + '" cy="' + y + '" r="13" data-tip="' + s.name + " @ " + row.budget + " tokens: " + row[s.key] + '%"/>');
      });
    });
    out.push('<text class="lbl" x="' + (L - 12) + '" y="' + (T - 2) + '" text-anchor="end">budget</text>');
    svg.innerHTML = out.join("");
    svg.setAttribute("viewBox", "0 0 " + W + " " + (axisY + 28));
  }
  svg.addEventListener("pointerover", function (e) {
    var t = e.target.getAttribute && e.target.getAttribute("data-tip");
    if (!t) { tip.hidden = true; return; }
    var box = svg.getBoundingClientRect(), c = e.target.getBoundingClientRect();
    tip.textContent = t; tip.hidden = false;
    tip.style.left = (c.left + c.width / 2 - box.left) + "px";
    tip.style.top = (c.top - box.top + 6) + "px";
  });
  svg.addEventListener("pointerleave", function () { tip.hidden = true; });

  function redrawAll() { drawWeave(1e9); drawChart(); }
  var resizeTimer;
  window.addEventListener("resize", function () { clearTimeout(resizeTimer); resizeTimer = setTimeout(function () { drawWeave(1e9); }, 80); });

  drawChart();
  // wait for the mono face so canvas labels use it
  (document.fonts && document.fonts.ready ? document.fonts.ready : Promise.resolve()).then(play);
  drawWeave(reduceMotion ? 1e9 : 0);
})();
