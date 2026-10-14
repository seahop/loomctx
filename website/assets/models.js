(function () {
  "use strict";
  var D = window.MODEL_SCORECARD;
  if (!D) return;
  var M = D.meta;
  var NS = "http://www.w3.org/2000/svg";

  // ---- derived numbers -------------------------------------------------
  var models = D.models.map(function (m) {
    var passes = m.passed[0], scored = m.passed[1];
    var runs = scored / M.tasks;
    return Object.assign({}, m, {
      passes: passes, scored: scored, rate: scored ? passes / scored : 0,
      per_correct: passes ? (m.cost * runs) / passes : null,
      per_task: m.cost / M.tasks
    });
  });
  function tier(m) { return m.rate === 1 ? "top" : m.rate >= 0.85 ? "mid" : "low"; }
  // best first: complete runs, then pass rate, then cost at the precision the
  // table shows (a gap too small to print is a tie), then the faster model
  function shown(v) { return v == null ? Infinity : Number(v.toPrecision(2)); }
  function rank(a, b) {
    return (a.incomplete - b.incomplete) || (b.rate - a.rate) || (shown(a.cost) - shown(b.cost)) ||
           ((a.secs == null ? Infinity : a.secs) - (b.secs == null ? Infinity : b.secs));
  }
  function money(v) {
    if (v == null) return "—";
    if (v >= 100) return "$" + Math.round(v).toLocaleString("en-US");
    if (v >= 1) return "$" + v.toFixed(2);
    if (v >= 0.1) return "$" + v.toFixed(2);
    if (v >= 0.01) return "$" + v.toFixed(3);
    return "$" + v.toFixed(4);
  }
  function k(n) { return n >= 1000 ? (n / 1000).toFixed(n >= 100000 ? 0 : 1) + "k" : String(n); }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }

  // ---- summary chips ---------------------------------------------------
  var perfect = models.filter(function (m) { return m.rate === 1 && !m.incomplete; }).length;
  document.getElementById("mb-meta").innerHTML = [
    ["models attempted", M.models_attempted], ["scored", models.length], ["20/20", perfect],
    ["runs per model", M.runs + " × " + M.tasks + " tasks"], ["scored task-runs", M.scored_task_runs.toLocaleString("en-US")],
    ["unseen citations", M.unseen_citations], ["whole sweep", "$" + M.total_cost.toFixed(2)], ["measured", M.date]
  ].map(function (c) { return "<span><b>" + esc(c[1]) + "</b> " + esc(c[0]) + "</span>"; }).join("");

  // ---- shared chart bits -----------------------------------------------
  var FILL = { top: "var(--woad)", mid: "var(--surface)", low: "var(--muted)" };
  var STROKE = { top: "var(--surface)", mid: "var(--woad)", low: "var(--surface)" };
  function logScale(lo, hi, a, b) {
    var l0 = Math.log10(lo), l1 = Math.log10(hi);
    return function (v) { return a + (Math.log10(Math.max(v, lo)) - l0) / (l1 - l0) * (b - a); };
  }
  // the tip lives outside the chart's scroll area (which clips), positioned
  // against the card-level box; near the top edge it opens below the mark
  function tipper(svg, tip) {
    svg.addEventListener("pointerover", function (e) {
      var t = e.target.getAttribute && e.target.getAttribute("data-tip");
      if (!t) { tip.hidden = true; return; }
      var box = tip.parentElement.getBoundingClientRect(), c = e.target.getBoundingClientRect();
      tip.textContent = t; tip.hidden = false;
      var below = c.top - box.top < 44;
      tip.classList.toggle("below", below);
      tip.style.left = Math.min(Math.max(c.left + c.width / 2 - box.left, tip.offsetWidth / 2 + 4), box.width - tip.offsetWidth / 2 - 4) + "px";
      tip.style.top = (below ? c.bottom - box.top : c.top - box.top + 4) + "px";
    });
    svg.addEventListener("pointerleave", function () { tip.hidden = true; });
  }
  var COST_TICKS = [0.01, 0.03, 0.1, 0.3, 1, 3];

  // ---- strip: one row per pass count, dots placed by cost ---------------
  (function () {
    var svg = document.getElementById("mb-scatter");
    var groups = {};
    models.forEach(function (m) { var key = m.passes + "/" + m.scored; (groups[key] = groups[key] || []).push(m); });
    var keys = Object.keys(groups).sort(function (p, q) {
      var a = groups[p][0], b = groups[q][0]; return (b.rate - a.rate) || (b.scored - a.scored);
    });
    var W = 1100, L = 118, R = 24, T = 10, ROW = 40, B = 38;
    var H = T + keys.length * ROW + B;
    var x = logScale(0.005, 3, L, W - R);
    var out = [], axisY = T + keys.length * ROW;
    COST_TICKS.forEach(function (v) {
      out.push('<line style="stroke:var(--line);stroke-width:1" x1="' + x(v) + '" x2="' + x(v) + '" y1="' + T + '" y2="' + axisY + '"/>');
      out.push('<text style="fill:var(--muted);font:500 10.5px var(--f-mono)" x="' + x(v) + '" y="' + (axisY + 16) + '" text-anchor="middle">' + money(v).replace(/0+$/, "").replace(/\.$/, "") + "</text>");
    });
    out.push('<text style="fill:var(--muted);font:500 10.5px var(--f-mono)" x="' + ((L + W - R) / 2) + '" y="' + (H - 4) + '" text-anchor="middle">cost of one four-task run (log scale) →</text>');
    var hits = [];
    keys.forEach(function (key, i) {
      var cy = T + i * ROW + ROW / 2, ms = groups[key].slice().sort(function (a, b) { return a.cost - b.cost; });
      out.push('<line style="stroke:var(--line);stroke-width:1" x1="' + L + '" x2="' + (W - R) + '" y1="' + (T + (i + 1) * ROW) + '" y2="' + (T + (i + 1) * ROW) + '"/>');
      out.push('<text style="fill:var(--ink-2);font:500 10.5px var(--f-mono)" x="' + (L - 12) + '" y="' + (cy + 4) + '" text-anchor="end">' + key + (ms[0].incomplete ? "*" : "") +
               '  <tspan style="fill:var(--muted);font:500 10.5px var(--f-mono)">(' + ms.length + ")</tspan></text>");
      var placed = [];
      ms.forEach(function (m) {
        var px = x(m.cost), dy = 0;
        [0, -9, 9, -18, 18].some(function (o) {
          if (!placed.some(function (p) { return p[1] === o && Math.abs(p[0] - px) < 10; })) { dy = o; return true; }
          return false;
        });
        placed.push([px, dy]);
        var t = tier(m);
        out.push('<circle cx="' + px + '" cy="' + (cy + dy) + '" r="4.5" style="fill:' + FILL[t] + ";stroke:" + STROKE[t] + ";stroke-width:" + (t === "mid" ? 2 : 1.5) + '"/>');
        hits.push('<circle style="fill:transparent" cx="' + px + '" cy="' + (cy + dy) + '" r="8" data-tip="' + esc(m.id + " · " + m.passes + "/" + m.scored + " · " + money(m.cost) + " a run") + '"/>');
      });
    });
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.innerHTML = out.join("") + hits.join("");
    tipper(svg, document.getElementById("mb-tip"));
  })();

  // ---- ranking: cost per correct answer ---------------------------------
  (function () {
    var svg = document.getElementById("mb-value");
    var ranked = models.filter(function (m) { return m.per_correct != null; })
      .sort(function (a, b) { return (shown(a.per_correct) - shown(b.per_correct)) || (b.rate - a.rate) || (a.secs - b.secs); });
    var none = models.filter(function (m) { return m.per_correct == null; });
    var W = 1100, L = 210, R = 70, T = 8, ROW = 18;
    var H = T + ranked.length * ROW + 34 + (none.length ? 18 : 0);
    var x = logScale(0.001, 1, L, W - R);
    var out = [], axisY = T + ranked.length * ROW + 4;
    [0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1].forEach(function (v) {
      out.push('<line style="stroke:var(--line);stroke-width:1" x1="' + x(v) + '" x2="' + x(v) + '" y1="' + T + '" y2="' + axisY + '"/>');
      out.push('<text style="fill:var(--muted);font:500 10.5px var(--f-mono)" x="' + x(v) + '" y="' + (axisY + 14) + '" text-anchor="middle">' + money(v).replace(/0+$/, "").replace(/\.$/, "") + "</text>");
    });
    ranked.forEach(function (m, i) {
      var cy = T + i * ROW + ROW / 2, t = tier(m);
      out.push('<text style="fill:var(--ink-2);font:500 10.5px var(--f-mono)" x="' + (L - 10) + '" y="' + (cy + 3.5) + '" text-anchor="end">' + (i + 1) + ". " + esc(m.name) + (m.incomplete ? "*" : "") + "</text>");
      out.push('<line x1="' + x(0.001) + '" x2="' + x(m.per_correct) + '" y1="' + cy + '" y2="' + cy + '" style="stroke:var(--line-2);stroke-width:2"/>');
      out.push('<circle cx="' + x(m.per_correct) + '" cy="' + cy + '" r="4.5" style="fill:' + FILL[t] + ";stroke:" + STROKE[t] + ";stroke-width:" + (t === "mid" ? 2 : 1.5) + '"/>');
      out.push('<text style="fill:var(--ink);font:600 10.5px var(--f-mono)" x="' + (x(m.per_correct) + 9) + '" y="' + (cy + 3.5) + '">' + money(m.per_correct) + "</text>");
      out.push('<rect style="fill:transparent" x="0" y="' + (cy - ROW / 2) + '" width="' + W + '" height="' + ROW + '" data-tip="' +
        esc(m.id + " · " + money(m.per_correct) + " per correct answer · " + m.passes + "/" + m.scored + " passed · " + money(m.cost) + " a run") + '"/>');
    });
    if (none.length) out.push('<text style="fill:var(--muted);font:500 10.5px var(--f-mono)" x="' + L + '" y="' + (axisY + 34) + '" text-anchor="start">no correct answers: ' + esc(none.map(function (m) { return m.name; }).join(", ")) + "</text>");
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.innerHTML = out.join("");
    tipper(svg, document.getElementById("mb-tip2"));
  })();

  // ---- speed × cost × reliability: time across, cost up, fill = result ----
  (function () {
    var svg = document.getElementById("mb-speed");
    if (!svg) return;
    var sets = {
      core: { rows: models, what: "four-task run" },
      ad: { rows: (D.ad ? D.ad.models : []).filter(function (m) { return m.secs != null; }).map(function (m) {
        return Object.assign({}, m, { passes: m.passed[0], scored: m.passed[1], rate: m.passed[1] ? m.passed[0] / m.passed[1] : 0 });
      }), what: "eight-audit run" }
    };
    var TIME_TICKS = [[15, "15 s"], [30, "30 s"], [60, "1 min"], [120, "2 min"], [300, "5 min"], [600, "10 min"], [1200, "20 min"]];
    function draw(view) {
      var S = sets[view];
      var W = 1100, L = 64, R = 24, T = 14, B = 44, H = 480;
      var x = logScale(12, 2000, L, W - R), y = logScale(0.005, 8, H - B, T);
      var out = [];
      TIME_TICKS.forEach(function (t) {
        out.push('<line style="stroke:var(--line);stroke-width:1" x1="' + x(t[0]) + '" x2="' + x(t[0]) + '" y1="' + T + '" y2="' + (H - B) + '"/>');
        out.push('<text style="fill:var(--muted);font:500 10.5px var(--f-mono)" x="' + x(t[0]) + '" y="' + (H - B + 16) + '" text-anchor="middle">' + t[1] + "</text>");
      });
      COST_TICKS.forEach(function (v) {
        out.push('<line style="stroke:var(--line);stroke-width:1" x1="' + L + '" x2="' + (W - R) + '" y1="' + y(v) + '" y2="' + y(v) + '"/>');
        out.push('<text style="fill:var(--muted);font:500 10.5px var(--f-mono)" x="' + (L - 8) + '" y="' + (y(v) + 3.5) + '" text-anchor="end">' + money(v).replace(/0+$/, "").replace(/\.$/, "") + "</text>");
      });
      out.push('<text style="fill:var(--muted);font:500 10.5px var(--f-mono)" x="' + ((L + W - R) / 2) + '" y="' + (H - 6) + '" text-anchor="middle">wall-clock time of one ' + S.what + ' (log scale) →</text>');
      out.push('<text style="fill:var(--muted);font:500 10.5px var(--f-mono)" x="' + (L + 10) + '" y="' + (H - B - 10) + '">← faster · ↓ cheaper</text>');
      var order = { low: 0, mid: 1, top: 2 }, hits = [];
      S.rows.slice().sort(function (a, b) { return order[tier(a)] - order[tier(b)]; }).forEach(function (m) {
        var t = tier(m), cx = x(m.secs), cy = y(m.cost);
        out.push('<circle cx="' + cx + '" cy="' + cy + '" r="5.5" style="fill:' + FILL[t] + ";stroke:" + STROKE[t] + ";stroke-width:" + (t === "mid" ? 2 : 1.5) + '"/>');
        hits.push('<circle style="fill:transparent" cx="' + cx + '" cy="' + cy + '" r="9" data-tip="' +
          esc(m.id + " · " + m.passes + "/" + m.scored + (m.incomplete ? " (partial)" : "") + " · " + money(m.cost) + " · " + Math.round(m.secs) + " s") + '"/>');
      });
      // name the models that passed everything; try right, left, above, below, and skip a label that would collide
      var boxes = S.rows.map(function (m) { var cx = x(m.secs), cy = y(m.cost); return [cx - 6, cy - 6, cx + 6, cy + 6]; });
      function free(r) { return r[0] > L && r[2] < W - R && r[1] > T + 14 && r[3] < H - B && !boxes.some(function (o) { return r[0] < o[2] && r[2] > o[0] && r[1] < o[3] && r[3] > o[1]; }); }
      S.rows.filter(function (m) { return tier(m) === "top" && !m.incomplete; }).sort(function (a, b) { return a.cost - b.cost; }).forEach(function (m) {
        var cx = x(m.secs), cy = y(m.cost), w = m.name.length * 6.1, h = 11;
        [[cx + 9, cy - h / 2, "start"], [cx - 9 - w, cy - h / 2, "end"], [cx - w / 2, cy - 9 - h, "middle"], [cx - w / 2, cy + 9, "middle"]].some(function (c) {
          var r = [c[0], c[1], c[0] + w, c[1] + h];
          if (!free(r)) return false;
          boxes.push(r);
          var tx = c[2] === "start" ? r[0] : c[2] === "end" ? r[2] : r[0] + w / 2;
          out.push('<text style="fill:var(--ink-2);font:500 10px var(--f-mono)" x="' + tx + '" y="' + (r[1] + 8.5) + '" text-anchor="' + c[2] + '">' + esc(m.name) + "</text>");
          return true;
        });
      });
      out.push('<text style="fill:var(--muted);font:500 10.5px var(--f-mono)" x="' + (L + 4) + '" y="' + (T + 4) + '" dominant-baseline="hanging">↑ cost of one ' + S.what + " (log scale)</text>");
      svg.setAttribute("viewBox", "0 0 " + W + " " + H);
      svg.innerHTML = out.join("") + hits.join("");
    }
    tipper(svg, document.getElementById("mb-tip3"));
    var btns = document.querySelectorAll("#mb-speed-view button");
    btns.forEach(function (b) {
      if (b.dataset.view === "ad" && !sets.ad.rows.length) b.hidden = true;
      b.addEventListener("click", function () {
        btns.forEach(function (o) { o.setAttribute("aria-pressed", String(o === b)); });
        draw(b.dataset.view);
      });
    });
    draw("core");
  })();

  // ---- table ---------------------------------------------------------------
  var tbody = document.querySelector("#mb-table tbody");
  var perday = document.getElementById("mb-perday");
  var search = document.getElementById("mb-search");
  var state = { key: "passed", dir: -1, filter: "all", q: "" };
  function val(m, key) {
    switch (key) {
      case "name": return m.id;
      case "passed": return (m.incomplete ? -1e6 : 0) + m.rate * 1000 - m.cost / 100;   // complete rows first, then pass rate, then cheaper
      case "exposure": case "lease": case "conflict": case "os":
        var t = m.tasks[key]; return t ? t[0] / t[1] : -1;
      case "monthly": return m.per_task;
      case "per_correct": return m.per_correct == null ? Infinity : m.per_correct;
      default: return m[key] == null ? Infinity : m[key];
    }
  }
  function cell(t) { return t ? t[0] + "/" + t[1] : "—"; }
  function render() {
    var n = Math.max(1, parseInt(perday.value, 10) || 0);
    var q = state.q.trim().toLowerCase();
    var rows = models.filter(function (m) {
      if (q && m.id.toLowerCase().indexOf(q) < 0) return false;
      if (state.filter === "perfect") return m.rate === 1 && !m.incomplete;
      if (state.filter === "cheap") return m.cost < 0.05;
      return true;
    }).sort(function (a, b) {
      if (state.key === "passed") return rank(a, b) * -state.dir;
      var va = val(a, state.key), vb = val(b, state.key);
      if (va < vb) return -state.dir; if (va > vb) return state.dir; return 0;
    });
    tbody.innerHTML = rows.length ? rows.map(function (m) {
      var notes = [];
      if (m.note) notes.push(m.invented ? '<span class="mb-warn">' + esc(m.note) + "</span>" : esc(m.note));
      if (m.released) notes.push("released " + m.released);
      return "<tr>" +
        "<td>" + esc(m.name) + "<small>" + esc(m.vendor) + "</small></td>" +
        '<td class="num"><span class="mb-pass"><span class="mb-bar" aria-hidden="true"><i style="width:' + Math.round(m.rate * 100) + '%"></i></span>' +
          m.passes + "/" + m.scored + (m.incomplete ? "*" : "") + "</span></td>" +
        '<td class="num">' + cell(m.tasks.exposure) + "</td><td class=\"num\">" + cell(m.tasks.lease) + "</td>" +
        '<td class="num">' + cell(m.tasks.conflict) + "</td><td class=\"num\">" + cell(m.tasks.os) + "</td>" +
        '<td class="num">' + money(m.cost) + "</td>" +
        '<td class="num">' + money(m.per_correct) + "</td>" +
        '<td class="num">' + money(m.per_task * n * 30) + "</td>" +
        '<td class="num">' + Math.round(m.secs) + " s</td>" +
        '<td class="num">' + m.steps + "</td>" +
        '<td class="num">' + k(m.tok_in) + " / " + k(m.tok_out) + "</td>" +
        '<td class="num">' + (m.price_in == null ? "—" : "$" + m.price_in.toFixed(2) + " · $" + m.price_out.toFixed(2)) + "</td>" +
        "<td>" + notes.join(" · ") + "</td></tr>";
    }).join("") : '<tr class="mb-empty"><td colspan="14">No model matches that filter.</td></tr>';
    document.querySelectorAll("#mb-table th[data-sort]").forEach(function (th) {
      th.setAttribute("aria-sort", th.dataset.sort === state.key ? (state.dir > 0 ? "ascending" : "descending") : "none");
    });
  }
  document.querySelectorAll("#mb-table th[data-sort]").forEach(function (th) {
    th.tabIndex = 0;
    function go() {
      var key = th.dataset.sort;
      if (state.key === key) state.dir = -state.dir;
      else { state.key = key; state.dir = (key === "passed" || ["exposure", "lease", "conflict", "os"].indexOf(key) >= 0) ? -1 : 1; }
      render();
    }
    th.addEventListener("click", go);
    th.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
  });
  document.querySelectorAll(".mb-controls .mb-chip").forEach(function (b) {
    b.addEventListener("click", function () {
      state.filter = b.dataset.filter;
      document.querySelectorAll(".mb-controls .mb-chip").forEach(function (o) { o.setAttribute("aria-pressed", String(o === b)); });
      render();
    });
  });
  search.addEventListener("input", function () { state.q = search.value; render(); });
  perday.addEventListener("input", render);
  render();
})();

(function () {
  "use strict";
  var D = window.MODEL_SCORECARD;
  if (!D || !D.ad) return;
  var A = D.ad, TASKS = A.tasks;
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); }
  function money(v) { return v == null ? "—" : v >= 1 ? "$" + v.toFixed(2) : v >= 0.01 ? "$" + v.toFixed(3) : "$" + v.toFixed(4); }
  var rows = A.models.map(function (m) {
    return Object.assign({}, m, { rate: m.passed[1] ? m.passed[0] / m.passed[1] : 0 });
  });
  // best first: complete runs, then pass rate, then cost at the precision the
  // table shows (a gap too small to print is a tie), then the faster model
  function shown(v) { return v == null ? Infinity : Number(v.toPrecision(2)); }
  function rank(a, b) {
    return (a.incomplete - b.incomplete) || (b.rate - a.rate) || (shown(a.cost) - shown(b.cost)) ||
           ((a.secs == null ? Infinity : a.secs) - (b.secs == null ? Infinity : b.secs));
  }
  var perfect = rows.filter(function (m) { return m.rate === 1 && !m.incomplete; }).length;
  function share(t) { return t && t[1] ? Math.round(100 * t[0] / t[1]) + "%" : "—"; }
  var T = A.totals || {};
  document.getElementById("ad-meta").innerHTML = [
    ["models", rows.length], ["perfect", perfect + " at " + (TASKS.length * A.runs) + "/" + (TASKS.length * A.runs)],
    ["runs per model", A.runs + " × " + TASKS.length + " audits"], ["accounts", A.forest.users.toLocaleString("en-US")],
    ["facts loaded", A.forest.observations.toLocaleString("en-US")],
    ["passed at 500k", share(T.xl_on)], ["at 10k", share(T.large_on)], ["500k, no named queries", share(T.xl_off)],
    ["whole sweep, all four", "$" + A.total_cost.toFixed(2)], ["measured", A.date]
  ].map(function (c) { return "<span><b>" + esc(c[1]) + "</b> " + esc(c[0]) + "</span>"; }).join("");
  var tbody = document.querySelector("#ad-table tbody");
  var state = { key: "passed", dir: -1 };
  function val(m, key) {
    if (key === "name") return m.id;
    if (key === "passed") return (m.incomplete ? -1e6 : 0) + m.rate * 1000 - m.cost / 100;   // partial runs rank last
    if (key === "passed_10k" || key === "passed_off") { var p = m[key]; return p && p[1] ? p[0] / p[1] : -1; }
    if (TASKS.indexOf(key) >= 0) { var t = m.tasks[key]; return t ? t[0] / t[1] : -1; }
    return m[key] == null ? Infinity : m[key];
  }
  function cell(t) { return t && t[1] ? t[0] + "/" + t[1] : "—"; }
  function render() {
    var sorted = rows.slice().sort(function (a, b) {
      if (state.key === "passed") return rank(a, b) * -state.dir;
      var va = val(a, state.key), vb = val(b, state.key);
      return va < vb ? -state.dir : va > vb ? state.dir : 0;
    });
    tbody.innerHTML = sorted.map(function (m) {
      return "<tr><td>" + esc(m.name) + (m.note ? ' <span title="' + esc(m.note) + '">†</span>' : "") + "<small>" + esc(m.vendor) + "</small></td>" +
        '<td class="num"><span class="mb-pass"><span class="mb-bar" aria-hidden="true"><i style="width:' + Math.round(m.rate * 100) + '%"></i></span>' +
        m.passed[0] + "/" + m.passed[1] + (m.incomplete ? "*" : "") + "</span></td>" +
        '<td class="num">' + cell(m.passed_10k) + "</td>" + '<td class="num">' + cell(m.passed_off) + "</td>" +
        TASKS.map(function (t) { return '<td class="num">' + cell(m.tasks[t]) + "</td>"; }).join("") +
        '<td class="num">' + money(m.cost) + "</td>" +
        '<td class="num">' + (m.secs == null ? "—" : Math.round(m.secs) + " s") + "</td></tr>";
    }).join("");
    document.querySelectorAll("#ad-table th[data-sort]").forEach(function (th) {
      th.setAttribute("aria-sort", th.dataset.sort === state.key ? (state.dir > 0 ? "ascending" : "descending") : "none");
    });
  }
  document.querySelectorAll("#ad-table th[data-sort]").forEach(function (th) {
    th.tabIndex = 0;
    function go() {
      var key = th.dataset.sort;
      if (state.key === key) state.dir = -state.dir;
      else { state.key = key; state.dir = (key === "passed" || key === "passed_10k" || key === "passed_off" || TASKS.indexOf(key) >= 0) ? -1 : 1; }
      render();
    }
    th.addEventListener("click", go);
    th.addEventListener("keydown", function (e) { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } });
  });
  render();
})();
