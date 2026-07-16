// ═══════════════════════════════════════════════════════════════════════════
// AVE 公开漏洞库 — 列表页面逻辑
// ═══════════════════════════════════════════════════════════════════════════

const PAGE_SIZE = 15;
const DATA_BASE = "assets/data";

const state = {
  page: 1,
  total: 0,
  totalPages: 1,
  loaded: false,
  keyword: "",
  severity: "",
  lastCards: [],
  sortKey: "published",
  sortDir: "desc",

  // ── Chunked static data path ──
  manifest: null,         // { total, pageSize, totalPages, generatedAt, version }
  searchIndex: null,      // compact entries (short keys) — v2 only
  expandedCards: null,    // expanded to full field names for display
  pageCache: {},          // Map<pageKey, fullCardArray> — lazy loaded
  useChunked: false,
  chunkedFailed: false,

  // ── Year-split data (version 3+) ──
  useYearSplit: false,
  yearsMeta: null,        // [{year, count, pages, indexSize}] from manifest
  yearIndices: {},        // { year: compactEntry[] } — lazy loaded per year
  yearIndexLoads: {},     // { year: Promise } — dedup concurrent loads
  currentYear: null,      // string like "2026" when browsing a year
  streamCancel: false,    // set true to abort in-flight streaming search
  searchResults: [],      // accumulated cards during global streaming search
  streamDone: 0,          // years completed in current stream
  streamTotal: 0,         // total years being searched

  // ── Fallback to GitHub API ──
  treeCache: null,
  treeCacheFailed: false,
  apiAssetIndex: null,
  apiAssetIndexFailed: false,
};

let loadToken = 0;

// ═══════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════

function enc(s) { return encodeURIComponent(s); }

function sevClass(s) {
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].includes(s) ? s : "UNKNOWN";
}

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"];

function setStatus(t) {
  const el = document.getElementById("status");
  if (el) el.textContent = t;
}

function showLoading(on) {
  const el = document.getElementById("spinner");
  if (el) el.style.display = on ? "inline-block" : "none";
}

function updateSearchMode(mode, label) {
  const el = document.getElementById("search-mode");
  if (!el) return;
  if (!mode) {
    el.textContent = "";
    el.className = "search-mode";
    return;
  }
  el.textContent = label || "";
  el.className = `search-mode ${mode === "year" ? "year-mode" : ""}`;
}

function debounce(fn, wait) {
  let timer = null;
  return (...args) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => fn(...args), wait);
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  URL state
// ═══════════════════════════════════════════════════════════════════════════

function saveUrlState() {
  const params = new URLSearchParams();
  if (state.keyword) params.set("q", state.keyword);
  if (state.severity) params.set("sev", state.severity);
  if (state.page > 1) params.set("p", String(state.page));
  const str = params.toString();
  const url = str ? `?${str}` : window.location.pathname;
  history.replaceState(null, "", url);
}

function restoreUrlState() {
  const params = new URLSearchParams(location.search);
  return {
    keyword: params.get("q") || "",
    severity: params.get("sev") || "",
    page: parseInt(params.get("p") || "1", 10),
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  Sort
// ═══════════════════════════════════════════════════════════════════════════

function updateSortIndicators() {
  document.querySelectorAll("[data-sort-key]").forEach((th) => {
    const arrow = th.querySelector(".sort-arrow");
    if (arrow) {
      arrow.textContent =
        th.dataset.sortKey === state.sortKey
          ? state.sortDir === "asc" ? " ▲" : " ▼"
          : "";
    }
  });
}

function sortCards(cards) {
  const key = state.sortKey;
  const dir = state.sortDir === "asc" ? 1 : -1;
  return [...cards].sort((a, b) => {
    let va = a[key], vb = b[key];

    if (key === "published" || key === "updated") {
      const da = va ? new Date(va).getTime() : 0;
      const db = vb ? new Date(vb).getTime() : 0;
      const diff = (da - db) * dir;
      if (diff !== 0) return diff;
      return b.ave_id.localeCompare(a.ave_id);
    }

    if (va == null) va = "";
    if (vb == null) vb = "";
    if (typeof va === "string") va = va.toLowerCase();
    if (typeof vb === "string") vb = vb.toLowerCase();
    if (va < vb) return -1 * dir;
    if (va > vb) return 1 * dir;
    return b.ave_id.localeCompare(a.ave_id);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  Render
// ═══════════════════════════════════════════════════════════════════════════

function renderSeverityBar(cards) {
  const el = document.getElementById("sev-bar");
  if (!el) return;
  const counts = {};
  SEV_ORDER.forEach(s => counts[s] = 0);
  let total = 0;
  for (const c of cards) {
    const s = sevClass(c.severity);
    counts[s] = (counts[s] || 0) + 1;
    total++;
  }
  if (!total) { el.innerHTML = ''; return; }
  let html = '<div class="sev-bar">';
  SEV_ORDER.forEach(s => {
    if (!counts[s]) return;
    const pct = (counts[s] / total * 100).toFixed(1);
    html += `<span class="sev-bar-seg ${s.toLowerCase()}" style="width:${pct}%" title="${s}: ${counts[s]} (${pct}%)"></span>`;
  });
  html += '</div><div class="sev-legend">';
  SEV_ORDER.forEach(s => {
    if (!counts[s]) return;
    html += `<span class="sev-legend-item"><span class="sev-dot ${s.toLowerCase()}"></span>${s} ${counts[s]}</span>`;
  });
  html += '</div>';
  el.innerHTML = html;
}

function renderError(msg) {
  const tbody = document.getElementById("list-body");
  if (tbody) tbody.innerHTML = "";
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = 9;
  td.className = "table-empty";
  td.style.color = "#fca5a5";
  td.textContent = msg;
  tr.appendChild(td);
  if (tbody) tbody.appendChild(tr);
  document.getElementById("page-info").textContent = "第 0 / 0 页（共 0 条）";
  document.getElementById("prev-page").disabled = true;
  document.getElementById("next-page").disabled = true;
}

function renderPager() {
  document.getElementById("page-info").textContent = `第 ${state.page} / ${state.totalPages} 页（共 ${state.total} 条）`;
  document.getElementById("prev-page").disabled = state.page <= 1;
  document.getElementById("next-page").disabled = state.page >= state.totalPages;
  const pageInput = document.getElementById("page-input");
  if (pageInput) {
    pageInput.value = state.page;
    pageInput.max = state.totalPages;
    pageInput.disabled = state.totalPages <= 1;
  }
}

function renderList(cards) {
  const tbody = document.getElementById("list-body");
  tbody.innerHTML = "";

  if (!cards.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 8;
    td.className = "table-empty";
    td.textContent = "当前条件下没有结果";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const c of cards) {
    const tr = document.createElement("tr");

    const aveTd = document.createElement("td");
    aveTd.textContent = c.ave_id;

    const titleTd = document.createElement("td");
    titleTd.className = "table-title";
    titleTd.title = c.title || "";
    titleTd.textContent = c.title || c.ave_id;

    const sevTd = document.createElement("td");
    const sev = document.createElement("span");
    sev.className = `severity ${sevClass(c.severity)}`;
    sev.textContent = c.severity;
    sevTd.appendChild(sev);

    const dateTd = document.createElement("td");
    dateTd.className = "table-date";
    dateTd.textContent = c.published || c.updated || "-";

    const scoreTd = document.createElement("td");
    scoreTd.textContent = String(c.score ?? 0);

    const pocTd = document.createElement("td");
    const pocFlag = document.createElement("span");
    pocFlag.className = "flag";
    pocFlag.textContent = c.has_poc ? "有" : "无";
    if (c.has_poc) pocFlag.classList.add("yes");
    pocTd.appendChild(pocFlag);

    const expTd = document.createElement("td");
    const expFlag = document.createElement("span");
    expFlag.className = "flag";
    expFlag.textContent = c.has_exp ? "有" : "无";
    if (c.has_exp) expFlag.classList.add("yes");
    expTd.appendChild(expFlag);

    const actionTd = document.createElement("td");
    actionTd.className = "table-action";
    const detailLink = document.createElement("a");
    detailLink.className = "detail-link";
    detailLink.href = `detail.html?file=${encodeURIComponent(c.file_name)}`;
    detailLink.target = "_blank";
    detailLink.rel = "noopener noreferrer";
    detailLink.textContent = "查看详情";
    actionTd.appendChild(detailLink);

    tr.className = `sev-row ${sevClass(c.severity).toLowerCase()}`;
    tr.append(aveTd, titleTd, sevTd, dateTd, scoreTd, pocTd, expTd, actionTd);
    tbody.appendChild(tr);
  }
}

function filterBySeverity(cards) {
  if (!state.severity) return cards;
  return cards.filter((c) => c.severity === state.severity);
}

// ═══════════════════════════════════════════════════════════════════════════
//  Compact index ↔ display card conversion
// ═══════════════════════════════════════════════════════════════════════════
// search-index.json uses single-char keys for compactness:
//   a=ave_id c=cve_id t=title s=severity p=score d=published
//   f=file_name r=raw_url o=has_poc e=has_exp

function expandIndexEntry(e) {
  return {
    ave_id: e.a,
    cve_id: e.c || "无",
    title: e.t || e.a,
    severity: e.s || "UNKNOWN",
    score: e.p ?? 0,
    published: e.d || "",
    file_name: e.f || "",
    raw_url: e.r || "",
    has_poc: e.o === 1,
    has_exp: e.e === 1,
    // Fields that renderList accesses but aren't in compact index:
    updated: "",
    description: "",
    aliases: [],
    sources: [],
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  Year-split index helpers (version 3+)
// ═══════════════════════════════════════════════════════════════════════════
// Per-year indices use array format for compactness:
//   [0]=ave_id [1]=cve_id [2]=title [3]=severity [4]=score
//   [5]=published [6]=has_poc [7]=has_exp
// file_name and raw_url are derivable from ave_id.

function inferFileName(aveId) {
  const p = aveId.split("-");
  return p.length === 3 ? `${p[1]}/${aveId}.toml` : `${aveId}.toml`;
}

function expandYearEntry(arr) {
  return {
    ave_id: arr[0],
    cve_id: arr[1] || "无",
    title: arr[2] || arr[0],
    severity: arr[3] || "UNKNOWN",
    score: arr[4] ?? 0,
    published: arr[5] || "",
    has_poc: arr[6] === 1,
    has_exp: arr[7] === 1,
    file_name: inferFileName(arr[0]),
    raw_url: `vulns/${inferFileName(arr[0])}`,
    updated: "",
    description: "",
    aliases: [],
    sources: [],
  };
}

function matchCompactEntry(arr, keyword, severity) {
  if (keyword) {
    const kw = keyword.toLowerCase();
    const match = arr[0].toLowerCase().includes(kw) ||
      (arr[1] || "").toLowerCase().includes(kw) ||
      (arr[2] || "").toLowerCase().includes(kw);
    if (!match) return false;
  }
  if (severity && arr[3] !== severity) return false;
  return true;
}

// ═══════════════════════════════════════════════════════════════════════════
//  Static asset index (PoC/EXP per AVE ID)
// ═══════════════════════════════════════════════════════════════════════════

function extractAveId(value) {
  const m = String(value || "").match(/AVE-\d{4}-\d+/i);
  return m ? m[0].toUpperCase() : "";
}

function getRepoAssetUrls(index, aveId, type) {
  if (!index || !aveId) return [];
  if (type === "poc") return index.pocUrlsByAve.get(aveId) || [];
  if (type === "exp") return index.expUrlsByAve.get(aveId) || [];
  return [];
}

async function ensureApiAssetIndex() {
  if (state.apiAssetIndex) return state.apiAssetIndex;
  if (state.apiAssetIndexFailed) return null;

  try {
    const resp = await fetch(`${DATA_BASE}/asset-index.json`);
    if (!resp.ok) throw new Error(`asset-index.json HTTP ${resp.status}`);
    const data = await resp.json();

    const pocUrlsByAve = new Map();
    const expUrlsByAve = new Map();

    for (const [ave, paths] of Object.entries(data.poc || {})) {
      pocUrlsByAve.set(ave, paths);
    }
    for (const [ave, paths] of Object.entries(data.exp || {})) {
      expUrlsByAve.set(ave, paths);
    }

    state.apiAssetIndex = { pocUrlsByAve, expUrlsByAve };
    return state.apiAssetIndex;
  } catch (e) {
    state.apiAssetIndexFailed = true;
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Card builder (fallback: TOML regex → card)
// ═══════════════════════════════════════════════════════════════════════════

function severityFromToml(text) {
  const m = text.match(/^severity\s*=\s*"([A-Za-z]+)"/m);
  return (m?.[1] || "UNKNOWN").toUpperCase();
}

function scoreFromToml(text) {
  const m = text.match(/^score\s*=\s*([0-9]+(?:\.[0-9]+)?)/m);
  return m ? Number(m[1]) : 0;
}

function titleFromToml(text, fallback) {
  const m = text.match(/^title\s*=\s*"([^"]*)"/m);
  return m?.[1] || fallback;
}

function descFromToml(text) {
  const m = text.match(/^description\s*=\s*"([^"]*)"/m);
  if (m?.[1]) return m[1];
  const ml = text.match(/^description\s*=\s*"""([\s\S]*?)"""/m);
  return ml?.[1]?.trim() || "";
}

function linksFromToml(text, key) {
  const arrRe = new RegExp(`^${key}\\s*=\\s*\\[(.*?)\\]`, "ms");
  const oneRe = new RegExp(`^${key}\\s*=\\s*\"([^\"]+)\"`, "m");
  const one = text.match(oneRe);
  if (one?.[1]) return [one[1]];
  const arr = text.match(arrRe);
  if (!arr?.[1]) return [];
  const out = [];
  const strRe = /"([^"]+)"/g;
  let m;
  while ((m = strRe.exec(arr[1])) !== null) out.push(m[1]);
  return out;
}

function textField(text, key, fallback = "") {
  const one = text.match(new RegExp(`^${key}\\s*=\\s*\"([^\"]*)\"`, "m"));
  if (one?.[1] !== undefined) return one[1];
  const multi = text.match(new RegExp(`^${key}\\s*=\\s*\"\"\"([\\s\\S]*?)\"\"\"`, "m"));
  if (multi?.[1] !== undefined) return multi[1].trim();
  return fallback;
}

function listField(text, key) {
  return linksFromToml(text, key);
}

function extractCveId(text) {
  const aliases = listField(text, "aliases");
  for (const a of aliases) {
    if (/^CVE-\d{4}-\d+/i.test(a)) return a.toUpperCase();
  }
  return "无";
}

function getVulnRelPath(item) {
  if (item.path) return item.path.replace(/^vulns\//, '');
  if (item.rel_path) return item.rel_path;
  return item.name;
}

function toCard(item, text, assetIndex) {
  const ave = item.name.replace(/\.toml$/i, "");
  const cve = extractCveId(text);
  const pocs = linksFromToml(text, "poc_urls");
  const exps = linksFromToml(text, "exp_urls");
  const repoPocs = getRepoAssetUrls(assetIndex, ave, "poc");
  const repoExps = getRepoAssetUrls(assetIndex, ave, "exp");

  return {
    ave_id: ave,
    file_name: getVulnRelPath(item),
    cve_id: cve,
    title: titleFromToml(text, ave),
    description: descFromToml(text),
    severity: severityFromToml(text),
    score: scoreFromToml(text),
    aliases: listField(text, "aliases"),
    sources: listField(text, "sources"),
    published: textField(text, "published", ""),
    updated: textField(text, "updated", ""),
    remediation: textField(text, "remediation", ""),
    status: textField(text, "status", ""),
    collected_at: textField(text, "collected_at", ""),
    references: linksFromToml(text, "urls"),
    poc_urls: pocs,
    exp_urls: exps,
    repo_poc_urls: repoPocs,
    repo_exp_urls: repoExps,
    has_poc: repoPocs.length > 0,
    has_exp: repoExps.length > 0,
    raw_url: item.html_url,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  Chunked static data loading & search (version 2) + Year-split (version 3)
// ═══════════════════════════════════════════════════════════════════════════

async function initChunkedData() {
  try {
    const maniResp = await fetch(`${DATA_BASE}/manifest.json`);
    if (!maniResp.ok) throw new Error(`manifest.json HTTP ${maniResp.status}`);
    state.manifest = await maniResp.json();

    // Version 3+: year-split mode
    if (state.manifest.version >= 3 && state.manifest.years) {
      return await initYearSplit();
    }

    // Version 2: combined search-index.json
    state.total = state.manifest.total;
    state.totalPages = state.manifest.totalPages;
    const idxResp = await fetch(`${DATA_BASE}/search-index.json`);
    if (!idxResp.ok) throw new Error(`search-index.json HTTP ${idxResp.status}`);
    const rawIndex = await idxResp.json();
    state.searchIndex = rawIndex;
    state.expandedCards = rawIndex.map(expandIndexEntry);
    state.useChunked = true;
    console.log(`[AVE] v2 分块数据加载成功：${state.total} 条`);
    return true;
  } catch (e) {
    console.warn("[AVE] 分块数据加载失败：", e.message);
    state.useChunked = false;
    state.chunkedFailed = true;
    return false;
  }
}

async function initYearSplit() {
  state.useYearSplit = true;
  state.useChunked = true;
  state.yearsMeta = state.manifest.years;
  state.total = state.manifest.total;
  state.totalPages = state.manifest.totalPages;

  // Select default year (most recent)
  const defaultYear = state.manifest.defaultYear || (state.yearsMeta[0]?.year || "");
  state.currentYear = defaultYear;

  // Load default year's index + first page
  await switchYear(defaultYear);

  // Preload next 2 most recent years in background
  const recentYears = state.yearsMeta.slice(1, 3).map(y => y.year);
  for (const y of recentYears) {
    loadYearIndex(y).catch(() => {});
  }

  console.log(`[AVE] v3 年份分片加载成功：${state.total} 条，${state.yearsMeta.length} 年`);
  return true;
}

async function loadYearIndex(year) {
  // Dedup concurrent loads
  if (state.yearIndexLoads[year]) return state.yearIndexLoads[year];
  if (state.yearIndices[year]) return state.yearIndices[year];

  state.yearIndexLoads[year] = (async () => {
    const resp = await fetch(`${DATA_BASE}/index/${year}.json`);
    if (!resp.ok) throw new Error(`index/${year}.json HTTP ${resp.status}`);
    const entries = await resp.json();
    state.yearIndices[year] = entries;
    return entries;
  })();

  try {
    return await state.yearIndexLoads[year];
  } finally {
    delete state.yearIndexLoads[year];
  }
}

async function switchYear(year) {
  // Cancel any in-flight streaming search
  state.streamCancel = true;
  await new Promise(r => setTimeout(r, 10));
  state.streamCancel = false;

  state.currentYear = year;
  state.keyword = "";
  state.severity = "";

  setStatus(`正在加载 ${year} 年数据...`);

  const entries = await loadYearIndex(year);
  state.expandedCards = entries.map(expandYearEntry);
  state.total = state.expandedCards.length;
  state.totalPages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
  state.page = 1;

  runPageChunked(1);
  updateYearTabs(year);
  updateSearchMode("year", `📅 ${year}年`);
  setStatus(`📅 浏览 ${year} 年：共 ${state.total} 条`);
}

// ── Streaming search across all years ──

let streamIdCounter = 0;

async function streamSearch(keyword, severity) {
  // Cancel previous stream
  state.streamCancel = true;
  await new Promise(r => setTimeout(r, 10));
  state.streamCancel = false;

  const myId = ++streamIdCounter;
  state.currentYear = null;
  state.searchResults = [];
  state.expandedCards = [];
  state.streamDone = 0;
  state.streamTotal = state.yearsMeta.length;
  updateSearchMode("global", "🌐 跨年搜索");

  const years = state.yearsMeta;
  const BATCH = 6; // concurrent year loads

  setStatus(`正在搜索全部年份... 0/${state.streamTotal} 年`);
  showLoading(true);

  for (let i = 0; i < years.length && !state.streamCancel; i += BATCH) {
    const batch = years.slice(i, i + BATCH);
    await Promise.all(batch.map(y => loadYearIndex(y.year)));

    for (const y of batch) {
      if (state.streamCancel || myId !== streamIdCounter) return;
      const entries = state.yearIndices[y.year];
      if (!entries) { state.streamDone++; continue; }

      const filtered = entries.filter(arr => matchCompactEntry(arr, keyword, state.severity));
      state.searchResults.push(...filtered.map(expandYearEntry));
      state.streamDone++;
    }

    // Re-render with accumulated results (if on page 1)
    const wasPage1 = state.page <= 1;
    state.expandedCards = [...state.searchResults];
    state.total = state.expandedCards.length;
    state.totalPages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));

    if (wasPage1) {
      const start = 0;
      const pageCards = sortCards(state.expandedCards).slice(start, start + PAGE_SIZE);
      state.lastCards = pageCards;
      state.loaded = true;
      state.page = 1;
      renderList(pageCards);
      renderSeverityBar(state.expandedCards);
    }
    renderPager();
    updateSortIndicators();
    showLoading(false);

    setStatus(`🔍 搜索中... ${state.streamDone}/${state.streamTotal} 年 (已找到 ${state.expandedCards.length} 条)`);
  }

  if (!state.streamCancel && myId === streamIdCounter) {
    state.streamDone = state.streamTotal;
    state.expandedCards = [...state.searchResults];
    saveUrlState();
    setStatus(`✅ 搜索完成：共 ${state.expandedCards.length} 条 (${state.streamTotal} 年)`);
    // Keep search mode indicator
  }
}

// ── Year tabs rendering ──

function updateYearTabs(activeYear) {
  const container = document.getElementById("year-tabs");
  if (!container || !state.yearsMeta) return;

  container.innerHTML = state.yearsMeta.map(y =>
    `<button class="year-tab${y.year === activeYear ? " active" : ""}" data-year="${y.year}">
      ${y.year}<span class="year-count">${y.count}</span>
    </button>`
  ).join("");

  // Fill stats table
  const stats = document.getElementById("year-stats");
  if (stats) {
    let rows = state.yearsMeta.map(y =>
      `<tr${y.year === activeYear ? ' class="active"' : ""} data-year="${y.year}">
        <td>${y.year}</td>
        <td class="num">${y.count}</td>
        <td class="num">${y.pages}</td>
      </tr>`
    ).join("");
    const total = state.yearsMeta.reduce((s, y) => s + y.count, 0);
    const totalPages = state.yearsMeta.reduce((s, y) => s + y.pages, 0);
    stats.innerHTML =
      `<table class="year-table">
        <thead><tr><th>年份</th><th class="num">漏洞</th><th class="num">页</th></tr></thead>
        <tbody>${rows}</tbody>
        <tfoot><tr class="total"><td>合计</td><td class="num">${total}</td><td class="num">${totalPages}</td></tr></tfoot>
      </table>`;
  }
}

function filterCardsLocally(keyword, severity) {
  const all = state.expandedCards;
  if (!all) return [];

  const kw = (keyword || "").trim().toLowerCase();
  let filtered = all;

  if (kw) {
    filtered = all.filter((c) =>
      c.ave_id.toLowerCase().includes(kw) ||
      c.cve_id.toLowerCase().includes(kw) ||
      (c.title && c.title.toLowerCase().includes(kw)) ||
      (c.description && c.description.toLowerCase().includes(kw)) ||
      (c.aliases && c.aliases.some(a => a.toLowerCase().includes(kw)))
    );
  }

  if (severity) {
    filtered = filtered.filter((c) => c.severity === severity);
  }

  return filtered;
}

function runPageChunked(page) {
  const filtered = filterCardsLocally(state.keyword, state.severity);

  state.total = filtered.length;
  state.totalPages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
  state.page = Math.max(1, Math.min(page, state.totalPages));

  const start = (state.page - 1) * PAGE_SIZE;
  const pageCards = sortCards(filtered).slice(start, start + PAGE_SIZE);

  state.lastCards = pageCards;
  state.loaded = true;

  renderList(pageCards);
  renderPager();
  renderSeverityBar(filtered);
  updateSortIndicators();
  saveUrlState();
  showLoading(false);

  let src;
  if (state.useYearSplit) {
    src = state.currentYear ? `📅 ${state.currentYear}` : "🔍 全局搜索";
  } else {
    src = state.keyword ? "本地搜索" : "全部数据";
  }
  setStatus(`已显示第 ${state.page} / ${state.totalPages} 页（共 ${state.total} 条），来源：${src}。`);

  // Background: prefetch current data page for future detail views
  lazyCachePage(state.page);
}

async function lazyCachePage(pageNum) {
  const year = state.useYearSplit ? state.currentYear : null;
  const key = year ? `${year}/${pageNum}` : String(pageNum);
  if (state.pageCache[key]) return;
  try {
    const path = year
      ? `${DATA_BASE}/pages/${year}/${pageNum}.json`
      : `${DATA_BASE}/pages/${pageNum}.json`;
    const resp = await fetch(path);
    if (resp.ok) {
      state.pageCache[key] = await resp.json();
    }
  } catch { /* ignore prefetch failures */ }
}

// ═══════════════════════════════════════════════════════════════════════════
//  API-based page loading (fallback — static data only)
// ═══════════════════════════════════════════════════════════════════════════

async function runPageApi(page) {
  const token = ++loadToken;
  state.page = Math.max(1, page);
  state.loaded = false;
  showLoading(true);
  setStatus("静态数据加载失败，无法获取列表。");

  showLoading(false);
  renderError("⚠ 静态数据加载失败，请刷新页面重试。");
  setStatus("静态数据加载失败，请刷新页面重试。");
}

// ═══════════════════════════════════════════════════════════════════════════
//  Unified runPage
// ═══════════════════════════════════════════════════════════════════════════

function runPage(page) {
  if (state.useYearSplit && state.currentYear) {
    runPageChunked(page);
  } else if (state.useChunked && state.expandedCards) {
    runPageChunked(page);
  } else {
    runPageApi(page);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Boot
// ═══════════════════════════════════════════════════════════════════════════

async function boot() {
  // ── Load chunked static data ──
  setStatus("正在加载漏洞数据...");
  const dataOk = await initChunkedData();

  if (!dataOk) {
    // Fallback: try to fetch old vuln-data.js (deprecated)
    if (typeof VULN_DATA !== "undefined" && VULN_DATA.cards && VULN_DATA.cards.length) {
      state.expandedCards = VULN_DATA.cards;
      state.useChunked = true;
      state.total = VULN_DATA.total || VULN_DATA.cards.length;
      state.totalPages = Math.max(1, Math.ceil(state.total / PAGE_SIZE));
      console.log(`[AVE] 使用旧版 vuln-data.js：${state.total} 条`);
    }
  }

  // ── Restore URL state ──
  const urlState = restoreUrlState();
  state.keyword = urlState.keyword;
  state.severity = urlState.severity;

  // ── Collapse project-intro on small screens ──
  const intro = document.getElementById("project-intro");
  if (intro && window.innerWidth < 480) intro.removeAttribute("open");

  // ── DOM refs ──
  const searchInput = document.getElementById("search");
  const severityInput = document.getElementById("severity");
  const searchBtn = document.getElementById("search-btn");
  const prev = document.getElementById("prev-page");
  const next = document.getElementById("next-page");
  const pageInput = document.getElementById("page-input");
  const jumpBtn = document.getElementById("jump-page");
  const yearTabs = document.getElementById("year-tabs");

  if (urlState.keyword) searchInput.value = urlState.keyword;
  if (urlState.severity) severityInput.value = urlState.severity;

  // ── Year tabs (version 3+) ──
  if (yearTabs && state.useYearSplit) {
    yearTabs.addEventListener("click", (e) => {
      const btn = e.target.closest(".year-tab");
      if (!btn) return;
      searchInput.value = "";
      severityInput.value = "";
      switchYear(btn.dataset.year);
    });
  }

  // ── Search ──
  const doSearch = debounce(() => {
    state.keyword = searchInput.value || "";
    state.severity = severityInput.value || "";

    if (state.useYearSplit) {
      if (state.keyword) {
        streamSearch(state.keyword, state.severity);
      } else {
        // No keyword → browse default year
        const target = state.currentYear || state.manifest.defaultYear;
        if (target) switchYear(target);
        else runPageChunked(1);
      }
    } else if (state.useChunked && state.expandedCards) {
      runPageChunked(1);
    } else {
      runPageApi(1);
    }
  }, 300);

  searchBtn.addEventListener("click", doSearch);
  searchInput.addEventListener("keydown", (e) => { if (e.key === "Enter") doSearch(); });

  // ── Severity filter ──
  severityInput.addEventListener("change", () => {
    if (!state.loaded) { setStatus("尚未加载列表，请先搜索。"); return; }
    state.severity = severityInput.value || "";
    state.keyword = searchInput.value || "";

    if (state.useYearSplit) {
      if (state.keyword) {
        streamSearch(state.keyword, state.severity);
      } else if (state.expandedCards) {
        runPageChunked(1);
      }
    } else if (state.useChunked && state.expandedCards) {
      runPageChunked(1);
    } else {
      doSearch();
    }
  });

  // ── Sort on header click ──
  document.querySelectorAll("[data-sort-key]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sortKey;
      if (state.sortKey === key) {
        state.sortDir = state.sortDir === "asc" ? "desc" : "asc";
      } else {
        state.sortKey = key;
        state.sortDir = "asc";
      }
      updateSortIndicators();
      if (state.loaded && state.lastCards.length) {
        if (state.useYearSplit || (state.useChunked && state.expandedCards)) {
          runPageChunked(state.page);
        } else {
          state.lastCards = sortCards(state.lastCards);
          renderList(filterBySeverity(state.lastCards));
        }
      }
    });
  });

  // ── Pagination ──
  prev.addEventListener("click", () => {
    if (!state.loaded) { setStatus("尚未加载列表，请先搜索。"); return; }
    runPage(state.page - 1);
  });

  next.addEventListener("click", () => {
    if (!state.loaded) { setStatus("尚未加载列表，请先搜索。"); return; }
    runPage(state.page + 1);
  });

  // ── Page jump ──
  function doJump() {
    if (!state.loaded) { setStatus("尚未加载列表，请先搜索。"); return; }
    if (!state.totalPages || state.totalPages <= 1) return;
    const val = parseInt(pageInput.value, 10);
    if (isNaN(val) || val < 1 || val > state.totalPages) {
      pageInput.value = state.page;
      setStatus(`页号超出范围（1 ~ ${state.totalPages}）`);
      return;
    }
    runPage(val);
  }

  jumpBtn.addEventListener("click", doJump);
  pageInput.addEventListener("keydown", (e) => { if (e.key === "Enter") doJump(); });

  renderPager();
  updateSortIndicators();

  // ── Load initial page ──
  if (state.useYearSplit && state.loaded) {
    // initYearSplit already loaded default year; just handle URL override
    if (urlState.keyword) {
      streamSearch(urlState.keyword, urlState.severity || "");
    } else if (urlState.page > 1) {
      runPageChunked(urlState.page);
    }
  } else {
    runPage(urlState.page);
  }
}

boot();
