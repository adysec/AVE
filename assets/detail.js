/* ── 工具函数 ── */

function setStatus(text) {
  const el = document.getElementById("status");
  if (el) el.textContent = text;
}

function q(name) {
  return new URLSearchParams(location.search).get(name) || "";
}

function numField(text, key, fallback = 0) {
  const m = text.match(new RegExp(`^${key}\\s*=\\s*([0-9]+(?:\\.[0-9]+)?)`, "m"));
  return m ? Number(m[1]) : fallback;
}

/* 从 TOML 文本中提取单行/多行字符串字段 */
function textField(text, key, fallback = "") {
  const one = text.match(new RegExp(`^${key}\\s*=\\s*\"([^\"]*)\"`, "m"));
  if (one?.[1] !== undefined) return one[1];
  const multi = text.match(new RegExp(`^${key}\\s*=\\s*\"\"\"([\\s\\S]*?)\"\"\"`, "m"));
  if (multi?.[1] !== undefined) return multi[1].trim();
  return fallback;
}

/* 从 TOML 文本中提取数组字段（如 ["a","b"] 或 ["a"]） */
function listField(text, key) {
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

function severityClass(sev) {
  const s = (sev || "UNKNOWN").toUpperCase();
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].includes(s) ? s : "UNKNOWN";
}

function extractAveId(value) {
  const m = String(value || "").match(/AVE-\d{4}-\d+/i);
  return m ? m[0].toUpperCase() : "";
}

/* 从 aliases 数组中提取 CVE 编号 */
function extractCveId(toml) {
  const aliases = listField(toml, "aliases");
  for (const a of aliases) {
    if (/^CVE-\d{4}-\d+/i.test(a)) return a.toUpperCase();
  }
  return "无";
}

/* 生成链接列表 */
function addLinks(el, arr, labelFn) {
  el.innerHTML = "";
  if (!arr.length) {
    const p = document.createElement("p");
    p.textContent = "（无）";
    p.className = "empty-hint";
    el.appendChild(p);
    return;
  }
  for (const u of arr) {
    const a = document.createElement("a");
    a.href = u;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = labelFn ? labelFn(u) : u;
    el.appendChild(a);
  }
}

/* ── 从 TOML 中提取来源名称并显示为徽章 ── */
function renderSources(el, sources) {
  el.innerHTML = "";
  if (!sources.length) {
    el.textContent = "无";
    return;
  }
  for (const s of sources) {
    const span = document.createElement("span");
    span.className = "source-badge";
    span.textContent = s.toUpperCase();
    el.appendChild(span);
  }
}

/* ── 获取仓库资产索引 (PoC/EXP 文件) ── */
async function loadAssetIndex() {
  const resp = await fetch("assets/data/asset-index.json", { cache: "no-cache" });
  if (!resp.ok) throw new Error(`获取资产索引失败：HTTP ${resp.status}`);
  const data = await resp.json();

  const pocUrlsByAve = new Map();
  const expUrlsByAve = new Map();

  for (const [ave, paths] of Object.entries(data.poc || {})) {
    pocUrlsByAve.set(ave, paths.map(p => ({
      url: p,
      html: p,
      path: p,
    })));
  }
  for (const [ave, paths] of Object.entries(data.exp || {})) {
    expUrlsByAve.set(ave, paths.map(p => ({
      url: p,
      html: p,
      path: p,
    })));
  }

  return { pocUrlsByAve, expUrlsByAve };
}

/* ── 加载漏洞 TOML ── */
async function loadToml(fileName) {
  const safeName = fileName.endsWith(".toml") ? fileName : `${fileName}.toml`;

  let vulnPath = safeName;
  if (!vulnPath.includes('/')) {
    const yearMatch = vulnPath.match(/AVE-(\d{4})-/);
    if (yearMatch) vulnPath = `${yearMatch[1]}/${vulnPath}`;
  }

  const res = await fetch(`vulns/${vulnPath}`, { cache: "no-cache" });
  if (!res.ok) throw new Error(`获取 TOML 失败：HTTP ${res.status}`);
  const text = await res.text();
  return { text, raw: `vulns/${vulnPath}`, html: `vulns/${vulnPath}`, safeName };
}

/* ── 加载 PoC/EXP TOML 文件内容 ── */
async function loadAssetToml(path) {
  try {
    const res = await fetch(path, { cache: "no-cache" });
    if (!res.ok) return null;
    return await res.text();
  } catch {
    return null;
  }
}

/* 从 PoC TOML [info] 中提取名称和描述 */
function pocInfo(toml) {
  const name = textField(toml, "name", "");
  const desc = textField(toml, "description", "");
  const severity = textField(toml, "severity", "").toLowerCase();
  return { name, desc, severity };
}

/* ── 渲染页面 ── */
function render(toml, fileName, rawUrl, htmlUrl, assetIndex) {
  // ── 提取所有字段 ──
  const ave = textField(toml, "ave_id", fileName.replace(/\.toml$/i, ""));
  const cve = extractCveId(toml);
  const title = textField(toml, "title", ave);
  const desc = textField(toml, "description", "");
  const sev = severityClass(textField(toml, "severity", "UNKNOWN"));
  const score = numField(toml, "score", 0);
  const aliases = listField(toml, "aliases");
  const sources = listField(toml, "sources");
  const published = textField(toml, "published", "");
  const updated = textField(toml, "updated", "");
  const remediation = textField(toml, "remediation", "");
  const status = textField(toml, "status", "");
  const collectedAt = textField(toml, "collected_at", "");
  const refs = listField(toml, "urls");
  const pocUrlsFromToml = listField(toml, "poc_urls");
  const expUrlsFromToml = listField(toml, "exp_urls");

  const repoPocs = assetIndex.pocUrlsByAve.get(ave) || [];
  const repoExps = assetIndex.expUrlsByAve.get(ave) || [];

  // ── 头部信息 ──
  document.getElementById("detail-subtitle").textContent = `${ave} / ${cve}`;
  document.getElementById("d-ave").textContent = ave;
  const sevEl = document.getElementById("d-sev");
  sevEl.textContent = sev;
  sevEl.className = "severity " + sev;

  document.getElementById("d-title").textContent = title;
  document.getElementById("d-desc").textContent = desc;

  // ── 评分显示 ──
  const scoreEl = document.getElementById("d-score");
  scoreEl.textContent = String(score);
  scoreEl.className = "score-big " + sev.toLowerCase();
  document.getElementById("d-score-label").textContent = `/ 10  ${sev}`;

  // ── 元信息 ──
  document.getElementById("d-published").textContent = published || "-";
  document.getElementById("d-updated").textContent = updated || "-";
  document.getElementById("d-status").textContent = status || "-";
  document.getElementById("d-collected").textContent = collectedAt || "-";

  // ── 来源 ──
  renderSources(document.getElementById("d-sources"), sources);

  // ── 别名（含 CVE） ──
  const aliasEl = document.getElementById("d-aliases");
  aliasEl.innerHTML = "";
  if (aliases.length) {
    for (const a of aliases) {
      const span = document.createElement("span");
      span.className = "alias-tag";
      const isCve = /^CVE-\d{4}-\d+/i.test(a);
      if (isCve) span.classList.add("cve");
      span.textContent = a;
      aliasEl.appendChild(span);
    }
  } else {
    aliasEl.textContent = "无";
  }

  // ── 修复建议 ──
  const remEl = document.getElementById("d-remediation");
  remEl.textContent = remediation || "";

  // ── PoC/EXP 标记 ──
  const pocFlag = document.getElementById("d-poc");
  const expFlag = document.getElementById("d-exp");
  pocFlag.textContent = `PoC：${repoPocs.length ? repoPocs.length : "无"}`;
  expFlag.textContent = `EXP：${repoExps.length ? repoExps.length : "无"}`;
  pocFlag.className = "flag" + (repoPocs.length ? " yes" : "");
  expFlag.className = "flag" + (repoExps.length ? " yes" : "");

  // ── 如果 TOML 中声明了外部 PoC/EXP URL 也显示 ──
  if (pocUrlsFromToml.length) {
    addLinks(document.getElementById("d-poc-urls"), pocUrlsFromToml);
    document.getElementById("d-poc-urls-section").style.display = "";
  } else {
    document.getElementById("d-poc-urls-section").style.display = "none";
  }
  if (expUrlsFromToml.length) {
    addLinks(document.getElementById("d-exp-urls"), expUrlsFromToml);
    document.getElementById("d-exp-urls-section").style.display = "";
  } else {
    document.getElementById("d-exp-urls-section").style.display = "none";
  }

  // ── 仓库 PoC 资产 ──
  const pocSection = document.getElementById("d-repo-pocs");
  const pocContainer = document.getElementById("d-repo-poc-files");
  pocContainer.innerHTML = "";
  if (repoPocs.length) {
    pocSection.style.display = "";
    for (const entry of repoPocs) {
      const div = document.createElement("div");
      div.className = "asset-file";
      div.innerHTML = `<a href="asset.html?file=${encodeURIComponent(entry.path)}&type=poc" class="asset-link">${entry.path.replace(/^pocs\//, '')}</a> ` +
        `<a href="${entry.url}" target="_blank" rel="noopener noreferrer" class="asset-raw" title="查看原始内容">📄</a>`;
      // 异步加载 PoC TOML 摘要
      loadAssetToml(entry.url).then(tomlText => {
        if (tomlText) {
          const info = pocInfo(tomlText);
          if (info.name || info.desc) {
            const tip = document.createElement("p");
            tip.className = "asset-tip";
            tip.textContent = (info.name ? info.name + "：": "") + (info.desc || "");
            div.appendChild(tip);
          }
        }
      });
      pocContainer.appendChild(div);
    }
  } else {
    pocSection.style.display = "none";
  }

  // ── 仓库 EXP 资产 ──
  const expSection = document.getElementById("d-repo-exps");
  const expContainer = document.getElementById("d-repo-exp-files");
  expContainer.innerHTML = "";
  if (repoExps.length) {
    expSection.style.display = "";
    for (const entry of repoExps) {
      const div = document.createElement("div");
      div.className = "asset-file";
      div.innerHTML = `<a href="asset.html?file=${encodeURIComponent(entry.path)}&type=exp" class="asset-link">${entry.path.replace(/^exploits\//, '')}</a> ` +
        `<a href="${entry.url}" target="_blank" rel="noopener noreferrer" class="asset-raw" title="查看原始内容">📄</a>`;
      expContainer.appendChild(div);
    }
  } else {
    expSection.style.display = "none";
  }

  // ── 参考链接 ──
  addLinks(document.getElementById("d-refs"), refs);

  // ── 原始 TOML ──
  const rawLink = document.getElementById("d-raw");
  rawLink.href = htmlUrl;
  rawLink.dataset.raw = rawUrl;

  // ── 显示卡片 ──
  document.getElementById("detail-card").style.display = "block";
}

/* ── 启动 ── */
async function boot() {
  const file = q("file").trim();
  if (!file) {
    setStatus("缺少参数：file");
    return;
  }

  setStatus("正在拉取并解析 TOML ...");
  try {
    const assetIndex = await loadAssetIndex();
    const { text, raw, html, safeName } = await loadToml(file);
    render(text, safeName, raw, html, assetIndex);
    setStatus("已完成 TOML 解析。")
  } catch (e) {
    setStatus(`加载失败：${e.message}`);
  }
}

boot();
