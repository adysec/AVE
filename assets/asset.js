const GH = {
  owner: "adysec",
  repo: "AVE",
  branch: "main",
};

/* ── 工具函数 ── */

function setStatus(text) {
  const el = document.getElementById("status");
  if (el) el.textContent = text;
}

function q(name) {
  return new URLSearchParams(location.search).get(name) || "";
}

/* 从 TOML 文本中提取单行/多行字符串字段 */
function textField(text, key, fallback = "") {
  const one = text.match(new RegExp(`^${key}\\s*=\\s*"([^"]*)"`, "m"));
  if (one?.[1] !== undefined) return one[1];
  const multi = text.match(new RegExp(`^${key}\\s*=\\s*"""([\\s\\S]*?)"""`, "m"));
  if (multi?.[1] !== undefined) return multi[1].trim();
  return fallback;
}

/* 从 TOML 文本中提取数组字段 */
function listField(text, key) {
  const arrRe = new RegExp(`^${key}\\s*=\\s*\\[(.*?)\\]`, "ms");
  const oneRe = new RegExp(`^${key}\\s*=\\s*"([^"]+)"`, "m");
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

/* 从内联表 {key = "val", key2 = "val2"} 中提取值 */
function inlineTableField(text, key) {
  const m = text.match(new RegExp(`${key}\\s*=\\s*"([^"]*)"`));
  return m ? m[1] : "";
}

/* inlineTable 整体提取 */
function parseInlineTable(text) {
  const m = text.match(/\{([^}]*)\}/);
  if (!m) return {};
  const obj = {};
  const pairs = m[1].match(/(\w+)\s*=\s*"([^"]*)"/g);
  if (pairs) {
    for (const p of pairs) {
      const kv = p.match(/(\w+)\s*=\s*"([^"]*)"/);
      if (kv) obj[kv[1]] = kv[2];
    }
  }
  return obj;
}

function severityClass(sev) {
  const s = (sev || "UNKNOWN").toUpperCase();
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"].includes(s) ? s : "UNKNOWN";
}

/* ── 分段解析 TOML ── */

function parseSections(text) {
  // Split by section headers like [info], [poc], [[poc.requests]]
  const lines = text.split('\n');
  const sections = [];
  let current = null;

  for (const line of lines) {
    const headerMatch = line.match(/^\[{1,2}([^\]]+)\]{1,2}\s*$/);
    if (headerMatch) {
      if (current) sections.push(current);
      current = { header: headerMatch[1], type: headerMatch[0].startsWith('[[') ? 'array' : 'table', lines: [] };
    } else if (current) {
      current.lines.push(line);
    }
  }
  if (current) sections.push(current);

  return sections;
}

/* 将 [[poc.requests]] 和其后紧跟的 [[poc.requests.matchers]] 分组 */
function groupRequests(sections) {
  const requests = [];
  let currentReq = null;

  for (const sec of sections) {
    if (sec.header === 'poc.requests' || sec.header === 'exp.requests') {
      if (currentReq) requests.push(currentReq);
      currentReq = { header: sec.header, lines: sec.lines, matchers: [] };
    } else if ((sec.header === 'poc.requests.matchers' || sec.header === 'exp.requests.matchers') && currentReq) {
      currentReq.matchers.push(sec.lines.join('\n'));
    }
  }
  if (currentReq) requests.push(currentReq);

  return requests;
}

/* ── 渲染 ── */

function render(tomlText, filePath, type) {
  const sections = parseSections(tomlText);

  // 合并 [info] 段
  const infoSection = sections.find(s => s.header === 'info');
  const infoText = infoSection ? infoSection.lines.join('\n') : '';

  const id = textField(infoText, 'id', filePath.split('/').pop().replace(/\.toml$/i, ''));
  const name = textField(infoText, 'name', id);
  const desc = textField(infoText, 'description', '');
  const author = textField(infoText, 'author', '-');
  const severity = textField(infoText, 'severity', 'info');
  const tags = listField(infoText, 'tags');
  const vulnId = listField(infoText, 'vuln_id');

  // 合并 [poc] 或 [exp] 段
  const logicSection = sections.find(s => s.header === 'poc' || s.header === 'exp');
  const logicText = logicSection ? logicSection.lines.join('\n') : '';
  const logic = textField(logicText, 'logic', '-');

  // 提取请求
  const requests = groupRequests(sections);

  // ── 渲染 ──
  const typeLabel = type === 'exp' ? 'EXP' : 'PoC';
  document.getElementById('detail-subtitle').textContent = `${id} / ${typeLabel}`;
  document.getElementById('a-id').textContent = id;

  const sevEl = document.getElementById('a-sev');
  const sevUpper = severityClass(severity);
  sevEl.textContent = sevUpper;
  sevEl.className = 'severity ' + sevUpper;

  const badge = document.getElementById('a-type-badge');
  badge.textContent = typeLabel;
  badge.className = 'asset-type-badge ' + typeLabel.toLowerCase();

  document.getElementById('a-name').textContent = name;
  document.getElementById('a-desc').textContent = desc;
  document.getElementById('a-author').textContent = author;

  const tagsEl = document.getElementById('a-tags');
  tagsEl.innerHTML = '';
  if (tags.length) {
    for (const t of tags) {
      const span = document.createElement('span');
      span.className = 'tag-pill';
      span.textContent = t;
      tagsEl.appendChild(span);
    }
  } else {
    tagsEl.textContent = '-';
  }

  document.getElementById('a-logic').textContent = logic;

  const vulnEl = document.getElementById('a-vuln-id');
  vulnEl.innerHTML = '';
  if (vulnId.length) {
    for (const v of vulnId) {
      const span = document.createElement('span');
      span.className = 'alias-tag';
      if (/^CVE-\d{4}-\d+/i.test(v)) span.classList.add('cve');
      if (/^AVE-\d{4}-\d+/i.test(v)) {
        // Link to detail page
        const a = document.createElement('a');
        a.href = `detail.html?file=${v}`;
        a.className = 'alias-tag cve';
        a.textContent = v;
        vulnEl.appendChild(a);
        continue;
      }
      span.textContent = v;
      vulnEl.appendChild(span);
    }
  } else {
    vulnEl.textContent = '-';
  }

  // ── 请求列表 ──
  const reqContainer = document.getElementById('a-requests');
  reqContainer.innerHTML = '';

  if (!requests.length) {
    reqContainer.innerHTML = '<p class="empty-hint">无请求定义</p>';
  } else {
    for (let i = 0; i < requests.length; i++) {
      const req = requests[i];
      const reqText = req.lines.join('\n');
      const method = textField(reqText, 'method', 'GET');
      const path = textField(reqText, 'path', '/');
      const headersRaw = reqText.match(/\{[^}]*\}/);
      const headers = headersRaw ? parseInlineTable(headersRaw[0]) : {};

      const card = document.createElement('div');
      card.className = 'request-card';

      // 请求头
      const headerDiv = document.createElement('div');
      headerDiv.className = 'request-header';

      const methodSpan = document.createElement('span');
      methodSpan.className = 'req-method ' + method.toLowerCase();
      methodSpan.textContent = method;

      const pathSpan = document.createElement('span');
      pathSpan.className = 'req-path';
      pathSpan.textContent = path;

      const numSpan = document.createElement('span');
      numSpan.className = 'req-num';
      numSpan.textContent = `#${i + 1}`;

      headerDiv.append(methodSpan, pathSpan, numSpan);
      card.appendChild(headerDiv);

      // Headers
      const headerKeys = Object.keys(headers);
      if (headerKeys.length) {
        const hdrPre = document.createElement('pre');
        hdrPre.className = 'req-headers';
        hdrPre.textContent = headerKeys.map(k => `${k}: ${headers[k]}`).join('\n');
        card.appendChild(hdrPre);
      }

      // Matchers
      if (req.matchers.length) {
        const matcherTitle = document.createElement('div');
        matcherTitle.className = 'matcher-title';
        matcherTitle.textContent = '匹配规则';
        card.appendChild(matcherTitle);

        for (let j = 0; j < req.matchers.length; j++) {
          const mText = req.matchers[j];
          const mType = textField(mText, 'type', '-');
          const mPart = textField(mText, 'part', '');
          const mExpect = textField(mText, 'expect', 'true');
          const mWords = listField(mText, 'words');
          const mStatus = listField(mText, 'status');

          const mDiv = document.createElement('div');
          mDiv.className = 'matcher-item';

          const mTypeSpan = document.createElement('span');
          mTypeSpan.className = 'matcher-type ' + mType;
          mTypeSpan.textContent = mType;

          mDiv.appendChild(mTypeSpan);

          if (mPart) {
            const mPartSpan = document.createElement('span');
            mPartSpan.className = 'matcher-part';
            mPartSpan.textContent = mPart;
            mDiv.appendChild(mPartSpan);
          }

          if (mWords.length) {
            const mValSpan = document.createElement('span');
            mValSpan.className = 'matcher-value';
            mValSpan.textContent = mWords.join(', ');
            mDiv.appendChild(mValSpan);
          }

          if (mStatus.length) {
            const mValSpan = document.createElement('span');
            mValSpan.className = 'matcher-value';
            mValSpan.textContent = 'HTTP ' + mStatus.join(', ');
            mDiv.appendChild(mValSpan);
          }

          const mExpectSpan = document.createElement('span');
          mExpectSpan.className = 'matcher-expect ' + (mExpect === 'true' ? 'yes' : 'no');
          mExpectSpan.textContent = mExpect === 'true' ? '✓ 期望匹配' : '✗ 期望不匹配';
          mDiv.appendChild(mExpectSpan);

          card.appendChild(mDiv);
        }
      }

      reqContainer.appendChild(card);
    }
  }

  // ── 链接 ──
  const rawUrl = `https://raw.githubusercontent.com/${GH.owner}/${GH.repo}/${GH.branch}/${filePath}`;
  const htmlUrl = `https://github.com/${GH.owner}/${GH.repo}/blob/${GH.branch}/${filePath}`;

  document.getElementById('a-raw').href = rawUrl;
  document.getElementById('a-github').href = htmlUrl;

  document.getElementById('detail-card').style.display = 'block';
}

/* ── 启动 ── */
async function boot() {
  const file = q('file').trim();
  const type = q('type') || 'poc';

  if (!file) {
    setStatus('缺少参数：file');
    return;
  }

  setStatus('正在加载 PoC/EXP ...');

  const rawUrl = `https://raw.githubusercontent.com/${GH.owner}/${GH.repo}/${GH.branch}/${file}`;
  try {
    const res = await fetch(rawUrl, { cache: 'no-cache' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    render(text, file, type);
    setStatus('加载完成。');
  } catch (e) {
    setStatus(`加载失败：${e.message}`);
  }
}

boot();
