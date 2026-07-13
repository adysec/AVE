# AVE 多源漏洞聚合引擎

> **AVE** 的多重含义：

| 含义 | 中文 | 说明 |
|------|------|------|
| AdySec Vulnerability Exposures | AdySec 漏洞披露 | 项目归属 |
| AI-powered Vulnerability Engine | AI 驱动漏洞引擎 | 核心方法 |
| Automated Vulnerability Extractor | 全自动漏洞提取 | 无人值守 |

Description: AVE 是面向安全运营的多源漏洞知识库，统一 AVE 编号并输出结构化 TOML，同时整理和校验公开 PoC/EXP 资产，支持按严重等级快速筛选高价值漏洞。漏洞爬取与梳理的代码和逻辑暂未开源。

该目录用于独立公开的 GitHub 仓库，并通过 GitHub Pages 提供展示。

## 公开内容

- 漏洞详情（`vulns/{year}/*.toml`，按年份分目录存储）
- PoC 文件（`pocs/{year}/*.toml`）
- EXP 文件（`exploits/{year}/*.toml`）
- 静态站点（`index.html`、`detail.html`、`assets/`）

## 不公开内容

- 漏洞爬取与梳理的核心代码与处理逻辑（暂未开源）
- 内部基础设施与私有自动化实现

## 站点功能

### 漏洞列表（`index.html`）

- **分页浏览**：每页显示 15 条漏洞记录，支持上下翻页。
- **搜索筛选**：支持按关键词（AVE/CVE/标题/描述）搜索，以及按严重性（CRITICAL / HIGH / MEDIUM / LOW / INFO / UNKNOWN）过滤。
- **列排序**：点击表头可按 AVE 编号、标题、严重性、日期、评分排序，支持升降序切换。默认按发布时间（`published`）降序排列。
- **表格布局**：使用 `table-layout: fixed` 固定列宽百分比分配，确保 8 列内容完整显示，大文本自动省略截断。
- **PoC/EXP 标记**：基于仓库中公开文件的真实存在性，自动标注"有/无"徽章。
- **年份统计**：侧边栏展示各年份的漏洞/PoC/EXP 数量分布。
- **严重性分布**：可视化进度条展示当前列表的严重性占比。
- **URL 状态持久化**：搜索条件、页码、筛选状态同步到 URL 参数，支持分享和书签。

### 漏洞详情（`detail.html`）

- **完整字段展示**：AVE 编号、CVE 编号（从 aliases 中提取）、标题、描述、严重性、评分。
- **元信息网格**：发布时间、更新时间、状态、采集时间。
- **来源徽章**：将数据来源（NVD、CVE、GitHub Advisory 等）渲染为彩色徽章。
- **别名标签**：CVE 编号绿色高亮，其他别名灰色标签。
- **修复建议**：金色背景框突出显示。
- **PoC/EXP 资产集成**：
  - 仓库中关联的 PoC TOML 文件列表（可查看 GitHub 页面和原始内容，异步加载摘要信息）。
  - 仓库中关联的 EXP 文件列表。
  - TOML 中声明的外部 poc_urls / exp_urls。
- **参考链接**：列出所有参考来源 URL。

## TOML 结构规范

每个漏洞使用严格的五段式 TOML 结构：

```toml
[id]
ave_id = "AVE-2026-0001"
aliases = ["CVE-2026-0001"]

[basic]
title = "漏洞标题（含中文，≥10 字）"
description = "漏洞描述（含中文，≥20 字）"
severity = "CRITICAL"    # CRITICAL | HIGH | MEDIUM | LOW | INFO
score = 9.8             # 0.1 ~ 10.0
sources = ["nvd", "cve"]
published = "2026-01-01"
updated = "2026-06-16"
remediation = "修复建议（含中文，≥10 字）"

[references]
urls = ["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"]

[exploit]
poc_urls = []
exp_urls = []

[meta]
status = "completed"
collected_at = "2026-07-11T22:24:09.189954216+00:00"
```

PoC/EXP 文件使用 `[info]` + `[poc]` / `[exp]` 结构，`[info]` 中 severity 使用小写（如 `"high"`）。

## 搜索架构

- 页面直接使用 **GitHub Code Search API** 与 **GitTree API** 检索仓库中的 TOML 文件。
- 优先使用 Code Search API（支持关键词搜索），API 受限时自动回退到 Tree API 本地过滤。
- 每页 15 条，total_count 上限 1000。
- 搜索条件、严重性筛选、页码同步到 URL query string（`?q=xx&sev=HIGH&p=2`），支持直接分享。
- 每次 push 后由 GitHub Actions 自动重新部署页面。

## GitHub Pages

- 通过 `.github/workflows/pages.yml` 自动部署。
- push 到 `main` 分支会触发构建与发布。
- 站点入口为 `index.html`，详情页入口为 `detail.html?file={year}/{AVE-ID}.toml`。
