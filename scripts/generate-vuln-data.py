#!/usr/bin/env python3
"""构建脚本：扫描所有 TOML 漏洞数据，按年份生成分片静态文件（manifest + per-year index + per-year pages）。"""

import os
import re
import json
import tomllib
from pathlib import Path
from collections import OrderedDict

REPO_ROOT = Path(__file__).resolve().parent.parent
GH_OWNER = "adysec"
GH_REPO = "AVE"
GH_BRANCH = "main"
PAGE_SIZE = 15


# ── Helpers ──────────────────────────────────────────────────────────────

def extract_ave_id(value: str) -> str:
    m = re.search(r"AVE-\d{4}-\d+", value, re.IGNORECASE)
    return m.group(0).upper() if m else ""


def first_cve(aliases: list[str]) -> str:
    for a in aliases:
        if re.match(r"^CVE-\d{4}-\d+", a, re.IGNORECASE):
            return a.upper()
    return "无"


def build_raw_url(rel_path: str) -> str:
    return f"https://github.com/{GH_OWNER}/{GH_REPO}/blob/{GH_BRANCH}/vulns/{rel_path}"


def infer_file_name(ave_id: str) -> str:
    """Derive file_name from ave_id (e.g. 'AVE-2026-0005' → '2026/AVE-2026-0005.toml')."""
    parts = ave_id.split("-", 2)
    if len(parts) == 3:
        return f"{parts[1]}/{ave_id}.toml"
    return f"{ave_id}.toml"


def infer_raw_url(ave_id: str) -> str:
    return build_raw_url(infer_file_name(ave_id))


# ── Parse one vulnerability TOML → full card dict ────────────────────────

def parse_toml(path: Path) -> dict | None:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception:
        return None

    basic = data.get("basic", {})
    info = data.get("info", {})
    ident = data.get("id", {})
    refs = data.get("references", {})
    exploit = data.get("exploit", {})
    meta = data.get("meta", {})

    ave_id = extract_ave_id(path.stem) or ""
    rel_to_vulns = path.relative_to(REPO_ROOT / "vulns")
    file_name = str(rel_to_vulns)

    aliases = ident.get("aliases", [])
    cve_id = first_cve(aliases)

    title = basic.get("title", info.get("name", "")) or ""
    description = basic.get("description", info.get("description", "")) or ""
    severity = (basic.get("severity", info.get("severity", "UNKNOWN")) or "UNKNOWN").upper()
    score = basic.get("score", info.get("score", 0)) or 0
    sources = basic.get("sources", info.get("sources", [])) or []
    published = basic.get("published", "") or ""
    updated = basic.get("updated", "") or ""
    remediation = basic.get("remediation", "") or ""
    status = meta.get("status", "") or ""
    collected_at = meta.get("collected_at", "") or ""
    references = refs.get("urls", []) or []
    poc_urls = exploit.get("poc_urls", []) or []
    exp_urls = exploit.get("exp_urls", []) or []

    return {
        "ave_id": ave_id,
        "file_name": file_name,
        "cve_id": cve_id,
        "title": title,
        "description": description,
        "severity": severity,
        "score": score,
        "aliases": aliases,
        "sources": sources,
        "published": published,
        "updated": updated,
        "remediation": remediation,
        "status": status,
        "collected_at": collected_at,
        "references": references,
        "poc_urls": poc_urls,
        "exp_urls": exp_urls,
        "repo_poc_urls": [],
        "repo_exp_urls": [],
        "has_poc": False,
        "has_exp": False,
        "raw_url": build_raw_url(file_name),
    }


# ── Build asset index (PoC / EXP per AVE ID) ────────────────────────────

def build_asset_index():
    poc_urls: dict[str, list[str]] = {}
    exp_urls: dict[str, list[str]] = {}

    for base, storage in [(REPO_ROOT / "pocs", poc_urls), (REPO_ROOT / "exploits", exp_urls)]:
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            ave = extract_ave_id(path.stem)
            if not ave:
                continue
            raw = f"https://raw.githubusercontent.com/{GH_OWNER}/{GH_REPO}/{GH_BRANCH}/{path.relative_to(REPO_ROOT)}"
            storage.setdefault(ave, []).append(raw)

    return poc_urls, exp_urls


# ── Sort key: newest published first, then AVE ID descending ────────────

def make_sort_key(c):
    pub = c["published"]
    ts = 0
    if pub:
        try:
            ts = -int(__import__("datetime").datetime.fromisoformat(pub).timestamp())
        except Exception:
            pass
    return (ts, c["ave_id"])


# ── Per-year compact index entry (array format) ──────────────────────────
# [ave_id, cve_id, title, severity, score, published, has_poc, has_exp]
# Arrays are ~40% smaller than dicts at scale.
# Fields like file_name/raw_url are derivable from ave_id on the client.

def to_index_entry(card: dict) -> list:
    return [
        card["ave_id"],
        card["cve_id"],
        card["title"],
        card["severity"],
        card["score"],
        card["published"],
        1 if card["has_poc"] else 0,
        1 if card["has_exp"] else 0,
    ]


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    vulns_dir = REPO_ROOT / "vulns"
    if not vulns_dir.is_dir():
        print("❌ vulns/ directory not found")
        return 1

    # ── Parse all ──
    cards = []
    for path in sorted(vulns_dir.rglob("*.toml")):
        card = parse_toml(path)
        if card is not None:
            cards.append(card)
    print(f"📦 Parsed {len(cards)} vulnerability files")

    # ── Asset index ──
    poc_by_ave, exp_by_ave = build_asset_index()
    print(f"📎 Found {sum(len(v) for v in poc_by_ave.values())} PoC files")
    print(f"📎 Found {sum(len(v) for v in exp_by_ave.values())} EXP files")

    # ── Enrich ──
    for card in cards:
        ave = card["ave_id"]
        card["repo_poc_urls"] = poc_by_ave.get(ave, [])
        card["repo_exp_urls"] = exp_by_ave.get(ave, [])
        card["has_poc"] = len(card["repo_poc_urls"]) > 0
        card["has_exp"] = len(card["repo_exp_urls"]) > 0

    # ── Sort (year desc, then date desc, then id desc) ──
    cards.sort(key=make_sort_key)

    # ── Group by year ──
    year_groups = OrderedDict()
    for card in cards:
        year = card["ave_id"].split("-")[1]  # e.g. "2026"
        year_groups.setdefault(year, []).append(card)

    # ── Output directories ──
    data_dir = REPO_ROOT / "assets" / "data"
    index_dir = data_dir / "index"
    pages_root = data_dir / "pages"
    index_dir.mkdir(parents=True, exist_ok=True)

    # ── Clean up old combined search-index.json (v2 format) ──
    old_index = data_dir / "search-index.json"
    if old_index.exists():
        old_index.unlink()
        print(f"🗑️  Removed old combined search-index.json")

    # ── Clean up old flat page files (v2: pages/1.json, pages/2.json…) ──
    if pages_root.exists():
        for f in sorted(pages_root.glob("[0-9]*.json")):
            f.unlink()
            print(f"🗑️  Removed old page file {f.name}")

    # ── Per‑year processing ──
    years_meta = []
    total_pages_all = 0

    for year, year_cards in year_groups.items():
        # Per-year page dir
        year_pages = pages_root / year
        year_pages.mkdir(parents=True, exist_ok=True)

        # 1. Per-year search index (compact arrays)
        index_entries = [to_index_entry(c) for c in year_cards]
        index_path = index_dir / f"{year}.json"
        index_path.write_text(
            json.dumps(index_entries, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        index_size = os.path.getsize(index_path)

        # 2. Per-year page files
        num_pages = max(1, (len(year_cards) + PAGE_SIZE - 1) // PAGE_SIZE)
        for page_num in range(1, num_pages + 1):
            start = (page_num - 1) * PAGE_SIZE
            end = start + PAGE_SIZE
            page_cards = year_cards[start:end]
            (year_pages / f"{page_num}.json").write_text(
                json.dumps(page_cards, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )

        total_pages_all += num_pages
        years_meta.append({
            "year": year,
            "count": len(year_cards),
            "pages": num_pages,
            "indexSize": index_size,
        })
        print(f"  📁 {year}: {len(year_cards):,} entries, {num_pages} pages, {index_size:,} bytes index")

    # ── Determine default year (most recent) ──
    default_year = years_meta[0]["year"] if years_meta else ""

    # ── Write manifest (version 3) ──
    now_iso = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    manifest = {
        "version": 3,
        "total": len(cards),
        "totalPages": total_pages_all,
        "pageSize": PAGE_SIZE,
        "generatedAt": now_iso,
        "defaultYear": default_year,
        "years": years_meta,
    }
    (data_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    print(f"📋 manifest.json written (version 3, {len(years_meta)} years)")

    # ── Cleanup old vuln-data.js ──
    old_file = REPO_ROOT / "assets" / "vuln-data.js"
    if old_file.exists():
        old_file.unlink()
        print(f"🗑️  Removed old {old_file}")

    # ── Stats ──
    total_pocs = sum(len(v) for v in poc_by_ave.values())
    total_exps = sum(len(v) for v in exp_by_ave.values())
    data_size = sum(f.stat().st_size for f in data_dir.rglob("*") if f.is_file())
    print(f"✅ Done. Total: {len(cards):,} vulns, {total_pocs:,} PoCs, {total_exps:,} EXPs")
    print(f"   Data directory: {data_size:,} bytes")

    # ── Scale projection ──
    total_index_bytes = sum(m["indexSize"] for m in years_meta)
    print(f"\n📊 Scale projection (array format, per-year indices):")
    print(f"   Current total index size: {total_index_bytes:,} bytes ({total_index_bytes/1024:.1f} KB)")
    print(f"   Max single year index: {max(m['indexSize'] for m in years_meta):,} bytes")
    for n in [10000, 100000, 500000]:
        avg = total_index_bytes / len(cards) if cards else 0
        est_raw = avg * n
        est_gz = est_raw * 0.3
        print(f"   {n:>7,} entries → {est_raw/1024/1024:.1f} MB raw, ~{est_gz/1024/1024:.1f} MB gzipped")
        print(f"     (per-year max at that scale: ~{avg * n / max(len(years_meta),1) / 1024:.0f} KB per year)")

    return 0


if __name__ == "__main__":
    exit(main())
