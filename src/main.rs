use chrono::Utc;
use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use walkdir::WalkDir;

// ── Constants ──────────────────────────────────────────────────────────

const GH_OWNER: &str = "adysec";
const GH_REPO: &str = "AVE";
const GH_BRANCH: &str = "main";
const PAGE_SIZE: usize = 15;

// ── Regex (lazy static) ────────────────────────────────────────────────

fn ave_id_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)AVE-\d{4}-\d+").unwrap())
}

fn cve_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^CVE-\d{4}-\d+").unwrap())
}

// ── Helpers ────────────────────────────────────────────────────────────

fn extract_ave_id(value: &str) -> Option<String> {
    ave_id_regex()
        .find(value)
        .map(|m| m.as_str().to_uppercase())
}

fn first_cve(aliases: &[String]) -> String {
    aliases
        .iter()
        .find(|a| cve_regex().is_match(a))
        .cloned()
        .unwrap_or_else(|| "无".to_string())
}

fn build_raw_url(rel_path: &str) -> String {
    format!(
        "https://github.com/{}/{}/blob/{}/vulns/{}",
        GH_OWNER, GH_REPO, GH_BRANCH, rel_path
    )
}

// ── TOML data structures (partial, only fields we need) ────────────────

#[derive(serde::Deserialize, Default)]
struct TomlBasic {
    #[serde(default)]
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    score: f64,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    published: String,
    #[serde(default)]
    updated: String,
    #[serde(default)]
    remediation: String,
}

#[derive(serde::Deserialize, Default)]
struct TomlInfo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    score: f64,
    #[serde(default)]
    sources: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct TomlId {
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    ave_id: String,
}

#[derive(serde::Deserialize, Default)]
struct TomlReferences {
    #[serde(default)]
    urls: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct TomlExploit {
    #[serde(default)]
    poc_urls: Vec<String>,
    #[serde(default)]
    exp_urls: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct TomlMeta {
    #[serde(default)]
    status: String,
    #[serde(default)]
    collected_at: String,
}

#[derive(serde::Deserialize, Default)]
struct TomlVuln {
    #[serde(default)]
    basic: TomlBasic,
    #[serde(default)]
    info: TomlInfo,
    #[serde(default)]
    id: TomlId,
    #[serde(default)]
    references: TomlReferences,
    #[serde(default)]
    exploit: TomlExploit,
    #[serde(default)]
    meta: TomlMeta,
}

// ── Output card ────────────────────────────────────────────────────────

#[derive(Serialize, Clone)]
struct VulnCard {
    ave_id: String,
    file_name: String,
    cve_id: String,
    title: String,
    description: String,
    severity: String,
    score: f64,
    aliases: Vec<String>,
    sources: Vec<String>,
    published: String,
    updated: String,
    remediation: String,
    status: String,
    collected_at: String,
    references: Vec<String>,
    poc_urls: Vec<String>,
    exp_urls: Vec<String>,
    repo_poc_urls: Vec<String>,
    repo_exp_urls: Vec<String>,
    has_poc: bool,
    has_exp: bool,
    raw_url: String,
}

// ── Index entry (compact array) ────────────────────────────────────────

type IndexEntry = [serde_json::Value; 8];

fn to_index_entry(card: &VulnCard) -> IndexEntry {
    let score_val = if card.score.is_finite() {
        serde_json::Number::from_f64(card.score).unwrap_or_else(|| 0.into())
    } else {
        0.into()
    };
    [
        serde_json::Value::String(card.ave_id.clone()),
        serde_json::Value::String(card.cve_id.clone()),
        serde_json::Value::String(card.title.clone()),
        serde_json::Value::String(card.severity.clone()),
        serde_json::Value::Number(score_val),
        serde_json::Value::String(card.published.clone()),
        serde_json::Value::Number((card.has_poc as u8).into()),
        serde_json::Value::Number((card.has_exp as u8).into()),
    ]
}

// ── Parse one TOML file ────────────────────────────────────────────────

fn parse_toml(path: &Path, repo_root: &Path) -> Option<VulnCard> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠️  Failed to read {}: {}", path.display(), e);
            return None;
        }
    };
    let data: TomlVuln = match toml::from_str(&content) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("⚠️  Failed to parse TOML {}: {}", path.display(), e);
            return None;
        }
    };

    // Determine AVE ID: filename first, then fall back to [id] ave_id
    let stem = path.file_stem()?.to_str()?;
    let mut ave_id = extract_ave_id(stem);
    if ave_id.is_none() {
        ave_id = extract_ave_id(&data.id.ave_id);
    }
    let ave_id = match ave_id {
        Some(id) => id,
        None => {
            eprintln!(
                "⚠️  No valid AVE ID in file: {} (stem: {}, id.ave_id: {})",
                path.display(),
                stem,
                data.id.ave_id
            );
            return None;
        }
    };

    let rel_to_vulns = match path.strip_prefix(repo_root.join("vulns")) {
        Ok(r) => r,
        Err(_) => {
            eprintln!(
                "⚠️  Path not under vulns/ directory: {}",
                path.display()
            );
            return None;
        }
    };
    let file_name = match rel_to_vulns.to_str() {
        Some(s) => s.to_string(),
        None => {
            eprintln!(
                "⚠️  Non-UTF-8 path: {}",
                rel_to_vulns.display()
            );
            return None;
        }
    };

    let cve_id = first_cve(&data.id.aliases);

    let title = if data.basic.title.is_empty() {
        data.info.name.clone()
    } else {
        data.basic.title.clone()
    };
    let description = if data.basic.description.is_empty() {
        data.info.description.clone()
    } else {
        data.basic.description.clone()
    };
    let severity = if data.basic.severity.is_empty() {
        if data.info.severity.is_empty() {
            "UNKNOWN".to_string()
        } else {
            data.info.severity.to_uppercase()
        }
    } else {
        data.basic.severity.to_uppercase()
    };
    let score = if data.basic.score != 0.0 {
        data.basic.score
    } else {
        data.info.score
    };
    // Guard against NaN / Infinity which serde_json cannot serialize
    if score.is_nan() || score.is_infinite() {
        eprintln!(
            "⚠️  Invalid score ({}) in {} — defaulting to 0.0",
            score,
            path.display()
        );
    }
    let score = if score.is_finite() { score } else { 0.0 };
    let sources = if data.basic.sources.is_empty() {
        data.info.sources.clone()
    } else {
        data.basic.sources.clone()
    };

    Some(VulnCard {
        ave_id: ave_id.clone(),
        file_name: file_name.clone(),
        cve_id,
        title,
        description,
        severity,
        score,
        aliases: data.id.aliases,
        sources,
        published: data.basic.published.clone(),
        updated: data.basic.updated.clone(),
        remediation: data.basic.remediation.clone(),
        status: data.meta.status.clone(),
        collected_at: data.meta.collected_at.clone(),
        references: data.references.urls,
        poc_urls: data.exploit.poc_urls,
        exp_urls: data.exploit.exp_urls,
        repo_poc_urls: vec![],
        repo_exp_urls: vec![],
        has_poc: false,
        has_exp: false,
        raw_url: build_raw_url(&file_name),
    })
}

// ── Build asset index ──────────────────────────────────────────────────

fn build_asset_index(repo_root: &Path) -> (HashMap<String, Vec<String>>, HashMap<String, Vec<String>>) {
    let mut poc_urls: HashMap<String, Vec<String>> = HashMap::new();
    let mut exp_urls: HashMap<String, Vec<String>> = HashMap::new();

    for (base, storage) in [
        (repo_root.join("pocs"), &mut poc_urls),
        (repo_root.join("exploits"), &mut exp_urls),
    ] {
        if !base.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&base).sort_by_file_name().into_iter() {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    eprintln!("⚠️  WalkDir error in {}: {}", base.display(), err);
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let stem = entry.path().file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if let Some(ave) = extract_ave_id(stem) {
                let rel = match entry.path().strip_prefix(repo_root) {
                    Ok(r) => r,
                    Err(_) => {
                        eprintln!(
                            "⚠️  Path not under repo root: {}",
                            entry.path().display()
                        );
                        continue;
                    }
                };
                let raw = format!(
                    "https://raw.githubusercontent.com/{}/{}/{}/{}",
                    GH_OWNER,
                    GH_REPO,
                    GH_BRANCH,
                    rel.display()
                );
                storage.entry(ave).or_default().push(raw);
            }
        }
    }

    (poc_urls, exp_urls)
}

// ── Sort key ───────────────────────────────────────────────────────────

fn sort_cards(cards: &mut [VulnCard]) {
    cards.sort_by(|a, b| {
        // newest published first
        let ts_a = parse_published_ts(&a.published, &a.ave_id);
        let ts_b = parse_published_ts(&b.published, &b.ave_id);
        ts_b
            .cmp(&ts_a)
            .then_with(|| b.ave_id.cmp(&a.ave_id))
    });
}

/// Parse a published date string to a Unix timestamp.
/// Tries multiple common formats: ISO 8601 with/without time, with/without fractional seconds.
fn parse_published_ts(published: &str, ave_id: &str) -> i64 {
    if published.is_empty() {
        return 0;
    }
    // Try full datetime with fractional seconds: "2024-01-15T12:00:00.000"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(published, "%Y-%m-%dT%H:%M:%S%.3f")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(published, "%Y-%m-%dT%H:%M:%S%.f"))
    {
        return dt.and_utc().timestamp();
    }
    // Try full datetime without fractional seconds: "2024-01-15T12:00:00" or "2024-01-15 12:00:00"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(published, "%Y-%m-%dT%H:%M:%S")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(published, "%Y-%m-%d %H:%M:%S"))
    {
        return dt.and_utc().timestamp();
    }
    // Try date only: "2024-01-15"
    if let Ok(d) = chrono::NaiveDate::parse_from_str(published, "%Y-%m-%d") {
        return d
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
            .timestamp();
    }
    eprintln!(
        "⚠️  Invalid published date '{}' for {}",
        published, ave_id
    );
    0
}

// ── Write JSON helper ──────────────────────────────────────────────────

fn write_json_compact(path: &Path, value: &impl Serialize) -> std::io::Result<usize> {
    let mut json = serde_json::to_string(value)?;
    // serde_json doesn't have a built-in compact mode that strips spaces
    // like Python's separators=(",", ":"), so we do a quick minify
    json = minify_json(&json);
    let len = json.len();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, &json)?;
    Ok(len)
}

/// Simple JSON minifier: removes whitespace outside strings.
/// This is safe because serde_json always produces valid JSON.
fn minify_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in json.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            continue;
        }
        if in_string {
            out.push(ch);
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else {
            match ch {
                '"' => {
                    in_string = true;
                    out.push(ch);
                }
                c if c.is_ascii_whitespace() => {} // skip
                _ => out.push(ch),
            }
        }
    }
    out
}

// ── Manifest ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct YearMeta {
    year: String,
    count: usize,
    pages: usize,
    #[serde(rename = "indexSize")]
    index_size: usize,
}

#[derive(Serialize)]
struct Manifest {
    version: u8,
    total: usize,
    #[serde(rename = "totalPages")]
    total_pages: usize,
    #[serde(rename = "pageSize")]
    page_size: usize,
    #[serde(rename = "generatedAt")]
    generated_at: String,
    #[serde(rename = "defaultYear")]
    default_year: String,
    years: Vec<YearMeta>,
}

fn find_repo_root() -> Option<PathBuf> {
    // 1. Try current working directory
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("vulns").is_dir() {
            return Some(cwd);
        }
    }

    // 2. Walk up from the binary's location
    if let Ok(exe) = std::env::current_exe() {
        if let Ok(mut path) = exe.canonicalize() {
            for _ in 0..10 {
                if let Some(parent) = path.parent() {
                    path = parent.to_path_buf();
                    if path.join("vulns").is_dir() {
                        return Some(path);
                    }
                } else {
                    break;
                }
            }
        }
    }

    // 3. Try common CI paths
    for candidate in &[
        "/home/runner/work/AVE/AVE",
        "/root/ave/output",
    ] {
        let p = Path::new(candidate);
        if p.join("vulns").is_dir() {
            return Some(p.to_path_buf());
        }
    }

    None
}

// ── Main ───────────────────────────────────────────────────────────────

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repo_root = find_repo_root().unwrap_or_else(|| {
        eprintln!("❌ Cannot find repo root (vulns/ directory not found)");
        std::process::exit(1);
    });

    let vulns_dir = repo_root.join("vulns");
    if !vulns_dir.is_dir() {
        eprintln!("❌ vulns/ directory not found");
        std::process::exit(1);
    }

    // ── Collect all .toml paths ──
    let toml_paths: Vec<PathBuf> = WalkDir::new(&vulns_dir)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|entry| match entry {
            Ok(e) => Some(e),
            Err(err) => {
                eprintln!("⚠️  WalkDir error in vulns/: {}", err);
                None
            }
        })
        .filter(|e| {
            e.file_type().is_file()
                && e.path()
                    .extension()
                    .map(|ext| ext.eq_ignore_ascii_case("toml"))
                    .unwrap_or(false)
        })
        .map(|e| e.into_path())
        .collect();

    // ── Parse all TOML files in parallel ──
    let mut cards: Vec<VulnCard> = toml_paths
        .par_iter()
        .filter_map(|path| parse_toml(path, &repo_root))
        .collect();

    println!("📦 Parsed {} vulnerability files", cards.len());

    // ── Build asset index ──
    let (poc_by_ave, exp_by_ave) = build_asset_index(&repo_root);
    let total_pocs: usize = poc_by_ave.values().map(|v| v.len()).sum();
    let total_exps: usize = exp_by_ave.values().map(|v| v.len()).sum();
    println!("📎 Found {} PoC files", total_pocs);
    println!("📎 Found {} EXP files", total_exps);

    // ── Enrich cards with asset URLs ──
    cards.par_iter_mut().for_each(|card| {
        card.repo_poc_urls = poc_by_ave.get(&card.ave_id).cloned().unwrap_or_default();
        card.repo_exp_urls = exp_by_ave.get(&card.ave_id).cloned().unwrap_or_default();
        card.has_poc = !card.repo_poc_urls.is_empty();
        card.has_exp = !card.repo_exp_urls.is_empty();
    });

    // ── Sort ──
    sort_cards(&mut cards);

    // ── Group by year ──
    let mut year_groups: BTreeMap<String, Vec<&VulnCard>> = BTreeMap::new();
    for card in &cards {
        let parts: Vec<&str> = card.ave_id.split('-').collect();
        if parts.len() < 2 {
            eprintln!("⚠️  Skipping malformed AVE ID: {}", card.ave_id);
            continue;
        }
        let year = parts[1].to_string();
        year_groups.entry(year).or_default().push(card);
    }
    // Reverse to get newest year first
    let year_groups: Vec<(String, Vec<&VulnCard>)> = {
        let mut v: Vec<_> = year_groups.into_iter().collect();
        v.reverse();
        v
    };

    // ── Output directories ──
    let data_dir = repo_root.join("assets").join("data");
    let index_dir = data_dir.join("index");
    let pages_root = data_dir.join("pages");
    fs::create_dir_all(&index_dir)?;

    // ── Clean up old combined search-index.json (v2 format) ──
    let old_index = data_dir.join("search-index.json");
    if old_index.exists() {
        fs::remove_file(&old_index)?;
        println!("🗑️  Removed old combined search-index.json");
    }

    // ── Clean up old flat page files (v2) ──
    if pages_root.exists() {
        for entry in WalkDir::new(&pages_root)
            .min_depth(1)
            .max_depth(1)
            .sort_by_file_name()
            .into_iter()
        {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    eprintln!("⚠️  WalkDir error in pages/: {}", err);
                    continue;
                }
            };
            if entry.file_type().is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    if name
                        .strip_suffix(".json")
                        .map(|s| s.chars().all(|c| c.is_ascii_digit()))
                        .unwrap_or(false)
                    {
                        fs::remove_file(entry.path())?;
                        println!("🗑️  Removed old page file {}", name);
                    }
                }
            }
        }
    }

    // ── Per-year processing ──
    let mut years_meta: Vec<YearMeta> = Vec::new();
    for (year, year_cards) in &year_groups {
        let year_pages = pages_root.join(year);
        fs::create_dir_all(&year_pages).map_err(|e| {
            eprintln!("❌ Failed to create directory {}: {}", year_pages.display(), e);
            e
        })?;

        // 1. Per-year search index (compact arrays)
        let index_entries: Vec<IndexEntry> =
            year_cards.iter().map(|c| to_index_entry(c)).collect();
        let index_path = index_dir.join(format!("{}.json", year));
        let index_size = write_json_compact(&index_path, &index_entries).map_err(|e| {
            eprintln!("❌ Failed to write index {}: {}", index_path.display(), e);
            e
        })?;

        // 2. Per-year page files
        let num_pages =
            std::cmp::max(1, (year_cards.len() + PAGE_SIZE - 1) / PAGE_SIZE);
        for page_num in 1..=num_pages {
            let start = (page_num - 1) * PAGE_SIZE;
            let end = (start + PAGE_SIZE).min(year_cards.len());
            let page_cards: Vec<&VulnCard> = year_cards[start..end].iter().copied().collect();
            let page_path = year_pages.join(format!("{}.json", page_num));
            write_json_compact(&page_path, &page_cards).map_err(|e| {
                eprintln!("❌ Failed to write page {}: {}", page_path.display(), e);
                e
            })?;
        }

        years_meta.push(YearMeta {
            year: year.clone(),
            count: year_cards.len(),
            pages: num_pages,
            index_size,
        });

        println!(
            "  📁 {}: {} entries, {} pages, {} bytes index",
            year, year_cards.len(), num_pages, index_size
        );
    }

    let total_pages_all: usize = years_meta.iter().map(|m| m.pages).sum();
    let default_year = years_meta
        .first()
        .map(|m| m.year.clone())
        .unwrap_or_default();

    // ── Write manifest ──
    let manifest = Manifest {
        version: 3,
        total: cards.len(),
        total_pages: total_pages_all,
        page_size: PAGE_SIZE,
        generated_at: Utc::now().to_rfc3339(),
        default_year,
        years: years_meta,
    };
    write_json_compact(&data_dir.join("manifest.json"), &manifest)?;
    println!(
        "📋 manifest.json written (version 3, {} years)",
        manifest.years.len()
    );

    // ── Cleanup old vuln-data.js ──
    let old_file = repo_root.join("assets").join("vuln-data.js");
    if old_file.exists() {
        fs::remove_file(&old_file)?;
        println!("🗑️  Removed old {}", old_file.display());
    }

    // ── Stats ──
    let data_size: u64 = WalkDir::new(&data_dir)
        .into_iter()
        .filter_map(|e| match e {
            Ok(entry) => Some(entry),
            Err(err) => {
                eprintln!("⚠️  WalkDir error in data/: {}", err);
                None
            }
        })
        .filter(|e| e.file_type().is_file())
        .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
        .sum();

    println!(
        "✅ Done. Total: {} vulns, {} PoCs, {} EXPs",
        cards.len(),
        total_pocs,
        total_exps
    );
    println!("   Data directory: {} bytes", data_size);

    // ── Scale projection ──
    let total_index_bytes: usize = manifest.years.iter().map(|m| m.index_size).sum();
    let max_index = manifest
        .years
        .iter()
        .map(|m| m.index_size)
        .max()
        .unwrap_or(0);
    println!("\n📊 Scale projection (array format, per-year indices):");
    println!(
        "   Current total index size: {} bytes ({:.1} KB)",
        total_index_bytes,
        total_index_bytes as f64 / 1024.0
    );
    println!("   Max single year index: {} bytes", max_index);

    for n in [10_000usize, 100_000, 500_000] {
        let avg = if cards.is_empty() {
            0.0
        } else {
            total_index_bytes as f64 / cards.len() as f64
        };
        let est_raw = avg * n as f64;
        let est_gz = est_raw * 0.3;
        println!(
            "   {:>7} entries → {:.1} MB raw, ~{:.1} MB gzipped",
            n,
            est_raw / 1024.0 / 1024.0,
            est_gz / 1024.0 / 1024.0
        );
        println!(
            "     (per-year max at that scale: ~{:.0} KB per year)",
            avg * n as f64
                / std::cmp::max(manifest.years.len(), 1) as f64
                / 1024.0
        );
    }

    Ok(())
}
