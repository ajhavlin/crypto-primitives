#![cfg(feature = "bench_harness")]

use super::super::{decode_delta, encode_varint};
use crate::merkle_tree::{
    legacy, tests::test_utils::poseidon_parameters, CoPath, Config, IdentityDigestConverter,
    LeafParam, MerkleTree, TwoToOneParam,
};
use ark_ed_on_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;
use ark_std::{
    rand::{rngs::StdRng, Rng, SeedableRng},
    UniformRand,
};
use plotters::prelude::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

type F = Fr;
type H = crate::crh::poseidon::CRH<F>;
type TwoToOneH = crate::crh::poseidon::TwoToOneCRH<F>;

struct FieldMTConfig;
impl Config for FieldMTConfig {
    type Leaf = [F];
    type LeafDigest = F;
    type LeafInnerDigestConverter = IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = H;
    type TwoToOneHash = TwoToOneH;
}

struct LegacyFieldMTConfig;
impl legacy::Config for LegacyFieldMTConfig {
    type Leaf = [F];
    type LeafDigest = F;
    type LeafInnerDigestConverter = legacy::IdentityDigestConverter<F>;
    type InnerDigest = F;
    type LeafHash = H;
    type TwoToOneHash = TwoToOneH;
}

type FieldMT = MerkleTree<FieldMTConfig>;
type LegacyFieldMT = legacy::MerkleTree<LegacyFieldMTConfig>;
type LegacyLeafParam = legacy::LeafParam<LegacyFieldMTConfig>;
type LegacyTwoToOneParam = legacy::TwoToOneParam<LegacyFieldMTConfig>;

const TREE_EXPONENTS: &[u32] = &[12, 14, 16, 18, 20];
const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
const LEAF_WIDTH: usize = 3;
const COORD_TREE_EXPONENTS: &[u32] = &[18];

#[derive(Clone, Copy)]
enum CoordinateEncoding {
    Natural,
    Leb128Index,
}

impl CoordinateEncoding {
    fn label(self) -> &'static str {
        match self {
            CoordinateEncoding::Natural => "natural",
            CoordinateEncoding::Leb128Index => "leb128",
        }
    }
}

#[derive(Clone, Copy)]
enum IndexPattern {
    Random,
    Clustered,
    Adversarial,
}

impl IndexPattern {
    fn label(self) -> &'static str {
        match self {
            IndexPattern::Random => "random",
            IndexPattern::Clustered => "clustered",
            IndexPattern::Adversarial => "adversarial",
        }
    }

    fn id(self) -> u64 {
        match self {
            IndexPattern::Random => 0,
            IndexPattern::Clustered => 1,
            IndexPattern::Adversarial => 2,
        }
    }
}

struct TreeFixture {
    leaves: Vec<Vec<F>>,
    tree: FieldMT,
    legacy_tree: LegacyFieldMT,
    leaf_params: LeafParam<FieldMTConfig>,
    legacy_leaf_params: LegacyLeafParam,
    two_to_one_params: TwoToOneParam<FieldMTConfig>,
    legacy_two_to_one_params: LegacyTwoToOneParam,
}

struct ReportRow {
    tree_size: usize,
    log2_size: u32,
    batch: usize,
    pattern: &'static str,
    strategy: &'static str,
    proof_bytes: usize,
    proof_nodes: usize,
    hashes_per_opening: f64,
    prove_ms: f64,
    verify_ms: f64,
    rss_delta_kb: Option<i64>,
}

struct PlotMetric {
    name: &'static str,
    filename_prefix: &'static str,
    y_label: &'static str,
    value: fn(&ReportRow) -> Option<f64>,
}

struct CoordinateSizeRow {
    tree_size: usize,
    log2_size: u32,
    batch: usize,
    pattern: &'static str,
    strategy: &'static str,
    proof_bytes: usize,
    proof_nodes: usize,
}

struct InnerEntry<'a, D> {
    depth: usize,
    index: usize,
    digest: &'a D,
}

trait ProofStats {
    fn opened(&self) -> usize;
    fn total_nodes(&self) -> usize;
}

impl<P: Config> ProofStats for CoPath<P> {
    fn opened(&self) -> usize {
        self.leaf_indexes.len()
    }

    fn total_nodes(&self) -> usize {
        let inner = self
            .inner_copath
            .as_ref()
            .map(|(_, _, _, digests)| digests.len())
            .unwrap_or(0);
        self.leaf_copath.len() + inner
    }
}

impl<P: legacy::Config> ProofStats for legacy::MultiPath<P> {
    fn opened(&self) -> usize {
        self.leaf_indexes.len()
    }

    fn total_nodes(&self) -> usize {
        let auth_len: usize = self.auth_paths_suffixes.iter().map(|path| path.len()).sum();
        self.leaf_siblings_hashes.len() + auth_len
    }
}

const PLOT_METRICS: &[PlotMetric] = &[
    PlotMetric {
        name: "Proof Size",
        filename_prefix: "proof_size",
        y_label: "proof size (bytes)",
        value: |row: &ReportRow| Some(row.proof_bytes as f64),
    },
    PlotMetric {
        name: "Proving Time",
        filename_prefix: "prove_ms",
        y_label: "prove time (ms)",
        value: |row: &ReportRow| Some(row.prove_ms),
    },
    PlotMetric {
        name: "Verification Time",
        filename_prefix: "verify_ms",
        y_label: "verify time (ms)",
        value: |row: &ReportRow| Some(row.verify_ms),
    },
];

#[test]
#[ignore]
fn multiproof_v2_benchmark_report() {
    run_report().expect("benchmark report must succeed");
}

#[test]
#[ignore]
fn coordinate_encoding_proof_size_report() {
    run_coordinate_report().expect("coordinate encoding report must succeed");
}

#[test]
#[ignore]
fn leb128_vs_delta_proof_size_report() {
    run_leb128_vs_delta_report().expect("leb128 vs delta report must succeed");
}

fn run_report() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixtures = Vec::new();
    for &exp in TREE_EXPONENTS {
        fixtures.push(build_fixture(exp)?);
    }

    let patterns = [
        IndexPattern::Random,
        IndexPattern::Clustered,
        IndexPattern::Adversarial,
    ];

    let mut rows = Vec::new();
    for fixture in fixtures.iter() {
        for &batch in BATCH_SIZES {
            if batch > fixture.leaves.len() {
                continue;
            }
            for &pattern in &patterns {
                let mut scenario_rng = StdRng::seed_from_u64(
                    0xC057_E771_u64
                        ^ ((fixture.leaves.len() as u64) << 16)
                        ^ ((batch as u64) << 2)
                        ^ pattern.id(),
                );
                let indexes =
                    sample_indexes(pattern, batch, fixture.leaves.len(), &mut scenario_rng);
                rows.extend(run_scenario(fixture, batch, pattern, &indexes)?);
            }
        }
    }

    let report_dir = PathBuf::from("target/merkle_tree_reports");
    fs::create_dir_all(&report_dir)?;
    let plot_files = write_plots(&rows, &report_dir)?;
    write_report(&rows, &report_dir, &plot_files)?;
    Ok(())
}

fn run_coordinate_report() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixtures = Vec::new();
    for &exp in COORD_TREE_EXPONENTS {
        fixtures.push(build_fixture(exp)?);
    }

    let patterns = [IndexPattern::Random, IndexPattern::Clustered];
    let encodings = [CoordinateEncoding::Natural, CoordinateEncoding::Leb128Index];

    let mut rows = Vec::new();
    for fixture in fixtures.iter() {
        for &batch in BATCH_SIZES {
            if batch > fixture.leaves.len() {
                continue;
            }
            for &pattern in &patterns {
                let mut scenario_rng = StdRng::seed_from_u64(
                    0xC0DE_1280_u64
                        ^ ((fixture.leaves.len() as u64) << 16)
                        ^ ((batch as u64) << 2)
                        ^ pattern.id(),
                );
                let indexes =
                    sample_indexes(pattern, batch, fixture.leaves.len(), &mut scenario_rng);
                let proof = fixture.tree.generate_multi_proof(indexes.iter().copied())?;
                let proof_nodes = proof.total_nodes();

                for &encoding in &encodings {
                    rows.push(CoordinateSizeRow {
                        tree_size: fixture.leaves.len(),
                        log2_size: fixture.log2_size(),
                        batch,
                        pattern: pattern.label(),
                        strategy: encoding.label(),
                        proof_bytes: serialized_coordinate_proof_size(&proof, encoding),
                        proof_nodes,
                    });
                }
            }
        }
    }

    let report_dir = PathBuf::from("target/merkle_tree_reports");
    fs::create_dir_all(&report_dir)?;
    let plot_files = write_coordinate_plots(&rows, &report_dir)?;
    write_coordinate_report(&rows, &report_dir, &plot_files)?;
    write_coordinate_rows_csv(&rows, &report_dir)?;
    Ok(())
}

fn run_leb128_vs_delta_report() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixtures = Vec::new();
    for &exp in COORD_TREE_EXPONENTS {
        fixtures.push(build_fixture(exp)?);
    }

    let patterns = [IndexPattern::Random, IndexPattern::Clustered];
    let mut rows = Vec::new();

    for fixture in fixtures.iter() {
        for &batch in BATCH_SIZES {
            if batch > fixture.leaves.len() {
                continue;
            }
            for &pattern in &patterns {
                let mut scenario_rng = StdRng::seed_from_u64(
                    0xD37A_1280_u64
                        ^ ((fixture.leaves.len() as u64) << 16)
                        ^ ((batch as u64) << 2)
                        ^ pattern.id(),
                );
                let indexes =
                    sample_indexes(pattern, batch, fixture.leaves.len(), &mut scenario_rng);
                let proof = fixture.tree.generate_multi_proof(indexes.iter().copied())?;
                let proof_nodes = proof.total_nodes();

                rows.push(CoordinateSizeRow {
                    tree_size: fixture.leaves.len(),
                    log2_size: fixture.log2_size(),
                    batch,
                    pattern: pattern.label(),
                    strategy: "leb128",
                    proof_bytes: serialized_coordinate_proof_size(
                        &proof,
                        CoordinateEncoding::Leb128Index,
                    ),
                    proof_nodes,
                });
                rows.push(CoordinateSizeRow {
                    tree_size: fixture.leaves.len(),
                    log2_size: fixture.log2_size(),
                    batch,
                    pattern: pattern.label(),
                    strategy: "delta",
                    proof_bytes: serialized_size(&proof),
                    proof_nodes,
                });
            }
        }
    }

    let report_dir = PathBuf::from("target/merkle_tree_reports");
    fs::create_dir_all(&report_dir)?;
    let plot_files = write_leb128_vs_delta_plots(&rows, &report_dir)?;
    write_leb128_vs_delta_report(&rows, &report_dir, &plot_files)?;
    write_leb128_vs_delta_rows_csv(&rows, &report_dir)?;
    Ok(())
}

fn run_scenario(
    fixture: &TreeFixture,
    batch: usize,
    pattern: IndexPattern,
    indexes: &[usize],
) -> Result<[ReportRow; 2], Box<dyn std::error::Error>> {
    let root = fixture.tree.root();
    let legacy_root = fixture.legacy_tree.root();
    let opened_leaves: Vec<Vec<F>> = indexes.iter().map(|&i| fixture.leaves[i].clone()).collect();

    let legacy_row = benchmark_strategy(
        "prefix",
        || {
            fixture
                .legacy_tree
                .generate_multi_proof(indexes.iter().copied())
        },
        |proof: &legacy::MultiPath<_>, leaves| {
            proof.verify(
                &fixture.legacy_leaf_params,
                &fixture.legacy_two_to_one_params,
                &legacy_root,
                leaves,
            )
        },
        &opened_leaves,
        fixture.leaves.len(),
        fixture.log2_size(),
        batch,
        pattern,
    )?;

    let coset_row = benchmark_strategy(
        "coset",
        || fixture.tree.generate_multi_proof(indexes.iter().copied()),
        |proof: &CoPath<_>, leaves| {
            proof.verify(
                &fixture.leaf_params,
                &fixture.two_to_one_params,
                &root,
                fixture.tree.height(),
                leaves,
            )
        },
        &opened_leaves,
        fixture.leaves.len(),
        fixture.log2_size(),
        batch,
        pattern,
    )?;
    Ok([legacy_row, coset_row])
}

fn benchmark_strategy<Gen, Proof, Verify>(
    strategy: &'static str,
    mut generator: Gen,
    mut verifier: Verify,
    opened_leaves: &[Vec<F>],
    tree_size: usize,
    log2_size: u32,
    batch: usize,
    pattern: IndexPattern,
) -> Result<ReportRow, Box<dyn std::error::Error>>
where
    Proof: CanonicalSerialize + ProofStats,
    Gen: FnMut() -> Result<Proof, crate::Error>,
    Verify: FnMut(&Proof, Vec<Vec<F>>) -> Result<bool, crate::Error>,
{
    let rss_before = rss_bytes();
    let prove_start = std::time::Instant::now();
    let proof = generator()?;
    let prove_time = prove_start.elapsed();
    let prove_rss = rss_delta_kb(rss_before, rss_bytes());

    let proof_bytes = serialized_size(&proof);
    let proof_nodes = proof.total_nodes();
    let opened = proof.opened().max(1);
    let hashes_per_opening = proof_nodes as f64 / opened as f64;

    let verify_input = opened_leaves.to_vec();
    let rss_before_verify = rss_bytes();
    let verify_start = std::time::Instant::now();
    let verify_ok = verifier(&proof, verify_input.clone())?;
    let verify_time = verify_start.elapsed();
    let verify_rss = rss_delta_kb(rss_before_verify, rss_bytes());
    assert!(
        verify_ok,
        "verification must succeed for {} (tree_n={}, batch={}, pattern={})",
        strategy,
        tree_size,
        batch,
        pattern.label()
    );

    let row = ReportRow {
        tree_size,
        log2_size,
        batch,
        pattern: pattern.label(),
        strategy,
        proof_bytes,
        proof_nodes,
        hashes_per_opening,
        prove_ms: duration_ms(prove_time),
        verify_ms: duration_ms(verify_time),
        rss_delta_kb: combine_rss(prove_rss, verify_rss),
    };

    Ok(row)
}

fn sample_indexes(
    pattern: IndexPattern,
    batch: usize,
    num_leaves: usize,
    rng: &mut StdRng,
) -> Vec<usize> {
    match pattern {
        IndexPattern::Random => {
            let mut set = BTreeSet::new();
            while set.len() < batch {
                let idx = rng.gen_range(0..num_leaves);
                set.insert(idx);
            }
            set.into_iter().collect()
        }
        IndexPattern::Clustered => {
            let max_start = num_leaves.saturating_sub(batch);
            let start = rng.gen_range(0..=max_start);
            (start..start + batch).collect()
        }
        IndexPattern::Adversarial => {
            if batch >= num_leaves {
                return (0..num_leaves).collect();
            }
            let step = num_leaves / batch;
            (0..batch).map(|i| (i * step) % num_leaves).collect()
        }
    }
}

fn build_fixture(exp: u32) -> Result<TreeFixture, Box<dyn std::error::Error>> {
    let leaf_params = poseidon_parameters();
    let legacy_leaf_params: LegacyLeafParam = leaf_params.clone();
    let two_to_one_params = leaf_params.clone();
    let legacy_two_to_one_params: LegacyTwoToOneParam = two_to_one_params.clone();

    let num_leaves = 1usize << exp;
    let mut rng = StdRng::seed_from_u64(0x5EED_C0DE_u64 ^ (exp as u64));
    let leaves = sample_leaves(num_leaves, &mut rng);

    let tree = FieldMT::new(&leaf_params, &two_to_one_params, &leaves).unwrap();
    let legacy_tree =
        LegacyFieldMT::new(&legacy_leaf_params, &legacy_two_to_one_params, &leaves).unwrap();

    Ok(TreeFixture {
        leaves,
        tree,
        legacy_tree,
        leaf_params,
        legacy_leaf_params,
        two_to_one_params,
        legacy_two_to_one_params,
    })
}

fn sample_leaves(count: usize, rng: &mut StdRng) -> Vec<Vec<F>> {
    (0..count)
        .map(|_| (0..LEAF_WIDTH).map(|_| F::rand(rng)).collect())
        .collect()
}

fn write_report(
    rows: &[ReportRow],
    report_dir: &Path,
    plot_files: &BTreeMap<&'static str, Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = report_dir.join("multiproof_v2_report.md");
    let mut file = File::create(&report_path)?;

    writeln!(file, "# Merkle Tree Multiproof Benchmark Report")?;
    writeln!(
        file,
        "\nGenerated: {:?}\n",
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?
    )?;
    writeln!(
        file,
        "| tree_n | log2(n) | batch_k | pattern | strategy | proof_bytes | proof_nodes | hashes/leaf | prove_ms | verify_ms | rss_delta_kb |"
    )?;
    writeln!(
        file,
        "| ------ | ------- | ------- | ------- | -------- | ----------- | ----------- | ------------ | -------- | --------- | ------------ |"
    )?;

    for row in rows {
        writeln!(
            file,
            "| {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {:.2} | {} |",
            row.tree_size,
            row.log2_size,
            row.batch,
            row.pattern,
            row.strategy,
            row.proof_bytes,
            row.proof_nodes,
            row.hashes_per_opening,
            row.prove_ms,
            row.verify_ms,
            row.rss_delta_kb
                .map(|kb| kb.to_string())
                .unwrap_or_else(|| "-".into())
        )?;
    }

    for (metric, files) in plot_files {
        if files.is_empty() {
            continue;
        }
        writeln!(file, "\n## {} Visualizations\n", metric)?;
        for plot in files {
            writeln!(
                file,
                "![{}]({})",
                metric.replace(' ', "-").to_lowercase(),
                plot
            )?;
        }
    }

    Ok(())
}

fn write_coordinate_report(
    rows: &[CoordinateSizeRow],
    report_dir: &Path,
    plot_files: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = report_dir.join("coordinate_encoding_report.md");
    let mut file = File::create(&report_path)?;

    writeln!(file, "# Merkle Tree Proof Size Comparison")?;
    writeln!(
        file,
        "\nGenerated: {:?}\n",
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?
    )?;
    writeln!(
        file,
        "| tree_n | log2(n) | batch_k | pattern | strategy | proof_bytes | proof_nodes |"
    )?;
    writeln!(
        file,
        "| ------ | ------- | ------- | ------- | -------- | ----------- | ----------- |"
    )?;

    for row in rows {
        writeln!(
            file,
            "| {} | {} | {} | {} | {} | {} | {} |",
            row.tree_size,
            row.log2_size,
            row.batch,
            row.pattern,
            row.strategy,
            row.proof_bytes,
            row.proof_nodes,
        )?;
    }

    if !plot_files.is_empty() {
        writeln!(file, "\n## Figures\n")?;
        for plot in plot_files {
            writeln!(file, "![coordinate-proof-size]({})", plot)?;
        }
    }

    Ok(())
}

fn write_coordinate_rows_csv(
    rows: &[CoordinateSizeRow],
    report_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let csv_path = report_dir.join("coordinate_encoding_rows.csv");
    let mut file = File::create(&csv_path)?;
    writeln!(
        file,
        "tree_size,log2_size,batch,pattern,strategy,proof_bytes,proof_nodes"
    )?;

    for row in rows {
        writeln!(
            file,
            "{},{},{},{},{},{},{}",
            row.tree_size,
            row.log2_size,
            row.batch,
            row.pattern,
            row.strategy,
            row.proof_bytes,
            row.proof_nodes,
        )?;
    }

    Ok(())
}

fn write_leb128_vs_delta_report(
    rows: &[CoordinateSizeRow],
    report_dir: &Path,
    plot_files: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let report_path = report_dir.join("leb128_vs_delta_report.md");
    let mut file = File::create(&report_path)?;

    writeln!(file, "# Merkle Tree Proof Size Comparison")?;
    writeln!(
        file,
        "\nGenerated: {:?}\n",
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?
    )?;
    writeln!(
        file,
        "| tree_n | log2(n) | batch_k | pattern | strategy | proof_bytes | proof_nodes |"
    )?;
    writeln!(
        file,
        "| ------ | ------- | ------- | ------- | -------- | ----------- | ----------- |"
    )?;

    for row in rows {
        writeln!(
            file,
            "| {} | {} | {} | {} | {} | {} | {} |",
            row.tree_size,
            row.log2_size,
            row.batch,
            row.pattern,
            row.strategy,
            row.proof_bytes,
            row.proof_nodes,
        )?;
    }

    if !plot_files.is_empty() {
        writeln!(file, "\n## Figures\n")?;
        for plot in plot_files {
            writeln!(file, "![leb128-vs-delta]({})", plot)?;
        }
    }

    Ok(())
}

fn write_leb128_vs_delta_rows_csv(
    rows: &[CoordinateSizeRow],
    report_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let csv_path = report_dir.join("leb128_vs_delta_rows.csv");
    let mut file = File::create(&csv_path)?;
    writeln!(
        file,
        "tree_size,log2_size,batch,pattern,strategy,proof_bytes,proof_nodes"
    )?;

    for row in rows {
        writeln!(
            file,
            "{},{},{},{},{},{},{}",
            row.tree_size,
            row.log2_size,
            row.batch,
            row.pattern,
            row.strategy,
            row.proof_bytes,
            row.proof_nodes,
        )?;
    }

    Ok(())
}

fn write_plots(
    rows: &[ReportRow],
    report_dir: &Path,
) -> Result<BTreeMap<&'static str, Vec<String>>, Box<dyn std::error::Error>> {
    let mut outputs: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();

    for metric in PLOT_METRICS {
        let mut grouped: BTreeMap<(usize, &'static str), BTreeMap<&'static str, Vec<(f64, f64)>>> =
            BTreeMap::new();

        for row in rows {
            if let Some(value) = (metric.value)(row) {
                grouped
                    .entry((row.tree_size, row.pattern))
                    .or_default()
                    .entry(row.strategy)
                    .or_default()
                    .push((row.batch as f64, value));
            }
        }

        let mut generated = Vec::new();
        for ((tree_size, pattern), strategies) in grouped {
            let mut ordered_series: Vec<(&'static str, Vec<(f64, f64)>)> = Vec::new();
            for &name in &["prefix", "coset"] {
                if let Some(mut series) = strategies.get(name).cloned() {
                    if series.is_empty() {
                        continue;
                    }
                    series.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
                    ordered_series.push((name, series));
                }
            }

            if ordered_series.len() < 2 || !ordered_series.iter().any(|(name, _)| *name == "prefix")
            {
                continue;
            }

            let mut min_x = f64::MAX;
            let mut max_x = f64::MIN;
            let mut min_y = f64::MAX;
            let mut max_y = f64::MIN;

            for (_, series) in &ordered_series {
                for &(x, y) in series {
                    min_x = min_x.min(x);
                    max_x = max_x.max(x);
                    min_y = min_y.min(y);
                    max_y = max_y.max(y);
                }
            }
            if min_x == f64::MAX || min_y == f64::MAX {
                continue;
            }

            let x_pad = ((max_x - min_x) * 0.05).max(1.0);
            let y_pad = ((max_y - min_y) * 0.05).max(1.0);

            let filename = format!("{}_{}_{}.svg", metric.filename_prefix, tree_size, pattern);
            let filepath = report_dir.join(&filename);
            let filepath_str = filepath.to_string_lossy().to_string();
            let drawing_area = SVGBackend::new(&filepath_str, (960, 540)).into_drawing_area();
            drawing_area.fill(&WHITE)?;

            let mut chart = ChartBuilder::on(&drawing_area)
                .caption(
                    format!(
                        "{} vs k (n={}, pattern={})",
                        metric.name, tree_size, pattern
                    ),
                    ("Helvetica Neue", 26).into_font().style(FontStyle::Bold),
                )
                .margin(20)
                .x_label_area_size(45)
                .y_label_area_size(70)
                .build_cartesian_2d(
                    (min_x - x_pad)..(max_x + x_pad),
                    (min_y - y_pad)..(max_y + y_pad),
                )?;

            chart
                .configure_mesh()
                .x_desc("batch size (k)")
                .y_desc(metric.y_label)
                .draw()?;

            for (name, series) in &ordered_series {
                let color = strategy_color(name);
                chart
                    .draw_series(LineSeries::new(series.clone(), color.clone()))?
                    .label(strategy_label(name))
                    .legend({
                        let color = color.clone();
                        move |(x, y)| PathElement::new(vec![(x, y), (x + 20, y)], color.clone())
                    });
            }

            chart
                .configure_series_labels()
                .border_style(&BLACK)
                .draw()?;

            generated.push(filename);
        }

        outputs.insert(metric.name, generated);
    }

    Ok(outputs)
}

fn write_coordinate_plots(
    rows: &[CoordinateSizeRow],
    report_dir: &Path,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut grouped: BTreeMap<(usize, &'static str), BTreeMap<&'static str, Vec<(f64, f64)>>> =
        BTreeMap::new();

    for row in rows {
        grouped
            .entry((row.tree_size, row.pattern))
            .or_default()
            .entry(row.strategy)
            .or_default()
            .push((row.batch as f64, row.proof_bytes as f64));
    }

    let mut generated = Vec::new();
    for ((tree_size, pattern), strategies) in grouped {
        let mut ordered_series: Vec<(&'static str, Vec<(f64, f64)>)> = Vec::new();
        for &name in &["natural", "leb128"] {
            if let Some(mut series) = strategies.get(name).cloned() {
                if series.is_empty() {
                    continue;
                }
                series.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
                ordered_series.push((name, series));
            }
        }

        if ordered_series.len() < 2 {
            continue;
        }

        let mut min_x = f64::MAX;
        let mut max_x = f64::MIN;
        let mut min_y = f64::MAX;
        let mut max_y = f64::MIN;
        for (_, series) in &ordered_series {
            for &(x, y) in series {
                min_x = min_x.min(x);
                max_x = max_x.max(x);
                min_y = min_y.min(y);
                max_y = max_y.max(y);
            }
        }
        if min_x == f64::MAX || min_y == f64::MAX {
            continue;
        }

        let x_pad = ((max_x - min_x) * 0.06).max(8.0);
        let y_pad = ((max_y - min_y) * 0.10).max(256.0);

        let filename = format!("coordinate_proof_size_{}_{}.svg", tree_size, pattern);
        let filepath = report_dir.join(&filename);
        let filepath_str = filepath.to_string_lossy().to_string();
        let drawing_area = SVGBackend::new(&filepath_str, (1280, 720)).into_drawing_area();
        drawing_area.fill(&WHITE)?;

        let mut chart = ChartBuilder::on(&drawing_area)
            .margin(28)
            .x_label_area_size(64)
            .y_label_area_size(96)
            .build_cartesian_2d(
                (min_x - x_pad)..(max_x + x_pad),
                (min_y - y_pad)..(max_y + y_pad),
            )?;

        chart
            .configure_mesh()
            .x_desc("input size k (opened leaves)")
            .y_desc("proof size (bytes)")
            .axis_desc_style(("Helvetica Neue", 24).into_font().style(FontStyle::Bold))
            .label_style(("Helvetica Neue", 18).into_font())
            .light_line_style(WHITE.mix(0.0))
            .draw()?;

        for (name, series) in &ordered_series {
            let color = coordinate_strategy_color(name);
            chart
                .draw_series(LineSeries::new(series.clone(), color.stroke_width(4)))?
                .label(coordinate_strategy_label(name))
                .legend({
                    let color = color.clone();
                    move |(x, y)| PathElement::new(vec![(x, y), (x + 28, y)], color.stroke_width(4))
                });

            chart.draw_series(
                series
                    .iter()
                    .map(|point| Circle::new(*point, 5, color.filled())),
            )?;
        }

        chart
            .configure_series_labels()
            .position(SeriesLabelPosition::UpperLeft)
            .background_style(WHITE.mix(0.85))
            .border_style(BLACK)
            .label_font(("Helvetica Neue", 22).into_font().style(FontStyle::Bold))
            .draw()?;

        generated.push(filename);
    }

    Ok(generated)
}

fn write_leb128_vs_delta_plots(
    rows: &[CoordinateSizeRow],
    report_dir: &Path,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut grouped: BTreeMap<(usize, &'static str), BTreeMap<&'static str, Vec<(f64, f64)>>> =
        BTreeMap::new();

    for row in rows {
        grouped
            .entry((row.tree_size, row.pattern))
            .or_default()
            .entry(row.strategy)
            .or_default()
            .push((row.batch as f64, row.proof_bytes as f64));
    }

    let mut generated = Vec::new();
    for ((tree_size, pattern), strategies) in grouped {
        let mut ordered_series: Vec<(&'static str, Vec<(f64, f64)>)> = Vec::new();
        for &name in &["leb128", "delta"] {
            if let Some(mut series) = strategies.get(name).cloned() {
                if series.is_empty() {
                    continue;
                }
                series.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
                ordered_series.push((name, series));
            }
        }

        if ordered_series.len() < 2 {
            continue;
        }

        let mut min_x = f64::MAX;
        let mut max_x = f64::MIN;
        let mut min_y = f64::MAX;
        let mut max_y = f64::MIN;
        for (_, series) in &ordered_series {
            for &(x, y) in series {
                min_x = min_x.min(x);
                max_x = max_x.max(x);
                min_y = min_y.min(y);
                max_y = max_y.max(y);
            }
        }
        if min_x == f64::MAX || min_y == f64::MAX {
            continue;
        }

        let x_pad = ((max_x - min_x) * 0.06).max(8.0);
        let y_pad = ((max_y - min_y) * 0.10).max(256.0);

        let filename = format!("leb128_vs_delta_proof_size_{}_{}.svg", tree_size, pattern);
        let filepath = report_dir.join(&filename);
        let filepath_str = filepath.to_string_lossy().to_string();
        let drawing_area = SVGBackend::new(&filepath_str, (1280, 720)).into_drawing_area();
        drawing_area.fill(&WHITE)?;

        let mut chart = ChartBuilder::on(&drawing_area)
            .margin(28)
            .x_label_area_size(64)
            .y_label_area_size(96)
            .build_cartesian_2d(
                (min_x - x_pad)..(max_x + x_pad),
                (min_y - y_pad)..(max_y + y_pad),
            )?;

        chart
            .configure_mesh()
            .x_desc("input size k (opened leaves)")
            .y_desc("proof size (bytes)")
            .axis_desc_style(("Helvetica Neue", 24).into_font().style(FontStyle::Bold))
            .label_style(("Helvetica Neue", 18).into_font())
            .light_line_style(WHITE.mix(0.0))
            .draw()?;

        for (name, series) in &ordered_series {
            let color = leb128_vs_delta_color(name);
            chart
                .draw_series(LineSeries::new(series.clone(), color.stroke_width(4)))?
                .label(leb128_vs_delta_label(name))
                .legend({
                    let color = color.clone();
                    move |(x, y)| PathElement::new(vec![(x, y), (x + 28, y)], color.stroke_width(4))
                });

            chart.draw_series(
                series
                    .iter()
                    .map(|point| Circle::new(*point, 5, color.filled())),
            )?;
        }

        chart
            .configure_series_labels()
            .position(SeriesLabelPosition::UpperLeft)
            .background_style(WHITE.mix(0.85))
            .border_style(BLACK)
            .label_font(("Helvetica Neue", 22).into_font().style(FontStyle::Bold))
            .draw()?;

        generated.push(filename);
    }

    Ok(generated)
}

fn strategy_label(name: &str) -> &str {
    match name {
        "prefix" => "prefix",
        "coset" => "coset",
        _ => name,
    }
}

fn coordinate_strategy_label(name: &str) -> &str {
    match name {
        "natural" => "Unoptimized",
        "leb128" => "Partially Optimized",
        _ => name,
    }
}

fn coordinate_strategy_color(name: &str) -> RGBColor {
    match name {
        "natural" => RGBColor(217, 95, 2),
        "leb128" => RGBColor(27, 158, 119),
        _ => BLACK,
    }
}

fn leb128_vs_delta_label(name: &str) -> &str {
    match name {
        "leb128" => "Partially Optimized",
        "delta" => "Optimized",
        _ => name,
    }
}

fn leb128_vs_delta_color(name: &str) -> RGBColor {
    match name {
        "leb128" => RGBColor(27, 158, 119),
        "delta" => RGBColor(117, 112, 179),
        _ => BLACK,
    }
}

fn strategy_color(name: &str) -> RGBColor {
    match name {
        "prefix" => RED,
        "coset" => BLUE,
        _ => BLACK,
    }
}

fn rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let data = fs::read_to_string("/proc/self/status").ok()?;
        for line in data.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb: u64 = rest
                    .split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                return Some(kb * 1024);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn rss_delta_kb(before: Option<u64>, after: Option<u64>) -> Option<i64> {
    match (before, after) {
        (Some(b), Some(a)) => Some(((a as i64) - (b as i64)) / 1024),
        _ => None,
    }
}

fn combine_rss(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x + y),
        _ => a.or(b),
    }
}

fn serialized_size<T: CanonicalSerialize>(value: &T) -> usize {
    let mut buf = Vec::new();
    value
        .serialize_uncompressed(&mut buf)
        .expect("serialization must succeed");
    buf.len()
}

fn serialized_coordinate_proof_size<P: Config>(
    proof: &CoPath<P>,
    encoding: CoordinateEncoding,
) -> usize {
    let mut buf = Vec::new();
    proof
        .tree_height
        .serialize_uncompressed(&mut buf)
        .expect("tree height serialization must succeed");
    proof
        .leaf_copath
        .serialize_uncompressed(&mut buf)
        .expect("leaf co-path serialization must succeed");
    serialize_inner_copath_absolute(&mut buf, proof, encoding);
    proof
        .leaf_indexes
        .serialize_uncompressed(&mut buf)
        .expect("leaf indexes serialization must succeed");
    buf.len()
}

fn serialize_inner_copath_absolute<P: Config>(
    buf: &mut Vec<u8>,
    proof: &CoPath<P>,
    encoding: CoordinateEncoding,
) {
    let entries = unpack_inner_entries(proof);
    (!entries.is_empty())
        .serialize_uncompressed(&mut *buf)
        .expect("option tag serialization must succeed");
    if entries.is_empty() {
        return;
    }

    entries
        .len()
        .serialize_uncompressed(&mut *buf)
        .expect("coordinate count serialization must succeed");
    for entry in &entries {
        entry
            .depth
            .serialize_uncompressed(&mut *buf)
            .expect("depth serialization must succeed");
        match encoding {
            CoordinateEncoding::Natural => entry
                .index
                .serialize_uncompressed(&mut *buf)
                .expect("index serialization must succeed"),
            CoordinateEncoding::Leb128Index => {
                encode_varint(buf, entry.index as u64);
            }
        }
    }

    entries
        .len()
        .serialize_uncompressed(&mut *buf)
        .expect("digest count serialization must succeed");
    for entry in entries {
        entry
            .digest
            .serialize_uncompressed(&mut *buf)
            .expect("digest serialization must succeed");
    }
}

fn unpack_inner_entries<'a, P: Config>(
    proof: &'a CoPath<P>,
) -> Vec<InnerEntry<'a, P::InnerDigest>> {
    let Some((start_depth, start_index, deltas, digests)) = proof.inner_copath.as_ref() else {
        return Vec::new();
    };
    if digests.is_empty() {
        return Vec::new();
    }

    let mut entries = Vec::with_capacity(digests.len());
    let mut depth = *start_depth as i64;
    let mut index = *start_index as i64;
    entries.push(InnerEntry {
        depth: *start_depth,
        index: *start_index,
        digest: &digests[0],
    });

    let mut cursor = 0usize;
    for digest in digests.iter().skip(1) {
        depth += decode_delta(deltas, &mut cursor).expect("packed depth delta must decode");
        index += decode_delta(deltas, &mut cursor).expect("packed index delta must decode");
        entries.push(InnerEntry {
            depth: usize::try_from(depth).expect("depth must remain non-negative"),
            index: usize::try_from(index).expect("index must remain non-negative"),
            digest,
        });
    }

    assert_eq!(
        cursor,
        deltas.len(),
        "all packed coordinate bytes must be consumed"
    );
    entries
}

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

impl TreeFixture {
    fn log2_size(&self) -> u32 {
        (self.leaves.len() as f64).log2().round() as u32
    }
}
