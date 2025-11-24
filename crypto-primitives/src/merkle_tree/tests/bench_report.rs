use crate::merkle_tree::{
    tests::test_utils::poseidon_parameters, Config, IdentityDigestConverter, LeafParam,
    MerkleTree, MultiPath, MultiPathV2, MultiPathV2Bench, Path as MerklePath, TwoToOneParam,
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

type FieldMT = MerkleTree<FieldMTConfig>;

const TREE_EXPONENTS: &[u32] = &[12, 14, 16, 18, 20];
const BATCH_SIZES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096];
const LEAF_WIDTH: usize = 3;

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
    leaf_params: LeafParam<FieldMTConfig>,
    two_to_one_params: TwoToOneParam<FieldMTConfig>,
}

#[derive(CanonicalSerialize)]
struct NoPruneBatch<P: Config> {
    paths: Vec<MerklePath<P>>,
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

trait ProofStats {
    fn opened(&self) -> usize;
    fn total_nodes(&self) -> usize;
}

impl<P: Config> ProofStats for MultiPath<P> {
    fn opened(&self) -> usize {
        self.leaf_indexes.len()
    }

    fn total_nodes(&self) -> usize {
        let auth_len: usize = self
            .auth_paths_suffixes
            .iter()
            .map(|path| path.len())
            .sum();
        self.leaf_siblings_hashes.len() + auth_len
    }
}

impl<P: Config> ProofStats for MultiPathV2Bench<P> {
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

impl<P: Config> ProofStats for MultiPathV2<P> {
    fn opened(&self) -> usize {
        self.leaf_indexes.len()
    }

    fn total_nodes(&self) -> usize {
        self.leaf_copath.len() + self.inner_copath.len()
    }
}

impl<P: Config> ProofStats for NoPruneBatch<P> {
    fn opened(&self) -> usize {
        self.paths.len()
    }

    fn total_nodes(&self) -> usize {
        self.paths
            .iter()
            .map(|path| 1 + path.auth_path.len())
            .sum()
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
        name: "Proof Nodes",
        filename_prefix: "proof_nodes",
        y_label: "proof nodes",
        value: |row: &ReportRow| Some(row.proof_nodes as f64),
    },
    PlotMetric {
        name: "Hashes Per Opening",
        filename_prefix: "hashes_per_opening",
        y_label: "hashes per opened leaf",
        value: |row: &ReportRow| Some(row.hashes_per_opening),
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
    PlotMetric {
        name: "RSS Delta",
        filename_prefix: "rss_delta_kb",
        y_label: "rss delta (kB)",
        value: |row: &ReportRow| row.rss_delta_kb.map(|kb| kb as f64),
    },
];

#[test]
#[ignore]
fn multiproof_v2_benchmark_report() {
    run_report().expect("benchmark report must succeed");
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

fn run_scenario(
    fixture: &TreeFixture,
    batch: usize,
    pattern: IndexPattern,
    indexes: &[usize],
) -> Result<[ReportRow; 4], Box<dyn std::error::Error>> {
    let root = fixture.tree.root();
    let opened_leaves: Vec<Vec<F>> = indexes.iter().map(|&i| fixture.leaves[i].clone()).collect();

    let legacy_row = benchmark_strategy(
        "prefix",
        || fixture.tree.generate_multi_proof(indexes.iter().copied()),
        |proof, leaves| {
            proof.verify(
                &fixture.leaf_params,
                &fixture.two_to_one_params,
                &root,
                leaves,
            )
        },
        &opened_leaves,
        fixture.leaves.len(),
        fixture.log2_size(),
        batch,
        pattern,
    )?;

    let no_prune_row = benchmark_strategy(
        "no_prune",
        || {
            let mut paths = Vec::with_capacity(indexes.len());
            for &idx in indexes.iter() {
                paths.push(fixture.tree.generate_proof(idx)?);
            }
            Ok(NoPruneBatch { paths })
        },
        |proof: &NoPruneBatch<_>, leaves| {
            if proof.paths.len() != leaves.len() {
                return Err(crate::Error::IncorrectInputLength(proof.paths.len()));
            }
            for (path, leaf) in proof.paths.iter().zip(leaves.iter()) {
                let ok = path.verify(
                    &fixture.leaf_params,
                    &fixture.two_to_one_params,
                    &root,
                    leaf.as_slice(),
                )?;
                if !ok {
                    return Ok(false);
                }
            }
            Ok(true)
        },
        &opened_leaves,
        fixture.leaves.len(),
        fixture.log2_size(),
        batch,
        pattern,
    )?;

    let coset_row = benchmark_strategy(
        "coset_v2",
        || {
            fixture
                .tree
                .generate_multi_proof_v2(indexes.iter().copied())
        },
        |proof: &MultiPathV2<_>, leaves| {
            proof.verify(
                &fixture.leaf_params,
                &fixture.two_to_one_params,
                &root,
                leaves,
            )
        },
        &opened_leaves,
        fixture.leaves.len(),
        fixture.log2_size(),
        batch,
        pattern,
    )?;

    let coset_bench_row = benchmark_strategy(
        "coset_v2_bench",
        || {
            fixture
                .tree
                .generate_multi_proof_v2_bench(indexes.iter().copied())
        },
        |proof: &MultiPathV2Bench<_>, leaves| {
            proof.verify(
                &fixture.leaf_params,
                &fixture.two_to_one_params,
                &root,
                leaves,
            )
        },
        &opened_leaves,
        fixture.leaves.len(),
        fixture.log2_size(),
        batch,
        pattern,
    )?;

    Ok([legacy_row, no_prune_row, coset_row, coset_bench_row])
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
    assert!(verify_ok, "verification must succeed for {}", strategy);

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
    let two_to_one_params = leaf_params.clone();

    let num_leaves = 1usize << exp;
    let mut rng = StdRng::seed_from_u64(0x5EED_C0DE_u64 ^ (exp as u64));
    let leaves = sample_leaves(num_leaves, &mut rng);

    let tree = FieldMT::new(&leaf_params, &two_to_one_params, &leaves).unwrap();

    Ok(TreeFixture {
        leaves,
        tree,
        leaf_params,
        two_to_one_params,
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
            writeln!(file, "![{}]({})", metric.replace(' ', "-").to_lowercase(), plot)?;
        }
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
            for &name in &["prefix", "no_prune", "coset_v2", "coset_v2_bench"] {
                if let Some(mut series) = strategies.get(name).cloned() {
                    if series.is_empty() {
                        continue;
                    }
                    series.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
                    ordered_series.push((name, series));
                }
            }

            if ordered_series.len() < 2
                || !ordered_series.iter().any(|(name, _)| *name == "prefix")
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

            let filename = format!(
                "{}_{}_{}.svg",
                metric.filename_prefix, tree_size, pattern
            );
            let filepath = report_dir.join(&filename);
            let filepath_str = filepath.to_string_lossy().to_string();
            let drawing_area = SVGBackend::new(&filepath_str, (960, 540)).into_drawing_area();
            drawing_area.fill(&WHITE)?;

            let mut chart = ChartBuilder::on(&drawing_area)
                .caption(
                    format!("{} vs k (n={}, pattern={})", metric.name, tree_size, pattern),
                    ("sans-serif", 26),
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

            chart.configure_series_labels().border_style(&BLACK).draw()?;

            generated.push(filename);
        }

        outputs.insert(metric.name, generated);
    }

    Ok(outputs)
}

fn strategy_label(name: &str) -> &str {
    match name {
        "prefix" => "prefix",
        "no_prune" => "no pruning",
        "coset_v2" => "coset v2",
        "coset_v2_bench" => "coset v2 (bench)",
        _ => name,
    }
}

fn strategy_color(name: &str) -> RGBColor {
    match name {
        "prefix" => RED,
        "no_prune" => RGBColor(255, 127, 14),
        "coset_v2" => BLUE,
        "coset_v2_bench" => GREEN,
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

fn duration_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

impl TreeFixture {
    fn log2_size(&self) -> u32 {
        (self.leaves.len() as f64).log2().round() as u32
    }
}
