//! Knowledge about sequencing and analysis files: what a file is, whether it is raw data, a final
//! result, a regenerable intermediate, or a cache, and what to do about it. Rules are advisory —
//! every suggestion keeps raw data and final results, and asks for a check that the producing run
//! finished.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// How valuable a file is to keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Retention {
    /// Instrument output or downloaded raw reads: keep, archive to cold storage.
    Raw,
    /// Pipeline deliverables: keep.
    Final,
    /// Regenerable from inputs once the run succeeded.
    Intermediate,
    /// Same content in a smaller form (compression, CRAM, bigWig).
    Reducible,
    /// Re-downloadable or rebuildable caches.
    Cache,
    /// Scratch and temporary files.
    Temp,
    /// Logs: keep recent, compress or rotate old.
    Log,
    /// Unknown value: ask the owner.
    Review,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileKind {
    pub id: String,
    pub label: String,
    pub retention: Retention,
    pub advice: String,
}

fn kind(id: &str, label: &str, retention: Retention, advice: &str) -> FileKind {
    FileKind { id: id.to_string(), label: label.to_string(), retention, advice: advice.to_string() }
}

/// Ordered: the first matching rule wins; tests run on the lowercased full path.
static RULES: LazyLock<Vec<(Regex, FileKind)>> = LazyLock::new(|| {
    [
        (r#"/work/[0-9a-f]{2}/[0-9a-f]{20,}/"#, "nextflow-work", "Nextflow work directory", Retention::Intermediate, r#"Task scratch of a Nextflow run. After the run completed and results were published, `nextflow clean -f` (or remove work/) — keep it only while you may `-resume`."#),
        (r#"/\.snakemake/(?:shadow|incomplete|conda-archive|singularity|metadata)/"#, "snakemake-meta", "Snakemake shadow/metadata", Retention::Intermediate, r#"Snakemake bookkeeping; shadow/ and incomplete/ can go once no run is active (`snakemake --cleanup-shadow`, `--cleanup-metadata`). Conda envs in .snakemake/conda are rebuildable."#),
        (r#"/_star(?:tmp|genome)/|_startmp/"#, "star-tmp", "STAR temporary", Retention::Temp, r#"STAR leftovers of a finished or crashed alignment; remove when no STAR process is running."#),
        (r#"/sc_(?:rna|atac|multi|vdj)_[a-z_]*cs/"#, "cellranger-pipeline", "Cell Ranger pipeline stage", Retention::Intermediate, r#"Cell Ranger internal stage directories; when outs/ (web_summary.html, filtered matrices) exists the stage directory can be removed."#),
        (r#"/(?:gatk_tmp|tmp_gatk|\.gatk)|\.tmp\.[0-9]+\.bam$|\.bam\.tmp\.[0-9]{4}\.bam$|\.sorting\.bam$"#, "gatk-tmp", "sort/GATK temporary", Retention::Temp, r#"Temporary sort or GATK files from an interrupted job; remove if no process holds them."#),
        (r#"\.(?:c?bcl)(?:\.gz|\.bgzf)?$|/thumbnail_images/"#, "bcl", "Illumina run data (BCL)", Retention::Raw, r#"Raw sequencer output. Once demultiplexed FASTQ is verified, archive the run folder (or keep per your facility policy) instead of keeping it on fast storage."#),
        (r#"\.(?:fast5|pod5|blow5|slow5)$"#, "nanopore-raw", "Nanopore raw signal", Retention::Raw, r#"Raw signal is needed for re-basecalling. Archive to cold storage; POD5 is smaller than FAST5 (`pod5 convert fast5`)."#),
        (r#"\.sra(?:lite)?$"#, "sra", "SRA archive", Retention::Intermediate, r#"Re-downloadable by accession. After fasterq-dump produced (and you checked) FASTQ, delete the .sra."#),
        (r#"(?:trim|clean|filtered|_val_[12]|\.paired|\.unpaired|_unpaired|fastp|cutadapt|\.qc\.)[^/]*\.(?:fastq|fq)(?:\.gz|\.bz2|\.zst)?$"#, "fastq-trimmed", "Trimmed/filtered FASTQ", Retention::Intermediate, r#"Regenerable from raw reads with the logged trimming command. Delete once alignments are final."#),
        (r#"\.(?:fastq|fq)$"#, "fastq-plain", "Uncompressed FASTQ", Retention::Reducible, r#"Compress (`pigz -p 8` or `zstd -T8`); aligners and most tools read .gz directly. Typically 3–5× smaller."#),
        (r#"\.(?:fastq|fq)\.(?:gz|bz2|xz|zst)$|\.(?:fastq|fq)\.ora$"#, "fastq", "Raw FASTQ", Retention::Raw, r#"Raw reads: keep, and archive a verified copy (md5sum) to cold storage."#),
        (r#"\.(?:fa|fasta|fna|ffn|faa)$"#, "fasta-plain", "Uncompressed FASTA", Retention::Reducible, r#"Large FASTA can be bgzip-compressed (`bgzip` + `samtools faidx` keeps random access)."#),
        (r#"\.sam$"#, "sam", "SAM alignment", Retention::Reducible, r#"Uncompressed alignments. Convert to sorted BAM/CRAM (`samtools sort -@8 -o x.bam x.sam && samtools quickcheck x.bam`), then delete the SAM."#),
        (r#"(?:unsorted|\.raw|aligned\.out|\.unsort)[^/]*\.bam$"#, "bam-unsorted", "Unsorted BAM", Retention::Intermediate, r#"Pre-sort alignment; delete once the sorted, indexed BAM passes `samtools quickcheck`."#),
        (r#"\.bam$"#, "bam", "BAM alignment", Retention::Reducible, r#"Final alignments can be stored as CRAM (`samtools view -C -T ref.fa`, roughly 40–60% smaller) once the reference FASTA is archived with it."#),
        (r#"\.cram$"#, "cram", "CRAM alignment", Retention::Final, r#"Keep together with the exact reference FASTA it was encoded against."#),
        (r#"\.(?:bai|crai|csi|tbi|fai|gzi)$"#, "index", "Index", Retention::Final, r#"Small; keep or delete together with the file it indexes."#),
        (r#"\.g\.vcf(?:\.gz)?$"#, "gvcf", "gVCF", Retention::Review, r#"Needed to re-run joint genotyping with new samples; delete only when the cohort is final."#),
        (r#"\.vcf$"#, "vcf-plain", "Uncompressed VCF", Retention::Reducible, r#"Compress and index: `bgzip x.vcf && tabix -p vcf x.vcf.gz` (or convert to BCF)."#),
        (r#"\.(?:vcf\.gz|bcf)$"#, "vcf", "Variant calls", Retention::Final, r#"Results: keep."#),
        (r#"\.(?:bedgraph|bdg|wig)$"#, "track-plain", "Text coverage track", Retention::Reducible, r#"Convert to bigWig (`bedGraphToBigWig`) and remove the text track."#),
        (r#"\.(?:mpileup|pileup)$"#, "pileup", "Pileup", Retention::Intermediate, r#"Regenerable from BAM; delete after variant calling."#),
        (r#"\.(?:h5ad|loom|rds|rdata|rda|h5seurat|qs)$"#, "sc-object", "Analysis object", Retention::Review, r#"Checkpoints of interactive analysis; keep the latest per project, ask the owner about older ones."#),
        (r#"\.(?:mtx|mtx\.gz|h5)$"#, "matrix", "Count matrix / HDF5", Retention::Final, r#"Usually results; keep."#),
        (r#"/core(?:\.[0-9]+)?$|\.core$"#, "core", "Core dump", Retention::Temp, r#"Crash dump; inspect with gdb if needed, then delete."#),
        (r#"\.(?:tar|tar\.gz|tgz|tar\.bz2|tar\.zst|zip|7z)$"#, "archive", "Archive", Retention::Review, r#"If it has already been extracted, keep either the archive or the extracted copy, not both."#),
        (r#"\.(?:log|out|err)\.(?:[0-9]+|gz|xz)$"#, "log-rotated", "Rotated log", Retention::Log, r#"Old rotated logs; compress or delete beyond your retention period."#),
        (r#"\.(?:log|out|err|stdout|stderr)$|/slurm-[0-9]+(?:_[0-9]+)?\.out$"#, "log", "Log", Retention::Log, r#"Large logs: check what is writing them (verbosity), compress old ones; never delete a log a process still writes."#),
        (r#"\.(?:ckpt|pt|pth|safetensors|bin|onnx)$"#, "checkpoint", "Model weights / checkpoint", Retention::Review, r#"Training checkpoints: keep the best and latest, ask the owner about the rest."#),
        (r#"/\.cache/|/pkgs/|/\.conda/|/site-packages/|/node_modules/"#, "cache", "Cache / packages", Retention::Cache, r#"Rebuildable caches: `conda clean --all`, `pip cache purge`, `huggingface-cli delete-cache` as the owning user."#),
        (r#"/(?:tmp|temp|scratch)/|\.(?:tmp|temp|swp|part)$"#, "temp", "Temporary", Retention::Temp, r#"Scratch files; remove those older than a few days that no process holds."#),
    ]
    .into_iter()
    .map(|(test, id, label, retention, advice)| (Regex::new(test).unwrap(), kind(id, label, retention, advice)))
    .collect()
});

fn other() -> FileKind {
    kind("other", "Other", Retention::Review, "Unclassified; ask the owner.")
}

pub fn classify_path(path: &str) -> FileKind {
    let lower = path.to_lowercase();
    RULES.iter().find(|(test, _)| test.is_match(&lower)).map_or_else(other, |(_, kind)| kind.clone())
}

pub fn kind_by_id(id: &str) -> FileKind {
    RULES.iter().find(|(_, kind)| kind.id == id).map_or_else(other, |(_, kind)| kind.clone())
}

static READ_PAIR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)_(?:r?[12]|read[12])$").unwrap());
static FASTQ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(?:fastq|fq)(?:\.gz|\.zst|\.bz2)?$").unwrap());
static SRA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.sra(?:lite)?$").unwrap());
static UNCOMPRESSED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\.(?:fastq|fq|vcf|fa|fasta)$").unwrap());

/// Sample stem: file name up to its first dot, with read-pair markers removed.
fn stem(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    READ_PAIR.replace(name.split('.').next().unwrap_or(name), "").into_owned()
}

/// Everything before the last `/`; a path without one loses its last character, as in the original.
fn dir_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(cut) => &path[..cut],
        None => path.char_indices().next_back().map_or("", |(index, _)| &path[..index]),
    }
}

/// Stage words that mark a BAM as derived from an earlier BAM of the same sample.
const BAM_STAGES: [&str; 15] = ["sorted", "sort", "dedup", "dedupped", "markdup", "markdups", "md", "rmdup", "filtered", "filt", "recal", "bqsr", "realigned", "clean", "final"];

fn stage_depth(name: &str) -> usize {
    name.to_lowercase().split(['.', '_', '-']).filter(|part| BAM_STAGES.contains(part)).count()
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Redundancy {
    pub path: String,
    /// The file that makes this one redundant.
    pub superseded_by: String,
    pub reason: String,
}

/// Files made redundant by a sibling: SAM next to BAM/CRAM, BAM next to CRAM, an earlier-stage BAM
/// next to a later-stage BAM of the same sample, plain FASTQ/VCF next to the compressed copy, SRA
/// next to its FASTQ.
pub fn find_redundant<S: AsRef<str>>(paths: &[S]) -> Vec<Redundancy> {
    let mut groups: Vec<Vec<&str>> = Vec::new();
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    for path in paths.iter().map(AsRef::as_ref) {
        let at = *index.entry((dir_of(path).to_string(), stem(path))).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[at].push(path);
    }
    let all: HashSet<&str> = paths.iter().map(AsRef::as_ref).collect();
    let mut out: Vec<Redundancy> = Vec::new();
    let mut add = |path: &str, superseded_by: &str, reason: &str| {
        if !out.iter().any(|r| r.path == path) {
            out.push(Redundancy { path: path.to_string(), superseded_by: superseded_by.to_string(), reason: reason.to_string() });
        }
    };
    for group in &groups {
        let ending = |suffix: &'static str| group.iter().copied().filter(move |p| p.to_lowercase().ends_with(suffix)).collect::<Vec<&str>>();
        let bams = ending(".bam");
        let crams = ending(".cram");
        let fastqs: Vec<&str> = group.iter().copied().filter(|p| FASTQ.is_match(&p.to_lowercase())).collect();
        for sam in ending(".sam") {
            if let Some(target) = bams.first().or(crams.first()) {
                add(sam, target, "a BAM/CRAM of the same sample exists; verify it with `samtools quickcheck` and delete the SAM");
            }
        }
        if let Some(cram) = crams.first() {
            for bam in &bams {
                add(bam, cram, "a CRAM of the same sample exists; verify it, then the BAM is a duplicate");
            }
        } else if bams.len() > 1 {
            let mut by_depth = bams.clone();
            by_depth.sort_by_key(|bam| std::cmp::Reverse(stage_depth(bam)));
            let deepest = by_depth[0];
            for bam in &bams {
                if *bam != deepest && stage_depth(bam) < stage_depth(deepest) {
                    add(bam, deepest, "a later processing stage of the same sample exists; this earlier-stage BAM is an intermediate once the final BAM is validated");
                }
            }
        }
        for sra in group.iter().filter(|p| SRA.is_match(&p.to_lowercase())) {
            if let Some(fastq) = fastqs.first() {
                add(sra, fastq, "FASTQ already extracted from this SRA");
            }
        }
    }
    for path in paths.iter().map(AsRef::as_ref) {
        if UNCOMPRESSED.is_match(&path.to_lowercase())
            && let Some(compressed) = [".gz", ".zst", ".bz2"].iter().map(|ext| format!("{path}{ext}")).find(|p| all.contains(p.as_str()))
        {
            add(path, &compressed, "a compressed copy exists; verify it (`gzip -t` / `zstd -t`), then remove the uncompressed file");
        }
    }
    out
}

/// Cleanup preference: what is offered first when sizes tie.
pub const RETENTION_ORDER: [Retention; 8] = [Retention::Temp, Retention::Intermediate, Retention::Cache, Retention::Reducible, Retention::Log, Retention::Review, Retention::Final, Retention::Raw];

pub fn retention_label(retention: Retention) -> &'static str {
    match retention {
        Retention::Raw => "raw data — keep/archive",
        Retention::Final => "results — keep",
        Retention::Intermediate => "regenerable intermediate",
        Retention::Reducible => "can be compressed/converted",
        Retention::Cache => "rebuildable cache",
        Retention::Temp => "temporary",
        Retention::Log => "log",
        Retention::Review => "ask the owner",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_paths() {
        for (path, id, retention) in [
            ("/data/run1/Sample_R1.fastq.gz", "fastq", Retention::Raw),
            ("/data/run1/trimmed/Sample_R1_val_1.fq.gz", "fastq-trimmed", Retention::Intermediate),
            ("/data/run1/Sample.fastq", "fastq-plain", Retention::Reducible),
            ("/data/aln/S1.sam", "sam", Retention::Reducible),
            ("/data/aln/S1.sorted.markdup.bam", "bam", Retention::Reducible),
            ("/data/aln/S1.Aligned.out.bam", "bam-unsorted", Retention::Intermediate),
            ("/data/aln/S1.cram", "cram", Retention::Final),
            ("/data/proj/work/3f/a1b2c3d4e5f60718293a4b5c6d7e8f/S1.bam", "nextflow-work", Retention::Intermediate),
            ("/data/proj/.snakemake/shadow/tmpx/out.txt", "snakemake-meta", Retention::Intermediate),
            ("/data/sc/S1/SC_RNA_COUNTER_CS/SC_RNA_COUNTER/x.h5", "cellranger-pipeline", Retention::Intermediate),
            ("/data/sra/SRR123.sra", "sra", Retention::Intermediate),
            ("/data/ont/run/x.pod5", "nanopore-raw", Retention::Raw),
            ("/data/vc/cohort.g.vcf.gz", "gvcf", Retention::Review),
            ("/data/vc/cohort.vcf", "vcf-plain", Retention::Reducible),
            ("/data/vc/cohort.vcf.gz", "vcf", Retention::Final),
            ("/home/alice/analysis/obj.h5ad", "sc-object", Retention::Review),
            ("/home/alice/.cache/pip/http/x", "cache", Retention::Cache),
            ("/data/logs/slurm-12345.out", "log", Retention::Log),
            ("/data/random/blob.dat", "other", Retention::Review),
        ] {
            let kind = classify_path(path);
            assert_eq!((kind.id.as_str(), kind.retention), (id, retention), "{path}");
            assert_eq!(kind_by_id(id), kind);
        }
        assert_eq!(RULES.len(), 31);
        assert_eq!(kind_by_id("nope").id, "other");
    }

    #[test]
    fn finds_files_a_sibling_supersedes() {
        let redundant = find_redundant(&["/d/S1.sam", "/d/S1.bam", "/d/S2.sorted.bam", "/d/S2.sorted.markdup.bam", "/d/S3.bam", "/d/S3.cram", "/d/SRR9.sra", "/d/SRR9_1.fastq.gz", "/d/x.fastq", "/d/x.fastq.gz", "/d/other/S1.bam"]);
        let by: Vec<(&str, &str)> = redundant.iter().map(|r| (r.path.as_str(), r.superseded_by.as_str())).collect();
        assert_eq!(by, [("/d/S1.sam", "/d/S1.bam"), ("/d/S2.sorted.bam", "/d/S2.sorted.markdup.bam"), ("/d/S3.bam", "/d/S3.cram"), ("/d/SRR9.sra", "/d/SRR9_1.fastq.gz"), ("/d/x.fastq", "/d/x.fastq.gz")]);
    }
}
