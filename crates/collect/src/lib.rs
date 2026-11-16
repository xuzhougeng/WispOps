//! Read-only collectors of WispOps: each is a pure pair of "build a POSIX shell script" and
//! "parse its stdout into a report", plus a rendering of the report as text for a model. Nothing
//! here opens a connection, reads a file or keeps state; callers run the scripts over SSH and
//! store the snapshots.

/// Failed logins by source, account and hour: the tail of the security triage the security page runs.
pub mod attacks;
/// Disk-full diagnosis of one path: usage, growth, open and deleted files, reclaimable caches.
pub mod disk;
/// Recent-file analysis with a cleanup plan ordered by reclaimable space.
pub mod files;
/// Fleet inspection: the script, its report, thresholds turned into findings, and trend metrics.
pub mod inspect;
/// Running Slurm, PBS and LSF jobs and their working directories.
pub mod jobs;
/// User processes and scheduler jobs that have run longer than a threshold.
pub mod longrun;
/// Muted findings: problems the owner acknowledged for a while.
pub mod mutes;
/// What sequencing and analysis files are and how long they are worth keeping.
pub mod omics;
/// Fleet overview: status matrix, sparkline metrics, reachability and disk forecasts per host.
pub mod overview;
/// Capability probe: what a host is and what the login may do.
pub mod probe;
/// Model-facing text for fleet command output and fleet inspections.
pub mod render;
/// `@@name` sections of collector output, `df` parsing, and size formatting.
pub mod sections;
/// Security triage: logins, connections, suspicious processes and persistence points.
pub mod security;
/// Owner-listed service checks added to the inspection script.
pub mod service_checks;
/// Directory space map of one path and the size tree the panel draws.
pub mod space;
/// Trends over the inspection history: rendered changes, disk-full forecast, reachability.
pub mod trends;
/// Thresholds, stored history records, and fleet inspection results.
pub mod types;
/// JavaScript-compatible number and date helpers, shell quoting, and an order-keeping JSON object.
pub mod util;

pub use types::{FleetCounts, FleetInspection, HistoryRecord, HostInspectionResult, Thresholds};
pub use util::{OrderedMap, shell_quote};
