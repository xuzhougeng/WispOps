//! Running scheduler jobs (Slurm, PBS, LSF) and their working directories, so cleanup advice
//! never touches a directory a job still uses.

use serde::{Deserialize, Serialize};

use crate::sections::Sections;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheduler {
    Slurm,
    Pbs,
    Lsf,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerJob {
    pub id: String,
    pub user: String,
    pub workdir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheduler: Option<Scheduler>,
}

/// Query only directory metadata; never send a complete PBS environment to the model.
pub const JOBS_SCRIPT: &str = include_str!("scripts/jobs.sh");

pub fn parse_scheduler_jobs(sections: &Sections) -> Vec<SchedulerJob> {
    let mut jobs = Vec::new();
    for (section, scheduler) in [("jobs", Scheduler::Slurm), ("pbs_jobs", Scheduler::Pbs), ("lsf_jobs", Scheduler::Lsf)] {
        for line in sections.get(section) {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let cell = |index: usize| cells.get(index).copied();
            let (id, user, workdir) = if scheduler == Scheduler::Lsf {
                if !["RUN", "SSUSP", "USUSP", "PSUSP"].contains(&cell(1).unwrap_or("")) {
                    continue;
                }
                (cell(0), cell(2), if cell(3).is_some_and(|cwd| cwd.starts_with('/')) { cell(3) } else { cell(4) })
            } else {
                (cell(0), cell(1), cell(2))
            };
            let (Some(id), Some(user), Some(workdir)) = (id, user, workdir) else { continue };
            if id.is_empty() || user.is_empty() || !workdir.starts_with('/') || workdir.contains(['\0', '\r', '\n']) {
                continue;
            }
            let trimmed = workdir.trim_end_matches('/');
            jobs.push(SchedulerJob { id: id.to_string(), user: user.to_string(), workdir: if trimmed.is_empty() { "/".to_string() } else { trimmed.to_string() }, scheduler: Some(scheduler) });
        }
    }
    jobs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sections::parse_sections;

    #[test]
    fn uses_lsf_execution_cwd_with_submission_fallback_and_skips_completed_or_queued_jobs() {
        let rows = parse_scheduler_jobs(&parse_sections("@@lsf_jobs\n1|RUN|alice|/data/run|/home/alice\n2|SSUSP|bob|-|/data/fallback\n3|DONE|alice|/data/old|/home/alice\n4|PEND|bob|-|/data/queued\n5|RUN|alice|-|relative"));
        assert_eq!(rows.iter().map(|r| r.workdir.as_str()).collect::<Vec<_>>(), ["/data/run", "/data/fallback"]);
    }

    #[test]
    fn reads_slurm_and_pbs_rows() {
        let rows = parse_scheduler_jobs(&parse_sections("@@jobs\n1001|bob|/data/projects/bob/\n|x|/y\n@@pbs_jobs\n123.server|alice|/data/long/run\n125.server|alice|/\n"));
        assert_eq!(rows, [
            SchedulerJob { id: "1001".into(), user: "bob".into(), workdir: "/data/projects/bob".into(), scheduler: Some(Scheduler::Slurm) },
            SchedulerJob { id: "123.server".into(), user: "alice".into(), workdir: "/data/long/run".into(), scheduler: Some(Scheduler::Pbs) },
            SchedulerJob { id: "125.server".into(), user: "alice".into(), workdir: "/".into(), scheduler: Some(Scheduler::Pbs) },
        ]);
    }

    /// The PBS query runs a fake `qstat` through the real shell: wrapped records are joined and
    /// nothing but the working directory leaves the environment list.
    #[cfg(unix)]
    #[test]
    fn extracts_active_pbs_jobs_without_returning_environment_secrets() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("wisp-pbs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let qstat = dir.join("qstat");
        std::fs::write(&qstat, "#!/bin/sh\ncat <<'DATA'\nJob Id: 123.server\n    Job_Owner = alice@submit\n    job_state = R\n    Variable_List = TOKEN=do-not-return,PBS_O_WORKDIR=/data/long/\n        run,PBS_O_HOME=/home/alice\n    queue = workq\nJob Id: 124.server\n    Job_Owner = bob@submit\n    job_state = Q\n    Variable_List = PBS_O_WORKDIR=/data/queued\nJob Id: 125.server\n    Job_Owner = alice@submit\n    job_state = E\n    Variable_List = PBS_O_WORKDIR=/data/finishing\nDATA\n").unwrap();
        std::fs::set_permissions(&qstat, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = std::process::Command::new("sh").arg("-c").arg(JOBS_SCRIPT).env("PATH", format!("{}:/usr/bin:/bin", dir.display())).output().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.contains("do-not-return"));
        let jobs: Vec<_> = parse_scheduler_jobs(&parse_sections(&stdout)).into_iter().map(|j| (j.id, j.user, j.workdir, j.scheduler)).collect();
        assert_eq!(jobs, [
            ("123.server".to_string(), "alice".to_string(), "/data/long/run".to_string(), Some(Scheduler::Pbs)),
            ("125.server".to_string(), "alice".to_string(), "/data/finishing".to_string(), Some(Scheduler::Pbs)),
        ]);
    }
}
