//! Capability probe: what a host is (OS, cores, GPUs, scheduler, containers) and what this login
//! may do (root, passwordless sudo). The result becomes planning guidance: no GPU means no GPU
//! work, no sudo means no privileged plan without a stored sudo password.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::sections::parse_sections;
use crate::util::{OrderedMap, js_number, to_iso};

/// The probe script; [`parse_probe`] reads its output.
pub const PROBE_SCRIPT: &str = include_str!("scripts/probe.sh");

/// root, passwordless sudo, sudo that needs a password, or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Privilege {
    Root,
    SudoNopasswd,
    SudoPassword,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeScheduler {
    Slurm,
    Pbs,
    Sge,
    Lsf,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DockerAccess {
    Usable,
    NoPermission,
    Absent,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostProbe {
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cores: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub privilege: Privilege,
    pub gpus: u32,
    pub scheduler: ProbeScheduler,
    pub docker: DockerAccess,
    pub systemd: bool,
}

/// Parse the probe output; `None` when the script did not run to its end marker.
pub fn parse_probe(output: &str, at: DateTime<Utc>) -> Option<HostProbe> {
    let s = parse_sections(output);
    if !s.has("end") {
        return None;
    }
    let mut kv: OrderedMap<String> = OrderedMap::new();
    for line in s.get("kv") {
        if let Some(eq) = line.find('=').filter(|eq| *eq > 0) {
            kv.insert(&line[..eq], line[eq + 1..].trim().to_string());
        }
    }
    let get = |key: &str| kv.get(key).map(String::as_str).filter(|value| !value.is_empty());
    let text = |key: &str| get(key).map(str::to_string);
    let privilege = match (get("uid"), get("sudo")) {
        (Some("0"), _) => Privilege::Root,
        (_, Some("nopasswd")) => Privilege::SudoNopasswd,
        (_, Some("password")) => Privilege::SudoPassword,
        _ => Privilege::None,
    };
    let cores = get("cores").map(js_number).filter(|cores| cores.is_finite() && cores.fract() == 0.0 && *cores > 0.0);
    let gpus = get("gpus").map(js_number).filter(|gpus| gpus.is_finite() && *gpus > 0.0);
    Some(HostProbe {
        at: to_iso(at),
        os: text("os"),
        kernel: text("kernel"),
        arch: text("arch"),
        hostname: text("hostname"),
        cores: cores.map(|cores| cores as u32),
        user: text("user"),
        privilege,
        gpus: gpus.map_or(0, |gpus| gpus as u32),
        scheduler: match get("scheduler") {
            Some("slurm") => ProbeScheduler::Slurm,
            Some("pbs") => ProbeScheduler::Pbs,
            Some("sge") => ProbeScheduler::Sge,
            Some("lsf") => ProbeScheduler::Lsf,
            _ => ProbeScheduler::None,
        },
        docker: match get("docker") {
            Some("usable") => DockerAccess::Usable,
            Some("no-permission") => DockerAccess::NoPermission,
            _ => DockerAccess::Absent,
        },
        systemd: get("systemd") == Some("yes"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::testing::assert_golden;

    #[test]
    fn parses_capabilities() {
        let probe = parse_probe("motd\n@@kv\nos=Rocky Linux 9\narch=x86_64\ncores=64\nuid=1000\nuser=alice\nsudo=password\ngpus=8\nscheduler=slurm\ndocker=no-permission\nsystemd=yes\n@@end\n", DateTime::UNIX_EPOCH).unwrap();
        assert_eq!((probe.privilege, probe.gpus, probe.scheduler, probe.docker, probe.cores), (Privilege::SudoPassword, 8, ProbeScheduler::Slurm, DockerAccess::NoPermission, Some(64)));
        assert_golden(&probe, include_str!("testdata/probe.json"));
        assert_eq!(serde_json::from_str::<HostProbe>(include_str!("testdata/probe.json")).unwrap(), probe);
        assert_eq!(parse_probe("restricted shell", DateTime::UNIX_EPOCH), None);
    }

    #[test]
    fn falls_back_when_probes_print_nothing() {
        let probe = parse_probe("@@kv\nuid=0\ncores=\ngpus=\nsudo=nopasswd\n@@end\n", DateTime::UNIX_EPOCH).unwrap();
        assert_eq!((probe.privilege, probe.cores, probe.gpus, probe.scheduler, probe.docker, probe.systemd), (Privilege::Root, None, 0, ProbeScheduler::None, DockerAccess::Absent, false));
        assert!(PROBE_SCRIPT.ends_with("echo @@end\n"));
    }
}
