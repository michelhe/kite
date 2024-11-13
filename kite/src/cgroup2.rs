use std::{
    path::{Path, PathBuf},
    str::Lines,
    sync::{Mutex as StdMutex, Once},
};

use anyhow::Context as _;

static mut CACHED_CGROUP2_MOUNT: Option<StdMutex<PathBuf>> = None;
static INIT: Once = Once::new();

pub fn find_cgroup2_mount() -> PathBuf {
    INIT.call_once(|| {
        let mounts: String = std::fs::read_to_string("/proc/1/mounts")
            .context("Failed to read /proc/1/mounts")
            .unwrap();

        let mount = mounts
            .lines()
            .find(|line| line.contains("cgroup2"))
            .context("cgroup2 mount not found")
            .unwrap();

        let mount_path = mount.split_whitespace().nth(1).unwrap();

        unsafe {
            CACHED_CGROUP2_MOUNT = Some(StdMutex::new(PathBuf::from(mount_path)));
        }
    });

    unsafe { CACHED_CGROUP2_MOUNT.as_ref().unwrap().lock().unwrap() }.clone()
}

pub struct ProcCgroupEntry {
    pub hier_id: u32,
    pub controller_list: Vec<String>,
    pub cgroup_path: String,
}
impl ProcCgroupEntry {
    pub fn new(hier_id: u32, controller_list: String, cgroup_path: String) -> Self {
        let controller_list = controller_list.split(',').map(|s| s.to_string()).collect();
        Self {
            hier_id,
            controller_list,
            cgroup_path,
        }
    }
}

pub struct ProcCgroupParser {
    lines: Lines<'static>,
    _content: Box<str>,
}

impl Iterator for ProcCgroupParser {
    type Item = ProcCgroupEntry;

    fn next(&mut self) -> Option<Self::Item> {
        self.lines.next().map(|line| {
            let mut split = line.split(':');
            let hier_id = split.next().unwrap().parse().unwrap();
            let controller_list = split.next().unwrap().to_string();
            let cgroup_path = split.next().unwrap().to_string();
            ProcCgroupEntry::new(hier_id, controller_list, cgroup_path)
        })
    }
}
pub fn parse_proc_cgroup(pid: &str) -> anyhow::Result<ProcCgroupParser> {
    let proc_cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", pid))
        .context("Failed reading /proc/pid/cgroup")?;
    let boxed_content = proc_cgroup.into_boxed_str();
    let lines = Box::leak(boxed_content.clone()).lines();
    Ok(ProcCgroupParser {
        lines,
        _content: boxed_content,
    })
}

pub fn get_my_cgroup() -> anyhow::Result<PathBuf> {
    let cgroup2_mount = find_cgroup2_mount();

    let cgroup_entry = parse_proc_cgroup("self")?
        .find(|entry| entry.hier_id == 0)
        .context("Could not a cgroup entry with hier_id 0")?;

    Ok(cgroup2_mount.join(Path::new(
        cgroup_entry
            .cgroup_path
            .strip_prefix("/")
            .context("Should start with /")?,
    )))
}
