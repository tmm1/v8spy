
use anyhow::{Context, Result};
use spytools::ProcessInfo;

use remoteprocess::{Pid, Process, ProcessMemory};

pub struct V8Spy {
    pub pid: Pid,
    pub process: Process,
}

impl V8Spy {
    pub fn new(pid: Pid) -> Result<Self> {
        let process = remoteprocess::Process::new(pid)
            .context(format!("Failed to open process {} - check if it is running.", pid))?;

        let process_info = ProcessInfo::new::<spytools::process::NodeProcessType>(&process)?;

        // lock the process when loading up on freebsd (rather than locking
        // on every memory read). Needs done after getting python process info
        // because procmaps also tries to attach w/ ptrace on freebsd
        #[cfg(target_os = "freebsd")]
        let _lock = process.lock();

        get_v8_version(&process_info, &process);

        Ok(Self { pid, process })
    }
}

fn get_v8_version(process_info: &ProcessInfo, process: &Process) {
    for ver in ["major", "minor", "build", "patch"] {
        let symbol = format!("_ZN2v88internal7Version6{}_E", ver);
        let symbol = process_info.get_symbol(symbol.as_str()).unwrap();
        let mut buf = [0u8; 4];
        if let Ok(()) = process.read(*symbol as usize, &mut buf) {
            println!("v8.{}: {:?}", ver, buf);
        } else {
            println!("Failed to read memory for symbol {}", ver);
        }
    }
}