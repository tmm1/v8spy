
use anyhow::{Context, Result};
use spytools::ProcessInfo;

use remoteprocess::{Pid, Process, ProcessMemory};

struct Version {
    major: u32,
    minor: u32,
    build: u32,
    patch: u32,
}

pub struct V8Spy {
    pub pid: Pid,
    pub process: Process,
    pub version: Version,
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

        let version = get_v8_version(&process_info, &process);
        println!("v8 version: {}.{}.{}.{}", version.major, version.minor, version.build, version.patch);

        Ok(Self { pid, process, version })
    }
}

fn get_v8_version(process_info: &ProcessInfo, process: &Process) -> Version {
    let mut version = [0u32; 4];
    for (i, ver) in ["major", "minor", "build", "patch"].iter().enumerate() {
        let symbol = format!("_ZN2v88internal7Version6{}_E", ver);
        let symbol = process_info.get_symbol(symbol.as_str()).unwrap();
        let mut buf = [0u8; 4];
        if let Ok(()) = process.read(*symbol as usize, &mut buf) {
            version[i] = buf[0] as u32 | (buf[1] as u32) << 8 | (buf[2] as u32) << 16 | (buf[3] as u32) << 24;
        } else {
            println!("Failed to read memory for symbol {}", ver);
        }
    }
    Version {
        major: version[0],
        minor: version[1],
        build: version[2],
        patch: version[3],
    }
}