extern crate anyhow;
extern crate log;

mod v8_spy;
use crate::v8_spy::V8Spy;
use remoteprocess::Pid;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let pid = Pid::from(args[1].parse::<i32>().unwrap());
    let _spy = V8Spy::new(pid).unwrap();
}
