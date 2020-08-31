use anyhow::Result;
use redbpf::Module;

fn main() -> Result<()> {
  let prog = include_bytes!("../target/bpf/programs/limit/limit.elf");
  let mut module = Module::parse(prog).expect("error parsing BPF code");

  for program in module.programs.iter_mut() {
    program
      .load(module.version, module.license.clone())
      .expect("failed to load program");
  }

  loop {}
}
