use std::fs;
use std::path::PathBuf;

use clap::CommandFactory;
use clap_complete::generate_to;
use clap_complete::shells::{Bash, Fish, PowerShell, Zsh};

#[path = "src/command.rs"]
mod command;

fn main() {
    println!("cargo:rerun-if-changed=src/command.rs");

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let man_dir = manifest_dir.join("../../docs/man");
    fs::create_dir_all(&man_dir).expect("create docs/man");

    let cmd = command::Cli::command();
    let man = clap_mangen::Man::new(cmd.clone());
    let mut roff = Vec::new();
    man.render(&mut roff).expect("render man page");
    fs::write(man_dir.join("intermed.1"), roff).expect("write intermed.1");

    let completions_dir = manifest_dir.join("../../docs/completions");
    fs::create_dir_all(&completions_dir).expect("create docs/completions");

    let mut cmd = cmd;
    generate_to(Bash, &mut cmd, "intermed", &completions_dir).expect("generate bash completions");
    generate_to(Zsh, &mut cmd, "intermed", &completions_dir).expect("generate zsh completions");
    generate_to(Fish, &mut cmd, "intermed", &completions_dir).expect("generate fish completions");
    generate_to(PowerShell, &mut cmd, "intermed", &completions_dir)
        .expect("generate powershell completions");
}
