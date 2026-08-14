use std::fs;
use std::path::PathBuf;
use std::process::Command;

use clap::CommandFactory;
use clap_complete::generate_to;
use clap_complete::shells::{Bash, Fish, PowerShell, Zsh};

#[path = "src/command.rs"]
mod command;

fn write_man_page(path: PathBuf, roff: Vec<u8>) {
    let rendered = String::from_utf8(roff).expect("man page is UTF-8");
    let normalized = rendered
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, format!("{normalized}\n")).expect("write intermed.1");
}

fn main() {
    println!("cargo:rerun-if-changed=src/command.rs");
    println!("cargo:rerun-if-env-changed=INTERMED_GENERATE_CLI_DOCS");

    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    println!(
        "cargo:rerun-if-changed={}",
        repo.join(".git/HEAD").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repo.join(".git/index").display()
    );
    for path in ["Cargo.toml", "Cargo.lock", "crates", "rules"] {
        println!("cargo:rerun-if-changed={}", repo.join(path).display());
    }
    if let Ok(output) = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&repo)
        .output()
        && output.status.success()
    {
        println!(
            "cargo:rustc-env=INTERMED_GIT_COMMIT={}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    if let Ok(status) = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&repo)
        .output()
        && status.status.success()
    {
        println!(
            "cargo:rustc-env=INTERMED_GIT_DIRTY={}",
            !status.stdout.is_empty()
        );
    }

    if std::env::var_os("INTERMED_GENERATE_CLI_DOCS").is_some() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let man_dir = manifest_dir.join("../../docs/man");
        fs::create_dir_all(&man_dir).expect("create docs/man");

        let cmd = command::Cli::command();
        let man = clap_mangen::Man::new(cmd.clone());
        let mut roff = Vec::new();
        man.render(&mut roff).expect("render man page");
        write_man_page(man_dir.join("intermed.1"), roff);

        let completions_dir = manifest_dir.join("../../docs/completions");
        fs::create_dir_all(&completions_dir).expect("create docs/completions");

        let mut cmd = cmd;
        generate_to(Bash, &mut cmd, "intermed", &completions_dir)
            .expect("generate bash completions");
        generate_to(Zsh, &mut cmd, "intermed", &completions_dir).expect("generate zsh completions");
        generate_to(Fish, &mut cmd, "intermed", &completions_dir)
            .expect("generate fish completions");
        generate_to(PowerShell, &mut cmd, "intermed", &completions_dir)
            .expect("generate powershell completions");
    } else if let Some(out_dir) = std::env::var_os("OUT_DIR") {
        let out_dir = PathBuf::from(out_dir);
        let cmd = command::Cli::command();
        let man = clap_mangen::Man::new(cmd.clone());
        let mut roff = Vec::new();
        man.render(&mut roff).expect("render man page");
        write_man_page(out_dir.join("intermed.1"), roff);

        let mut cmd = cmd;
        generate_to(Bash, &mut cmd, "intermed", &out_dir).expect("generate bash completions");
        generate_to(Zsh, &mut cmd, "intermed", &out_dir).expect("generate zsh completions");
        generate_to(Fish, &mut cmd, "intermed", &out_dir).expect("generate fish completions");
        generate_to(PowerShell, &mut cmd, "intermed", &out_dir)
            .expect("generate powershell completions");
    }
}
