// Copyright 2023 Mivik
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use anyhow::{Context, Result};
use bijou::{Bijou, Config, FileId, FileKind, Limit};
use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};
use std::{fs::File, path::PathBuf, sync::Arc};
use tracing::info;
use tracing_log::LogTracer;
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*, EnvFilter};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

fn limit_parser(s: &str) -> Result<Limit, &'static str> {
    Ok(match s {
        "interactive" | "i" => Limit::Interactive,
        "moderate" | "m" => Limit::Moderate,
        "sensitive" | "s" => Limit::Sensitive,
        _ => {
            if let Ok(val) = s.parse::<usize>() {
                Limit::Custom(val)
            } else {
                return Err(
                    "expected one of: interactive(i), moderate(m), sensitive(s), or a number",
                );
            }
        }
    })
}

#[derive(Subcommand)]
enum Command {
    /// Create a new Bijou
    Create {
        /// the path to the Bijou to create
        path: PathBuf,

        /// the path to the config file (JSON) to use
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// the operation limit of Argon2id
        #[arg(long, value_parser = limit_parser)]
        ops_limit: Option<Limit>,

        /// the memory limit of Argon2id
        #[arg(long, value_parser = limit_parser)]
        mem_limit: Option<Limit>,
    },

    #[cfg(not(windows))]
    /// Mount a Bijou
    Mount {
        /// the path to the Bijou
        path: PathBuf,

        /// mount point
        mount_point: PathBuf,

        /// allow other users to access the mount point
        #[arg(long)]
        allow_other: bool,
    },

    /// Print the file tree of a Bijou
    Tree {
        /// the path to the Bijou
        path: PathBuf,
    },
}

fn print_file_tree(bijou: &Bijou, dir: FileId, depth: usize) -> Result<()> {
    for entry in bijou.read_dir(dir)?.reset() {
        let (name, item) = entry?;
        if name == "." || name == ".." {
            continue;
        }
        println!("{}| {name}", "  ".repeat(depth));
        if item.kind == FileKind::Directory {
            print_file_tree(bijou, item.id, depth + 1)?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    LogTracer::init()?;

    let subscriber = tracing_subscriber::registry().with(
        fmt::layer().with_writer(std::io::stderr).with_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        ),
    );

    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set global default subscriber");

    bijou::init()?;

    let args = Args::parse();

    match args.command {
        Command::Create {
            path,
            config,
            ops_limit,
            mem_limit,
        } => {
            let config = match config {
                Some(path) => {
                    (|| -> Result<Config> { Ok(serde_json::from_reader(File::open(path)?)?) })()
                        .context("failed to read config")?
                }
                None => Config::default(),
            };
            if path.exists() && (!path.is_dir() || path.read_dir()?.next().is_some()) {
                Args::command()
                    .error(ErrorKind::Io, "Destination is not empty")
                    .exit();
            }

            let password = rpassword::prompt_password("Enter password: ")?;
            if rpassword::prompt_password("Repeat: ")? != password {
                Args::command()
                    .error(ErrorKind::InvalidValue, "Passwords do not match")
                    .exit();
            }
            Bijou::create(
                &path,
                password.into_bytes(),
                config,
                ops_limit.unwrap_or(Limit::Moderate),
                mem_limit.unwrap_or(Limit::Moderate),
            )?;

            info!("Bijou created at {}", path.display());
        }
        #[cfg(not(windows))]
        Command::Mount {
            path,
            mount_point,
            allow_other,
        } => {
            if !path.is_dir() {
                Args::command()
                    .error(ErrorKind::Io, "Data directory does not exist")
                    .exit();
            }
            if !mount_point.is_dir() {
                Args::command()
                    .error(ErrorKind::Io, "Mount point does not exist")
                    .exit();
            }

            let password = rpassword::prompt_password("Enter password: ")?;
            let bijou = Arc::new(Bijou::open(path, password.into_bytes())?);
            let fuse = bijou::BijouFuse::new(bijou);
            let mut options = Vec::new();
            if allow_other {
                options.push(bijou::MountOption::AllowOther);
            }
            let mut unmounter = fuse.mount(mount_point, &options)?;
            ctrlc::set_handler(move || {
                unmounter.unmount().expect("failed to unmount");
                std::process::exit(0);
            })?;

            loop {
                std::thread::park();
            }
        }
        Command::Tree { path } => {
            let password = rpassword::prompt_password("Enter password: ")?;
            let bijou = Bijou::open(path, password.into_bytes())?;
            print_file_tree(&bijou, FileId::ROOT, 0)?;
        }
    }

    Ok(())
}
