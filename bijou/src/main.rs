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
use bijou_core::{Bijou, BijouFuse, Config, FileId, FileKind, MountOption};
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

#[derive(Subcommand)]
enum Command {
    /// Create a new Bijou
    Create {
        /// the path to the Bijou to create
        path: PathBuf,

        /// the path to the config file (JSON) to use
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

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

    bijou_core::init()?;

    let args = Args::parse();

    match args.command {
        Command::Create { path, config } => {
            let config = match config {
                Some(path) => {
                    (|| -> Result<Config> { Ok(serde_json::from_reader(File::open(path)?)?) })()
                        .context("failed to read config")?
                }
                None => Config::default(),
            };

            let password = rpassword::prompt_password("Enter password: ")?;
            if rpassword::prompt_password("Repeat: ")? != password {
                Args::command()
                    .error(ErrorKind::InvalidValue, "Passwords do not match")
                    .exit();
            }
            Bijou::create(&path, password.into_bytes(), config)?;

            info!("Bijou created at {}", path.display());
        }
        Command::Mount {
            path,
            mount_point: mountpoint,
            allow_other,
        } => {
            let password = rpassword::prompt_password("Enter password: ")?;
            let bijou = Arc::new(Bijou::open(path, password.into_bytes())?);
            let fuse = BijouFuse::new(bijou);
            let mut options = Vec::new();
            if allow_other {
                options.push(MountOption::AllowOther);
            }
            let mut unmounter = fuse.mount(mountpoint, &options)?;
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
