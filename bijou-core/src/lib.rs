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

pub mod algo;
mod bijou;
mod cache;
mod crypto;
mod db;
mod error;
mod fs;
mod id_lock;
mod secret;
mod serde_ext;

pub(crate) use error::{anyhow, bail, Context};

pub use bijou::{Bijou, BijouFs, DirIterator, File};
pub use error::{Error, ErrorKind, Result};
pub use fs::{
    config::{self, Config},
    path, raw as raw_fs, FileId, FileKind, FileMeta, LowLevelFile, OpenOptions,
};
pub use secret::SecretBytes;

#[cfg(feature = "fuse")]
pub use bijou::BijouFuse;

/// Initialize Bijou.
///
/// Should be called before any use of this library.
pub fn init() -> Result<()> {
    sodiumoxide::init().map_err(|_| anyhow!(@CryptoError "failed to initialize libsodium"))?;
    Ok(())
}

#[cfg(debug_assertions)]
struct TimeSpan(String, std::time::Instant);
#[cfg(debug_assertions)]
fn begin_span(name: impl Into<String>) -> TimeSpan {
    TimeSpan(name.into(), std::time::Instant::now())
}
#[cfg(debug_assertions)]
impl Drop for TimeSpan {
    fn drop(&mut self) {
        let elapsed = self.1.elapsed();
        tracing::debug!(name = self.0, elapsed = elapsed.as_nanos(), "time span");
    }
}

#[cfg(not(debug_assertions))]
fn begin_span(_name: impl Into<String>) {}
