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

use super::RawFileSystem;
use crate::{algo::Algorithm, db::Database, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// File encryption algorithm.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FileEncryption {
    /// AES-256-GCM
    ///
    /// This is the default algorithm and is most commonly
    /// used. However, this is not the safest algorithm due
    /// to its small nonce size. For a safer alternative,
    /// see [`XChaCha20Poly1305IETF`].
    ///
    /// [`XChaCha20Poly1305IETF`]: FileEncryption::XChaCha20Poly1305IETF
    Aes256Gcm,

    /// ChaCha20-Poly1305
    ///
    /// This is a safer alternative to [`Aes256Gcm`].
    ///
    /// [`Aes256Gcm`]: FileEncryption::Aes256Gcm
    ChaCha20Poly1305,

    /// XChaCha20-Poly1305-IETF
    ///
    /// This is the safest algorithm but can be slower than
    /// [`Aes256Gcm`].
    ///
    /// [`Aes256Gcm`]: FileEncryption::Aes256Gcm
    XChaCha20Poly1305IETF,

    /// XSalsa20
    ///
    /// This is a stream cipher, which means it has lower
    /// storage overhead than other algorithms, but does
    /// not provide integrity protection.
    XSalsa20,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum OpenDALType {
    Memory,
}

#[cfg(feature = "opendal")]
impl OpenDALType {
    pub fn build(&self) -> Result<opendal::BlockingOperator> {
        use opendal::{services, Operator};
        let operator = match self {
            Self::Memory => Operator::new(services::Memory::default())?.finish(),
        };
        Ok(operator.blocking())
    }
}

/// File storage type.
///
/// Multiple storage types can be combined together.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum FileStorage {
    /// Local filesystem.
    Local,

    /// Split filesystem. See [`SplitFileSystem`] for more details.
    ///
    /// [`SplitFileSystem`]: crate::raw_fs::SplitFileSystem
    Split {
        inner: Box<FileStorage>,
        cluster_size: u64,
    },

    /// Tracking filesystem. See [`TrackingFileSystem`] for more details.
    ///
    /// [`TrackingFileSystem`]: crate::raw_fs::TrackingFileSystem
    Tracking { inner: Box<FileStorage> },

    /// OpenDAL filesystem. See [`OpenDALFileSystem`] for more details.
    ///
    /// This requires the `opendal` feature.
    ///
    /// [`OpenDALFileSystem`]: crate::raw_fs::OpenDALFileSystem
    OpenDAL { ty: OpenDALType, prefix: String },

    /// RocksDB filesystem. See [`RocksDBFileSystem`] for more details.
    ///
    /// [`RocksDBFileSystem`]: crate::raw_fs::RocksDBFileSystem
    RocksDB,
}

impl FileStorage {
    pub(crate) fn build(
        &self,
        db: &Arc<Database>,
        data_dir: &std::path::Path,
    ) -> Result<Arc<dyn RawFileSystem + Send + Sync>> {
        use crate::fs::raw::*;
        Ok(match self {
            Self::Local => Arc::new(LocalFileSystem::new(data_dir)),
            Self::Split {
                inner,
                cluster_size,
            } => Arc::new(SplitFileSystem::new(
                inner.build(db, data_dir)?,
                Arc::clone(db),
                *cluster_size,
            )),
            Self::Tracking { inner } => Arc::new(TrackingFileSystem::new(
                inner.build(db, data_dir)?,
                Arc::clone(db),
            )),
            #[cfg(feature = "opendal")]
            Self::OpenDAL { ty, prefix } => {
                let operator = ty.build()?;
                Arc::new(OpenDALFileSystem::new(operator, prefix.clone()))
            }
            #[cfg(not(feature = "opendal"))]
            Self::OpenDAL { .. } => {
                panic!("OpenDAL is not enabled, please enable it by adding `opendal` feature")
            }
            Self::RocksDB => Arc::new(RocksDBFileSystem::new(Arc::new(Database::open(
                data_dir, None,
            )?))),
        })
    }
}

/// Configuration for Bijou. Used to initialize a Bijou instance.
///
/// See also [`Bijou::create`].
///
/// [`Bijou::create`]: crate::Bijou::create
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// The version of the configuration.
    ///
    /// See [`Config::CURRENT_VERSION`] for the current version.
    pub version: u32,

    /// File encryption algorithm.
    pub file_encryption: FileEncryption,
    /// File encryption block size.
    pub block_size: u64,

    /// Whether to encrypt the database.
    pub encrypt_db: bool,
    /// Whether to encrypt the file name.
    ///
    /// This is somehow redundant if [`encrypt_db`] is `true`,
    /// since the file name is stored in the database.
    ///
    /// [`encrypt_db`]: Config::encrypt_db
    pub encrypt_file_name: bool,

    /// Whether to use Unix permissions.
    ///
    /// When disabled, all files will have same default
    /// permissions.
    pub unix_perms: bool,

    /// File storage type. See [`FileStorage`] for more details.
    pub storage: FileStorage,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 0,

            file_encryption: FileEncryption::Aes256Gcm,
            block_size: 4096,

            encrypt_db: true,
            encrypt_file_name: false,

            unix_perms: true,

            storage: FileStorage::Local,
        }
    }
}

impl Config {
    pub const CURRENT_VERSION: u32 = 0;

    pub fn to_algorithm(&self) -> Result<Arc<dyn Algorithm + Send + Sync>> {
        use crate::algo::*;
        Ok(match self.file_encryption {
            FileEncryption::Aes256Gcm => {
                Arc::new(RingAead::new(&ring::aead::AES_256_GCM, self.block_size)?)
            }
            FileEncryption::ChaCha20Poly1305 => Arc::new(RingAead::new(
                &ring::aead::CHACHA20_POLY1305,
                self.block_size,
            )?),
            FileEncryption::XChaCha20Poly1305IETF => {
                Arc::new(XChaCha20Poly1305IETF::new(self.block_size))
            }
            FileEncryption::XSalsa20 => Arc::new(XSalsa20::new(self.block_size)),
        })
    }
}
