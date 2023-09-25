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

use crate::{error::ResultExt, fs::FileId, Context, ErrorKind, Result, SecretBytes};
use rocksdb::{
    BlockBasedOptions, DBPinnableSlice, DBWithThreadMode, LogLevel, Options, ReadOptions,
    SingleThreaded, WriteBatchWithTransaction, DB,
};
use serde::{de::DeserializeOwned, Serialize};
use smallvec::SmallVec;
use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut},
    path::Path,
    sync::Arc,
};

pub type RawKeyType = SmallVec<[u8; consts::FILE_ROOT.len() + std::mem::size_of::<FileId>()]>;

pub mod consts {
    pub const FILE_ROOT: &[u8] = b"f";

    pub const DIR_DERIVE: &[u8] = b":";
    pub const DIR_DERIVE_UPPER: &[u8] = b";";

    pub const SYMLINK_DERIVE: &[u8] = b"s";

    pub const BLOCKS_DERIVE: &[u8] = b"b";
    pub const TRACKING_DERIVE: &[u8] = b"t";

    pub const XATTR_DERIVE: &[u8] = b"x";
    pub const XATTR_DERIVE_UPPER: &[u8] = b"y";
}

mod cipher {
    use crate::{algo::is_nil, crypto::cast_key, SecretBytes};
    use sodiumoxide::crypto::stream::*;

    pub const METADATA_SIZE: usize = NONCEBYTES;
    pub const BLOCK_SIZE: usize = 4096;

    pub use sodiumoxide::crypto::stream::KEYBYTES;

    pub struct MyCipher(pub SecretBytes);
    impl rocksdb::CustomCipher for MyCipher {
        fn encrypt_block(&self, _block_index: u64, data: &mut [u8], metadata: &mut [u8]) -> bool {
            let nonce: &mut Nonce = unsafe { &mut *(metadata.as_mut_ptr() as *mut Nonce) };
            while is_nil(&nonce.0) {
                *nonce = gen_nonce();
            }
            stream_xor_inplace(data, nonce, cast_key(&self.0));
            true
        }

        fn decrypt_block(&self, _block_index: u64, data: &mut [u8], metadata: &[u8]) -> bool {
            let nonce: &Nonce = unsafe { &*(metadata.as_ptr() as *const Nonce) };
            if is_nil(&nonce.0) {
                data.fill(0);
                return true;
            }
            stream_xor_inplace(data, nonce, cast_key(&self.0));
            true
        }
    }
}

pub struct Database(pub Arc<DBWithThreadMode<SingleThreaded>>, Arc<Options>);
impl Database {
    pub const KEYBYTES: usize = cipher::KEYBYTES;

    pub fn open(path: impl AsRef<Path>, key: Option<SecretBytes>) -> Result<Self> {
        let env = Arc::new(if let Some(key) = key {
            rocksdb::Env::encrypted(
                Box::new(cipher::MyCipher(key)),
                cipher::METADATA_SIZE,
                cipher::BLOCK_SIZE,
            )
            .context("failed to create encrypted RocksDB environment")?
        } else {
            rocksdb::Env::new().context("failed to create RocksDB environment")?
        });

        // TODO increase parallelism?
        let mut options = Options::default();
        options.increase_parallelism(4);
        options.create_if_missing(true);
        options.set_log_level(LogLevel::Fatal);
        options.set_use_adaptive_mutex(true);
        options.set_env(&env);
        options.set_compression_type(rocksdb::DBCompressionType::None);
        let mut block_opts = BlockBasedOptions::default();
        block_opts.set_ribbon_filter(20.0);
        options.set_block_based_table_factory(&block_opts);
        // options.set_prefix_extractor(SliceTransform::create_fixed_prefix(std::mem::size_of::<FileId>() + 1));
        let options = Arc::new(options);

        Ok(Self(
            DB::open(&options, path.as_ref())
                .context("failed to open database")
                .kind(ErrorKind::DBError)?
                .into(),
            options,
        ))
    }

    pub fn key(&self, key: impl AsRef<[u8]>) -> DatabaseKey {
        DatabaseKey {
            db: Arc::clone(&self.0),
            key: key.as_ref().into(),
            marker: PhantomData,
        }
    }

    pub fn batch(&self) -> BatchWrapper {
        BatchWrapper {
            db: self,
            inner: WriteBatchWithTransaction::default(),
        }
    }
}

pub struct BatchWrapper<'db> {
    db: &'db Database,
    inner: WriteBatchWithTransaction<false>,
}
impl Deref for BatchWrapper<'_> {
    type Target = WriteBatchWithTransaction<false>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for BatchWrapper<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
impl BatchWrapper<'_> {
    pub fn commit(self) -> Result<()> {
        self.db.0.write(self.inner).kind(ErrorKind::DBError)
    }
}

pub struct Nothing;

pub struct DatabaseKey<T = Nothing> {
    pub db: Arc<DBWithThreadMode<SingleThreaded>>,
    pub key: RawKeyType,
    marker: PhantomData<T>,
}

impl<T> Clone for DatabaseKey<T> {
    fn clone(&self) -> Self {
        Self {
            db: Arc::clone(&self.db),
            key: self.key.clone(),
            marker: PhantomData,
        }
    }
}

impl<T> DatabaseKey<T> {
    pub fn read(&self) -> Result<Option<DBPinnableSlice>> {
        self.db.get_pinned(&self.key).kind(ErrorKind::DBError)
    }

    pub fn read_owned(&self) -> Result<Option<Vec<u8>>> {
        self.db.get(&self.key).kind(ErrorKind::DBError)
    }

    pub fn get(&self) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        self
            .read()
            .kind(ErrorKind::DBError)?
            .map(|bytes| postcard::from_bytes(&bytes))
            .transpose()
            .wrap()
    }

    pub fn write(&self, value: impl AsRef<[u8]>) -> Result<()> {
        self.db.put(&self.key, value).kind(ErrorKind::DBError)
    }

    pub fn write_batch<const B: bool>(
        &self,
        batch: &mut WriteBatchWithTransaction<B>,
        value: impl AsRef<[u8]>,
    ) {
        batch.put(&self.key, value);
    }

    pub fn put(&self, value: &T) -> Result<()>
    where
        T: Serialize,
    {
        // TODO cache
        self.write(postcard::to_allocvec(value).context("failed to serialize data")?)
    }

    pub fn put_batch<const B: bool>(
        &self,
        batch: &mut WriteBatchWithTransaction<B>,
        value: &T,
    ) -> Result<()>
    where
        T: Serialize,
    {
        self.write_batch(
            batch,
            postcard::to_allocvec(value).context("failed to deserialize data")?,
        );
        Ok(())
    }

    pub fn delete(&self) -> Result<()> {
        self.db.delete(&self.key).kind(ErrorKind::DBError)
    }

    pub fn delete_batch<const B: bool>(&self, batch: &mut WriteBatchWithTransaction<B>) {
        batch.delete(&self.key);
    }

    pub fn exists(&self) -> Result<bool> {
        Ok(if self.db.key_may_exist(&self.key) {
            self.read().is_ok()
        } else {
            false
        })
    }

    pub fn derive(self, name: impl AsRef<[u8]>) -> DatabaseKey<Nothing> {
        let mut key = self.key;
        key.extend_from_slice(name.as_ref());
        DatabaseKey {
            db: self.db,
            key,
            marker: PhantomData,
        }
    }

    pub fn range_iter(
        &self,
        lower: &[u8],
        upper: &[u8],
    ) -> impl Iterator<Item = Result<(Box<[u8]>, Box<[u8]>), rocksdb::Error>> + '_ {
        let mut opts = ReadOptions::default();

        let mut upper_key = self.key.to_vec();
        upper_key.extend_from_slice(upper);
        opts.set_iterate_upper_bound(upper_key);

        let mut lower_key = self.key.to_vec();
        lower_key.extend_from_slice(lower);
        self.db.iterator_opt(
            rocksdb::IteratorMode::From(&lower_key, rocksdb::Direction::Forward),
            opts,
        )
    }

    #[inline]
    pub fn typed<U>(self) -> DatabaseKey<U> {
        DatabaseKey {
            db: self.db,
            key: self.key,
            marker: PhantomData,
        }
    }
}
