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

use super::{RawFile, RawFileMeta, RawFileSystem};
use crate::{
    cache::{CachedStorage, CachedStorageKey},
    db::{consts, Database},
    fs::{FileFlags, FileId},
    Result,
};
use chrono::Utc;
use std::sync::Arc;

/// A filesystem that keeps track of file metadata (size, modified
/// time and access time). This is needed for files that cannot keep
/// track of, or is expensive to keep track of, their own metadata (e.g.
/// [`SplitFileSystem`], remote filesystem).
///
/// [`SplitFileSystem`]: super::split::SplitFileSystem
pub struct TrackingFileSystem<FS: RawFileSystem> {
    inner: FS,
    metas: Arc<CachedStorage<RawFileMeta>>,
}
impl<FS: RawFileSystem> TrackingFileSystem<FS> {
    pub fn new(inner: FS, db: Arc<Database>) -> Self {
        Self {
            inner,
            metas: Arc::new(CachedStorage::new(db, consts::TRACKING_DERIVE)),
        }
    }
}
impl<FS: RawFileSystem> RawFileSystem for TrackingFileSystem<FS> {
    fn open(&self, id: FileId, flags: FileFlags) -> Result<Box<dyn RawFile + Send + Sync>> {
        let key = self.metas.key(id)?;
        let mut meta = key.write();
        if flags.has(FileFlags::TRUNCATE) {
            meta.size = 0;
        }
        if flags.has(FileFlags::READ) {
            meta.accessed = Some(Utc::now());
        }
        if flags.has(FileFlags::WRITE) {
            meta.modified = Some(Utc::now());
        }
        key.update(meta);

        Ok(Box::new(TrackingFile {
            inner: self.inner.open(id, flags)?,
            key,
        }))
    }

    fn create(&self, id: FileId) -> Result<()> {
        self.inner.create(id)?;
        self.metas.store(id, RawFileMeta::create());
        Ok(())
    }

    fn exists(&self, id: FileId) -> Result<bool> {
        self.metas.exists(id)
    }

    fn unlink(&self, id: FileId) -> Result<()> {
        self.inner.unlink(id)?;
        self.metas.delete(id)?;
        Ok(())
    }

    fn stat(&self, id: FileId) -> Result<RawFileMeta> {
        self.metas.stat(id)
    }

    fn write(&self, id: FileId, data: &[u8]) -> Result<()> {
        self.inner.write(id, data)?;

        let key = self.metas.key(id)?;
        let mut meta = key.write();
        meta.size = data.len() as u64;
        meta.modified = Some(Utc::now());
        key.update(meta);

        Ok(())
    }
}

struct TrackingFile {
    inner: Box<dyn RawFile + Send + Sync>,
    key: CachedStorageKey<RawFileMeta>,
}
impl RawFile for TrackingFile {
    fn read_block(&self, data: &mut [u8], block: u64) -> Result<u64> {
        self.inner.read_block(data, block)
    }

    fn write_block(&mut self, data: &[u8], block_end: usize, block: u64) -> Result<()> {
        self.inner.write_block(data, block_end, block)
    }

    fn set_len(&mut self, len: u64, block_size: u64) -> Result<()> {
        self.inner.set_len(len, block_size)
    }

    fn set_metadata(&self, its_meta: RawFileMeta) -> Result<()> {
        let mut meta = self.key.write();
        *meta = its_meta;
        self.key.update(meta);
        Ok(())
    }

    fn metadata(&self) -> Result<RawFileMeta> {
        Ok(self.key.write().clone())
    }
}
