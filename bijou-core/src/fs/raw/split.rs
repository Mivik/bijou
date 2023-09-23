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

use super::{RawFile, RawFileSystem};
use crate::{
    cache::{CachedStorage, CachedStorageKey},
    db::{consts, Database},
    fs::{FileFlags, FileId},
    Result,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard},
};

// TODO optimize
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FileClusters {
    ids: Vec<FileId>,
    sparse: BTreeMap<u64, FileId>,
}
impl FileClusters {
    pub fn get(&self, block: u64) -> Option<FileId> {
        self.ids
            .get(block as usize)
            .or_else(|| self.sparse.get(&block))
            .copied()
    }

    pub fn insert(&mut self, block: u64, id: FileId) {
        if self.ids.len() == block as usize {
            self.ids.push(id);
            while self.sparse.first_key_value().map(|it| *it.0) == Some(self.ids.len() as u64) {
                let (_, id) = self.sparse.pop_first().unwrap();
                self.ids.push(id);
            }
        } else {
            self.sparse.insert(block, id);
        }
    }

    pub fn truncate(&mut self, blocks: u64) -> impl Iterator<Item = FileId> + '_ {
        self.ids
            .drain(self.ids.len().min(blocks as usize)..)
            .chain(self.sparse.split_off(&blocks).into_values())
    }

    pub fn into_values(self) -> impl Iterator<Item = FileId> {
        self.ids.into_iter().chain(self.sparse.into_values())
    }
}

/// A filesystem that splits files into clusters.
///
/// A cluster contains `cluster_size` blocks. When `cluster_size`
/// is large enough, this filesystem is equivalent to the underlying
/// filesystem.
///
/// Lower `cluster_size` implies better file size obfuscation, but also
/// a higher overhead (both performance and storage).
pub struct SplitFileSystem<FS: RawFileSystem> {
    inner: Arc<FS>,
    cluster_size: u64,
    clusters: Arc<CachedStorage<FileClusters>>,
}
impl<FS: RawFileSystem> SplitFileSystem<FS> {
    pub fn new(inner: FS, db: Arc<Database>, cluster_size: u64) -> Self {
        Self {
            inner: Arc::new(inner),
            cluster_size,
            clusters: Arc::new(CachedStorage::new(db, consts::BLOCKS_DERIVE)),
        }
    }
}
impl<FS: RawFileSystem + Send + Sync + 'static> RawFileSystem for SplitFileSystem<FS> {
    fn open(&self, id: FileId, flags: FileFlags) -> Result<Box<dyn RawFile + Send + Sync>> {
        let key = self.clusters.key(id)?;
        if flags.has(FileFlags::TRUNCATE) {
            let mut blocks = key.write();
            *blocks = FileClusters::default();
            key.update(blocks);
        }

        Ok(Box::new(SplitFile {
            fs: Arc::clone(&self.inner),
            flags: flags.remove(FileFlags::TRUNCATE),
            cluster_size: self.cluster_size,
            key,
            current_file: Mutex::default(),
        }))
    }

    fn create(&self, id: FileId) -> Result<()> {
        self.clusters.touch(id);
        Ok(())
    }

    fn exists(&self, id: FileId) -> Result<bool> {
        self.clusters.exists(id)
    }

    fn unlink(&self, id: FileId) -> Result<()> {
        let clusters = self.clusters.stat(id)?;
        self.clusters.delete(id)?;
        for id in clusters.into_values() {
            self.inner.unlink(id)?;
        }

        Ok(())
    }
}

type BoxRawFile = Box<dyn RawFile + Send + Sync>;
type CurrentFile = Option<(u64, BoxRawFile)>;

struct SplitFile<FS: RawFileSystem> {
    fs: Arc<FS>,
    flags: FileFlags,
    cluster_size: u64,
    key: CachedStorageKey<FileClusters>,
    // TODO better cache
    current_file: Mutex<CurrentFile>,
}
impl<FS: RawFileSystem> SplitFile<FS> {
    fn cluster_id(&self, cluster: u64) -> Result<FileId> {
        let mut clusters = self.key.write();
        Ok(if let Some(id) = clusters.get(cluster) {
            id
        } else {
            let mut id = FileId::gen();
            while self.fs.exists(id)? {
                id = FileId::gen();
            }
            self.fs.create(id)?;
            clusters.insert(cluster, id);
            self.key.update(clusters);
            id
        })
    }

    fn open(&self, block: u64) -> Result<(MutexGuard<CurrentFile>, u64)> {
        let cluster = block / self.cluster_size;
        let block = block % self.cluster_size;
        let mut current_file = self.current_file.lock().unwrap();
        if current_file.as_ref().map(|it| it.0) != Some(cluster) {
            let file = self.fs.open(self.cluster_id(cluster)?, self.flags)?;
            *current_file = Some((cluster, file));
        }

        Ok((current_file, block))
    }
}

impl<FS: RawFileSystem> RawFile for SplitFile<FS> {
    fn read_block(&self, data: &mut [u8], block: u64) -> Result<u64> {
        let (mut file, block) = self.open(block)?;
        file.as_mut().unwrap().1.read_block(data, block)
    }

    fn write_block(&mut self, data: &[u8], block_end: usize, block: u64) -> Result<()> {
        if self.cluster_size == 1 {
            return self.fs.write(self.cluster_id(block)?, &data[..block_end]);
        }
        let (mut file, block) = self.open(block)?;
        file.as_mut().unwrap().1.write_block(data, block_end, block)
    }

    fn set_len(&mut self, len: u64, block_size: u64) -> Result<()> {
        let blocks = len / block_size;
        let offset = len % block_size;

        let mut clusters = self.key.write();
        for id in clusters.truncate(blocks + 1) {
            self.fs.unlink(id)?;
        }
        if let Some(id) = clusters.get(blocks) {
            self.fs.open(id, self.flags)?.set_len(offset, block_size)?;
        }
        self.key.update(clusters);

        Ok(())
    }
}
