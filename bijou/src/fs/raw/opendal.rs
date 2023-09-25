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
    fs::{raw::write_vec_at, FileFlags, FileId},
    Result,
};
use opendal::BlockingOperator;
use std::sync::Arc;
use tracing::warn;

/// A filesystem that uses OpenDAL as backend.
///
/// This is experimental and not recommended for production use.
pub struct OpenDALFileSystem {
    operator: Arc<BlockingOperator>,
    prefix: String,
}

impl OpenDALFileSystem {
    pub fn new(operator: BlockingOperator, prefix: String) -> Self {
        Self {
            operator: Arc::new(operator),
            prefix,
        }
    }

    fn path(&self, id: FileId) -> String {
        format!("{}{id}", self.prefix)
    }
}

impl RawFileSystem for OpenDALFileSystem {
    fn open(&self, id: FileId, flags: FileFlags) -> Result<Box<dyn RawFile + Send + Sync>> {
        if flags.has(FileFlags::TRUNCATE) {
            self.write(id, b"")?;
        }
        Ok(Box::new(OpenDALFile {
            operator: Arc::clone(&self.operator),
            path: self.path(id),
        }))
    }

    fn create(&self, id: FileId) -> Result<()> {
        self.write(id, b"")
    }

    fn exists(&self, id: FileId) -> Result<bool> {
        Ok(self.operator.is_exist(&self.path(id))?)
    }

    fn unlink(&self, id: FileId) -> Result<()> {
        self.operator.delete(&self.path(id))?;
        Ok(())
    }

    fn stat(&self, id: FileId) -> Result<RawFileMeta> {
        Ok(RawFileMeta::from_opendal(
            self.operator.stat(&self.path(id))?,
        ))
    }

    fn write(&self, id: FileId, data: &[u8]) -> Result<()> {
        // TODO cache
        self.operator.write(&self.path(id), data.to_vec())?;
        Ok(())
    }
}

pub struct OpenDALFile {
    operator: Arc<BlockingOperator>,
    path: String,
}
impl RawFile for OpenDALFile {
    fn read_block(&self, data: &mut [u8], block: u64) -> Result<u64> {
        let len = data.len() as u64;
        let mut reader = self
            .operator
            .range_reader(&self.path, block * len..(block + 1) * len)?;
        let res = reader.read(data)?;
        dbg!(&data[..res]);
        Ok(res as u64)
    }

    fn write_block(&mut self, data: &[u8], block_end: usize, block: u64) -> Result<()> {
        warn!(
            "OpenDAL does not support random write and thus is recommended to wrap it with SplitFileSystem with cluster_size=1"
        );

        let mut vec = self.operator.read(&self.path)?;
        write_vec_at(&mut vec, data, block_end, block);
        self.operator.write(&self.path, vec)?;

        Ok(())
    }

    fn set_len(&mut self, len: u64, _block_size: u64) -> Result<()> {
        let data = self.operator.range_read(&self.path, 0..len)?;
        self.operator.write(&self.path, data)?;

        Ok(())
    }

    fn metadata(&self) -> Result<RawFileMeta> {
        let meta = self.operator.stat(&self.path)?;
        Ok(RawFileMeta::from_opendal(meta))
    }
}
