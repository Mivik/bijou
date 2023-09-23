use super::{RawFile, RawFileSystem};
use crate::{
    db::{Database, DatabaseKey},
    fs::{raw::write_vec_at, FileFlags, FileId},
    Result,
};
use std::sync::Arc;
use tracing::warn;

/// A filesystem that uses RocksDB as backend.
///
/// This is experimental and not recommended for production use.
pub struct RocksDBFileSystem {
    db: Arc<Database>,
}

impl RocksDBFileSystem {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

impl RawFileSystem for RocksDBFileSystem {
    fn open(&self, id: FileId, flags: FileFlags) -> Result<Box<dyn RawFile + Send + Sync>> {
        if flags.has(FileFlags::TRUNCATE) {
            self.write(id, b"")?;
        }
        Ok(Box::new(RocksDBFile {
            key: self.db.key(id),
        }))
    }

    fn create(&self, id: FileId) -> Result<()> {
        self.write(id, b"")
    }

    fn unlink(&self, id: FileId) -> Result<()> {
        self.db.key(id).delete()
    }

    fn exists(&self, id: FileId) -> Result<bool> {
        self.db.key(id).exists()
    }

    fn write(&self, id: FileId, data: &[u8]) -> Result<()> {
        self.db.key(id).write(data)
    }
}

pub struct RocksDBFile {
    key: DatabaseKey,
}
impl RawFile for RocksDBFile {
    fn read_block(&self, data: &mut [u8], block: u64) -> Result<u64> {
        let Some(slice) = self.key.read()? else {
            return Ok(0);
        };
        let offset = data.len() * block as usize;
        if offset > slice.len() {
            return Ok(0);
        }
        let len = slice.len().saturating_sub(offset);
        data[..len].copy_from_slice(&slice[offset..offset + len]);
        Ok(len as u64)
    }

    fn write_block(&mut self, data: &[u8], block_end: usize, block: u64) -> Result<()> {
        warn!(
            "RocksDB does not support random write and thus is recommended to wrap it with SplitFileSystem with cluster_size=1"
        );

        let mut vec = self.key.read_owned()?.unwrap();
        write_vec_at(&mut vec, data, block_end, block);
        self.key.write(&vec)
    }

    fn set_len(&mut self, len: u64, _block_size: u64) -> Result<()> {
        let slice = self.key.read()?.unwrap();
        self.key.write(&slice[..len as usize])
    }
}
