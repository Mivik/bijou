mod local;
mod rocksdb;
mod split;
mod tracking;

pub use self::rocksdb::RocksDBFileSystem;
pub use local::LocalFileSystem;
pub use split::SplitFileSystem;
pub use tracking::TrackingFileSystem;

#[cfg(feature = "opendal")]
mod opendal;
#[cfg(feature = "opendal")]
pub use self::opendal::OpenDALFileSystem;

use super::{time, FileFlags, FileId};
use crate::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

type ArcRawFileSystem = Arc<dyn RawFileSystem + Send + Sync>;

/// A type abstracting over different low-level filesystems.
pub trait RawFileSystem {
    /// Opens a file.
    ///
    /// The caller should make sure that the file exists.
    fn open(&self, id: FileId, flags: FileFlags) -> Result<Box<dyn RawFile + Send + Sync>>;

    /// Creates a file.
    ///
    /// The caller should make sure that the file does not exist.
    fn create(&self, id: FileId) -> Result<()>;

    /// Checks if a file exists.
    fn exists(&self, id: FileId) -> Result<bool>;

    /// Deletes a file.
    ///
    /// The caller should make sure that the file exists and that
    /// the file is not being opened.
    fn unlink(&self, id: FileId) -> Result<()>;

    /// Returns the metadata of a files.
    ///
    /// The caller should make sure that the file exists.
    fn stat(&self, _id: FileId) -> Result<RawFileMeta> {
        panic!(
            "This filesystem does not support stat. You should wrap it in a TrackingFileSystem."
        )
    }

    /// Writes directly into a file, replacing all its content.
    ///
    /// The caller should make sure that the file exists and that
    /// the size of `block` does not exceed block size as defined
    /// in the algorithm.
    fn write(&self, id: FileId, data: &[u8]) -> Result<()> {
        self.open(id, FileFlags::WRITE | FileFlags::TRUNCATE)?
            .write_block(data, data.len(), 0)
    }
}

/// File created by a [`RawFileSystem`].
pub trait RawFile {
    /// Reads a block of data from the file, returning the
    /// number of bytes read.
    ///
    /// The length of `data` should be the block size.
    ///
    /// The caller should make sure that the file is opened with read permission.
    fn read_block(&self, data: &mut [u8], block: u64) -> Result<u64>;

    /// Writes a block of data tchildo the file.
    ///
    /// `block_end` indicates the number of bytes to write, and
    /// the length of `data` should be the block size.
    ///
    /// The caller should make sure that the file is opened with write permission.
    fn write_block(&mut self, data: &[u8], block_end: usize, block: u64) -> Result<()>;

    /// Resizes the file.
    ///
    /// If the original file is larger than `len`, extra content
    /// got truncated; otherwise, the file is extended with zeros.
    fn set_len(&mut self, len: u64, block_size: u64) -> Result<()>;

    /// Sets the metadata.
    ///
    /// Filesystems capable of automatically persisting metadata
    /// (e.g., LocalFileSystem) should overrides this method with
    /// simply doing nothing. This is implemented, for example,
    /// by TrackingFileSystem to persist metadata to a database.
    ///
    /// This might be called frequently and implementations may
    /// want to take care to batch updates.
    fn set_metadata(&self, _meta: RawFileMeta) -> Result<()> {
        panic!("This filesystem does not support persisting metadata. You should wrap it in a TrackingFileSystem.");
    }

    /// Returns the metadata of the file.
    fn metadata(&self) -> Result<RawFileMeta> {
        unimplemented!()
    }
}

impl RawFileSystem for ArcRawFileSystem {
    fn open(&self, id: FileId, flags: FileFlags) -> Result<Box<dyn RawFile + Send + Sync>> {
        self.as_ref().open(id, flags)
    }

    fn create(&self, id: FileId) -> Result<()> {
        self.as_ref().create(id)
    }

    fn exists(&self, id: FileId) -> Result<bool> {
        self.as_ref().exists(id)
    }

    fn unlink(&self, id: FileId) -> Result<()> {
        self.as_ref().unlink(id)
    }

    fn stat(&self, id: FileId) -> Result<RawFileMeta> {
        self.as_ref().stat(id)
    }

    fn write(&self, id: FileId, data: &[u8]) -> Result<()> {
        self.as_ref().write(id, data)
    }
}

/// Raw file metadata.
///
/// The reason to take this out instead of simply using [`FileMeta`]
/// is that some filesystems (e.g., LocalFileSystem) can automatically
/// keep track of this efficiently, and we should use them whenever
/// possible. For other cases, we can use [`TrackingFileSystem`].
///
/// [`FileMeta`]: crate::FileMeta
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RawFileMeta {
    pub size: u64,

    #[serde(with = "time::opt_compact_date_time")]
    pub accessed: Option<DateTime<Utc>>,
    #[serde(with = "time::opt_compact_date_time")]
    pub modified: Option<DateTime<Utc>>,
}

impl RawFileMeta {
    pub fn create() -> Self {
        let now = Utc::now();
        Self {
            size: 0,

            accessed: Some(now),
            modified: Some(now),
        }
    }

    pub fn from_std(meta: std::fs::Metadata) -> Self {
        Self {
            size: meta.len(),

            accessed: meta
                .accessed()
                .ok()
                .as_ref()
                .map(time::system_time_to_date_time),
            modified: meta
                .modified()
                .ok()
                .as_ref()
                .map(time::system_time_to_date_time),
        }
    }

    #[cfg(feature = "opendal")]
    pub fn from_opendal(meta: ::opendal::Metadata) -> Self {
        Self {
            size: meta.content_length(),

            accessed: None,
            modified: meta.last_modified(),
        }
    }
}

/// Writes `data` to `vec` at `block`. Useful for implementing
/// [`RawFile::write_block`] in non-random-write filesystems,
/// where file content is fully loaded into memory in order to
/// be edited.
fn write_vec_at(vec: &mut Vec<u8>, data: &[u8], block_end: usize, block: u64) {
    let offset = data.len() * block as usize;
    if offset > vec.len() {
        vec.resize(offset + block_end, 0);
    }
    vec[offset..offset + block_end].copy_from_slice(data);
}
