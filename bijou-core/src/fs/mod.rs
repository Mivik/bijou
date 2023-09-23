pub mod config;
mod file;
pub mod path;
pub mod raw;
pub mod time;

pub use file::*;
pub use raw::*;

use crate::{algo::Algorithm, db::DatabaseKey, Context, ErrorKind, Result};
use chrono::{DateTime, Utc};
use postcard::fixint;
use serde::{Deserialize, Serialize};
use std::fmt;

pub(crate) fn obtain_metadata(
    key: &DatabaseKey<FileMeta>,
    algo: &dyn Algorithm,
    f: impl FnOnce() -> Result<RawFileMeta>,
) -> Result<FileMeta> {
    let mut meta = key.get()?.kind(ErrorKind::NotFound)?;
    match meta.kind {
        FileKind::Directory => {
            meta.size = 512;
        }
        FileKind::Symlink => {}
        FileKind::File => {
            let std = f()?;
            meta.accessed = std.accessed.unwrap_or_else(time::unix_epoch_date_time);
            meta.modified = std.modified.unwrap_or_else(time::unix_epoch_date_time);
            meta.size = algo.plaintext_size(std.size);
        }
    }

    Ok(meta)
}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct DirItem {
    pub id: FileId,
    pub kind: FileKind,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy, Debug, PartialOrd, Ord)]
pub struct Inode(#[serde(with = "fixint::le")] pub u64);
impl Inode {
    pub const ROOT: Inode = Inode(1);
    pub const DUMMY: Inode = Inode(!0);

    #[inline]
    pub fn as_index(&self) -> usize {
        self.0 as usize - 1
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum FileKind {
    File,
    Symlink,
    Directory,
}

/// The internal unique identifier of a file.
#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct FileId(u64);
impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}
impl AsRef<[u8]> for FileId {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                &self.0 as *const u64 as *const u8,
                std::mem::size_of::<u64>(),
            )
        }
    }
}
impl FileId {
    pub const ROOT: FileId = FileId(0);

    pub fn gen() -> Self {
        Self(rand::random())
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(u64::from_le_bytes(bytes.try_into().unwrap()))
    }
}

/// Metadata for a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    pub id: FileId,
    pub kind: FileKind,

    /// Size of this file in bytes. We don't actually store this.
    /// We use the size of the underlying [`RawFileSystem`].
    #[serde(skip)]
    pub size: u64,

    /// Time of the last access. Only for directories.
    ///
    /// For files, we use times from the underlying filesystem.
    #[serde(with = "time::compact_date_time")]
    pub accessed: DateTime<Utc>,

    /// Time of the last modification. Only for directories.
    ///
    /// For files, we use times from the underlying filesystem.
    #[serde(with = "time::compact_date_time")]
    pub modified: DateTime<Utc>,

    /// Number of links. Should always be 1 for files since we don't
    /// support hardlinks.
    pub nlinks: u32,

    /// Optional Unix permissions.
    pub perms: Option<UnixPerms>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct UnixPerms {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
}
