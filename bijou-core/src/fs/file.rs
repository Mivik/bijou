use super::{obtain_metadata, FileMeta, RawFile, RawFileMeta};
use crate::{
    algo::{AlgoKey, Algorithm},
    bail,
    db::DatabaseKey,
    path::Path,
    Bijou, BijouFs, File, Result,
};
use std::{
    cell::RefCell,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, RwLock,
    },
};

/// Options and flags which can be used to configure how a file is opened.
///
/// This corresponds to [`std::fs::OpenOptions`].
#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) append: bool,
    pub(crate) truncate: bool,
    pub(crate) create: bool,
    pub(crate) create_new: bool,
}

impl OpenOptions {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the option for read access.
    ///
    /// See also [`std::fs::OpenOptions::read`].
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }

    /// Sets the option for write access.
    ///
    /// See also [`std::fs::OpenOptions::write`].
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }

    /// Sets the option for append mode.
    ///
    /// See also [`std::fs::OpenOptions::append`].
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.append = append;
        self
    }

    /// Sets the option for truncating a previous file.
    ///
    /// See also [`std::fs::OpenOptions::truncate`].
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }

    /// Sets the option to create a new file, or open it if it already exists.
    ///
    /// See also [`std::fs::OpenOptions::create`].
    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }

    /// Sets the option to always create a new file.
    ///
    /// See also [`std::fs::OpenOptions::create_new`].
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }

    #[doc(hidden)]
    pub fn to_flags(&self) -> FileFlags {
        let mut flags = FileFlags::EMPTY;

        if self.read {
            flags = flags | FileFlags::READ;
        }
        if self.write {
            flags = flags | FileFlags::WRITE;
        }
        if self.truncate {
            flags = flags | FileFlags::TRUNCATE;
        }

        flags
    }

    /// Opens a low level file at `path` with the options specified by `self`.
    pub fn open_low_level(&self, bijou: &Bijou, path: impl AsRef<Path>) -> Result<LowLevelFile> {
        Ok(if !(self.create || self.create_new) {
            bijou.open_file_direct(bijou.resolve(path.as_ref())?, self)?
        } else {
            let (parent, name) = bijou.resolve_parent_nonroot(path.as_ref())?;
            bijou.open_file(parent, name, self, None)?
        })
    }

    /// Opens a file at path `with` the options specified by `self`.
    ///
    /// This corresponds to [`std::fs::OpenOptions::open`].
    pub fn open(&self, fs: &BijouFs, path: impl AsRef<Path>) -> Result<File> {
        self.open_low_level(&fs.bijou, path).map(File::new)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileFlags(u8);
impl FileFlags {
    pub const EMPTY: FileFlags = FileFlags(0);
    pub const READ: FileFlags = FileFlags(1 << 0);
    pub const WRITE: FileFlags = FileFlags(1 << 1);
    pub const TRUNCATE: FileFlags = FileFlags(1 << 2);

    pub fn has(&self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }

    pub fn remove(&self, flag: Self) -> Self {
        Self(self.0 & !flag.0)
    }

    pub fn to_std(self) -> std::fs::OpenOptions {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(self.has(Self::READ))
            .write(self.has(Self::WRITE))
            .truncate(self.has(Self::TRUNCATE));
        opts
    }
}
impl std::ops::BitOr for FileFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

thread_local! {
    static BUFFER: RefCell<Vec<u8>> = RefCell::default();
}

/// File handle with low-level APIs, created by [`Bijou::open_file`].
///
/// [`Bijou::open_file`]: crate::Bijou::open_file
pub struct LowLevelFile {
    raw_file: Box<dyn RawFile + Send + Sync>,
    algo: Arc<dyn Algorithm + Send + Sync>,
    key: Box<dyn AlgoKey + Send + Sync>,

    db_key: DatabaseKey<FileMeta>,
    flags: FileFlags,

    lock: Arc<RwLock<RawFileMeta>>,
    handle_count: Arc<AtomicU32>,
}

impl LowLevelFile {
    pub(crate) fn new(
        raw_file: Box<dyn RawFile + Send + Sync>,
        algo: Arc<dyn Algorithm + Send + Sync>,
        key: Box<dyn AlgoKey + Send + Sync>,
        db_key: DatabaseKey<FileMeta>,
        flags: FileFlags,
        lock: Arc<RwLock<RawFileMeta>>,
        handle_count: Arc<AtomicU32>,
    ) -> Self {
        handle_count.fetch_add(1, Ordering::Relaxed);
        Self {
            raw_file,
            algo,
            key,

            db_key,
            flags,

            lock,
            handle_count,
        }
    }
}

impl LowLevelFile {
    fn load_block(
        algo: &dyn Algorithm,
        key: &dyn AlgoKey,
        raw_file: &dyn RawFile,
        buffer: &mut [u8],
        block: u64,
    ) -> Result<usize> {
        let block_end = raw_file.read_block(buffer, block)? as usize;

        if block_end != 0 {
            if block_end < algo.header_size() as usize {
                bail!(@CryptoError "incomplete block");
            }

            key.decrypt(block, &mut buffer[..block_end])?;
        }

        Ok(block_end)
    }

    /// Reads a number of bytes starting from a given offset.
    ///
    /// Returns the number of bytes read.
    pub fn read(&self, mut data: &mut [u8], offset: u64) -> Result<u64> {
        if !self.flags.has(FileFlags::READ) {
            bail!(@BadFileDescriptor "reading a file without permission");
        }

        if data.is_empty() {
            return Ok(0);
        }

        BUFFER.with(move |buffer| {
            let mut buffer = buffer.borrow_mut();
            buffer.resize(self.algo.block_size() as _, 0);

            let _guard = self.lock.read().unwrap();

            let content_size = self.algo.content_size();
            let header_size = self.algo.header_size() as usize;
            let tag_size = self.algo.tag_size() as usize;

            let start_block = offset / content_size;
            let start_offset = offset % content_size;

            let mut read = 0;

            // First block

            let block_end = Self::load_block(
                self.algo.as_ref(),
                self.key.as_ref(),
                self.raw_file.as_ref(),
                &mut buffer,
                start_block,
            )?;

            let block_read = {
                let offset = header_size + start_offset as usize;
                let len = block_end.saturating_sub(offset + tag_size).min(data.len());
                data[..len].copy_from_slice(&buffer[offset..offset + len]);
                len as u64
            };
            read += block_read;
            data = &mut data[block_read as usize..];

            let mut block = start_block + 1;
            for chunk in data.chunks_mut(content_size as _) {
                let block_end = Self::load_block(
                    self.algo.as_ref(),
                    self.key.as_ref(),
                    self.raw_file.as_ref(),
                    &mut buffer,
                    block,
                )?;

                if block_end == 0 {
                    break;
                }

                let block_read = {
                    let len = (block_end - header_size - tag_size).min(chunk.len());
                    chunk[..len].copy_from_slice(&buffer[header_size..header_size + len]);
                    len as u64
                };
                read += block_read;
                if block_read < content_size {
                    break;
                }

                block += 1;
            }

            sodiumoxide::utils::memzero(&mut buffer);

            // TODO access time

            Ok(read)
        })
    }

    /// Writes a number of bytes starting from a given offset.
    ///
    /// Returns the number of bytes written.
    pub fn write(&mut self, mut data: &[u8], offset: u64) -> Result<u64> {
        if !self.flags.has(FileFlags::WRITE) {
            bail!(@BadFileDescriptor "writing a file without permission");
        }

        if data.is_empty() {
            return Ok(0);
        }

        let mut meta = self.lock.write().unwrap();

        if offset > self.algo.plaintext_size(meta.size) {
            Self::set_len_inner(
                self.raw_file.as_mut(),
                self.algo.as_ref(),
                self.key.as_ref(),
                &mut meta,
                offset,
            )?;
        }

        BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            buffer.resize(self.algo.block_size() as _, 0);

            let content_size = self.algo.content_size();
            let header_size = self.algo.header_size() as usize;
            let tag_size = self.algo.tag_size() as usize;

            let start_block = offset / content_size;
            let start_offset = offset % content_size;

            let mut written = 0;

            // First block

            let mut block_end = if start_offset != 0 || data.len() < content_size as usize {
                Self::load_block(
                    self.algo.as_ref(),
                    self.key.as_ref(),
                    self.raw_file.as_ref(),
                    &mut buffer,
                    start_block,
                )?
            } else {
                0
            };

            let block_written = {
                let offset = header_size + start_offset as usize;
                let len = buffer
                    .len()
                    .saturating_sub(offset + tag_size)
                    .min(data.len());
                block_end = block_end.max(offset + len + tag_size);
                buffer[offset..offset + len].copy_from_slice(&data[..len]);
                len as u64
            };
            self.key.encrypt(start_block, &mut buffer[..block_end])?;
            self.raw_file.write_block(&buffer, block_end, start_block)?;
            written += block_written;
            data = &data[block_written as usize..];

            let mut block = start_block + 1;
            for chunk in data.chunks(content_size as _) {
                let block_end = if chunk.len() < content_size as usize {
                    Self::load_block(
                        self.algo.as_ref(),
                        self.key.as_ref(),
                        self.raw_file.as_mut(),
                        &mut buffer,
                        block,
                    )?
                } else {
                    0
                };

                let offset = header_size;
                buffer[offset..offset + chunk.len()].copy_from_slice(chunk);
                let block_end = block_end.max(offset + chunk.len() + tag_size);

                let block_written = chunk.len() as u64;

                self.key.encrypt(block, &mut buffer[..block_end])?;
                self.raw_file.write_block(&buffer, block_end, block)?;

                written += block_written;
                if block_written < content_size {
                    break;
                }

                block += 1;
            }

            sodiumoxide::utils::memzero(&mut buffer);

            meta.size = meta.size.max(self.algo.ciphertext_size(offset + written));
            meta.modified = Some(chrono::Utc::now());
            self.raw_file.set_metadata(meta.clone())?;

            Ok(written)
        })
    }

    fn edit_block(
        file: &mut dyn RawFile,
        algo: &dyn Algorithm,
        key: &dyn AlgoKey,
        block: u64,
        f: impl FnOnce(&dyn Algorithm, &mut [u8], usize) -> usize,
    ) -> Result<()> {
        BUFFER.with(|buffer| {
            let mut buffer = buffer.borrow_mut();
            buffer.resize(algo.block_size() as _, 0);
            let block_end = file.read_block(&mut buffer, block)? as usize;

            key.decrypt(block, &mut buffer[..block_end])?;
            let block_end = f(algo, &mut buffer, block_end);
            key.encrypt(block, &mut buffer[..block_end])?;

            file.write_block(&buffer, block_end, block)
        })
    }

    fn set_len_inner(
        file: &mut dyn RawFile,
        algo: &dyn Algorithm,
        key: &dyn AlgoKey,
        meta: &mut RawFileMeta,
        len: u64,
    ) -> Result<()> {
        let current_size = algo.plaintext_size(meta.size);

        if current_size == len {
            return Ok(());
        }

        if current_size < len {
            let block = current_size / algo.content_size();
            let offset = current_size % algo.content_size();

            if offset != 0 {
                Self::edit_block(file, algo, key, block, |algo, data, block_end| {
                    let end = if len / algo.content_size() == block {
                        (algo.metadata_size() + len % algo.content_size()) as usize
                    } else {
                        data.len()
                    };
                    data[block_end..end].fill(0);
                    end
                })?;
            }
        } else {
            let block = len / algo.content_size();
            let offset = len % algo.content_size();

            if offset != 0 {
                Self::edit_block(file, algo, key, block, |algo, _data, _block_end| {
                    (algo.metadata_size() + offset) as usize
                })?;
            }
        }

        let new_len = algo.ciphertext_size(len);
        file.set_len(new_len, algo.block_size())?;
        meta.size = new_len;

        Ok(())
    }

    /// Sets the size of a file.
    ///
    /// See [`Bijou::set_len`] for more details.
    ///
    /// [`Bijou::set_len`]: crate::Bijou::set_len
    pub fn set_len(&mut self, len: u64) -> Result<()> {
        if !self.flags.has(FileFlags::WRITE) {
            bail!(@BadFileDescriptor "resizing a file without permission");
        }

        let mut meta = self.lock.write().unwrap();
        Self::set_len_inner(
            self.raw_file.as_mut(),
            self.algo.as_ref(),
            self.key.as_ref(),
            &mut meta,
            len,
        )?;
        self.raw_file.set_metadata(meta.clone())?;

        Ok(())
    }

    /// Returns the metadata of a file.
    pub fn metadata(&self) -> Result<FileMeta> {
        let meta = self.lock.read().unwrap();
        obtain_metadata(&self.db_key, self.algo.as_ref(), || Ok(meta.clone()))
    }
}

impl Drop for LowLevelFile {
    fn drop(&mut self) {
        self.handle_count.fetch_sub(1, Ordering::Relaxed);
    }
}
