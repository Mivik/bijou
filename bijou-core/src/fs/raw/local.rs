use super::{RawFile, RawFileMeta, RawFileSystem};
use crate::{
    error::{bail, ErrorExt},
    fs::{FileFlags, FileId},
    Context, ErrorKind, Result,
};
use std::{fs, io, path};

/// The default local filesystem.
pub struct LocalFileSystem {
    root: path::PathBuf,
}
impl LocalFileSystem {
    pub fn new(root: impl Into<path::PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path(&self, id: FileId) -> Result<path::PathBuf> {
        let name = id.to_string();
        let (dir, name) = name.split_at(2);
        let dir = self.root.join(dir);
        if !dir.exists() {
            fs::create_dir(&dir).kind(ErrorKind::IOError)?;
        }
        Ok(dir.join(name))
    }
}
impl RawFileSystem for LocalFileSystem {
    fn open(&self, id: FileId, flags: FileFlags) -> Result<Box<dyn RawFile + Send + Sync>> {
        Ok(Box::new(LocalFile::new(
            flags
                .to_std()
                .open(self.path(id)?)
                .context("failed to open local file")
                .kind(ErrorKind::IOError)?,
        )))
    }

    fn create(&self, id: FileId) -> Result<()> {
        fs::File::create(self.path(id)?)
            .context("failed to create local file")
            .kind(ErrorKind::IOError)?;
        Ok(())
    }

    fn exists(&self, id: FileId) -> Result<bool> {
        Ok(self.path(id)?.exists())
    }

    fn unlink(&self, id: FileId) -> Result<()> {
        fs::remove_file(self.path(id)?)
            .context("failed to unlink local file")
            .kind(ErrorKind::IOError)?;
        Ok(())
    }

    fn stat(&self, id: FileId) -> Result<RawFileMeta> {
        Ok(RawFileMeta::from_std(
            fs::metadata(self.path(id)?)
                .context("failed to stat local file")
                .kind(ErrorKind::IOError)?,
        ))
    }

    fn write(&self, id: FileId, data: &[u8]) -> Result<()> {
        fs::write(self.path(id)?, data)
            .context("failed to write to local file")
            .kind(ErrorKind::IOError)?;
        Ok(())
    }
}

#[cfg(any(unix, windows))]
struct LocalFile(fs::File);

#[cfg(not(any(unix, windows)))]
struct LocalFile(std::sync::Mutex<fs::File>);

#[cfg(unix)]
impl LocalFile {
    fn new(file: fs::File) -> Self {
        Self(file)
    }

    fn get_file(&self) -> &fs::File {
        &self.0
    }

    fn read_at(file: &fs::File, data: &mut [u8], offset: u64) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        file.read_at(data, offset)
    }

    fn write_at(file: &fs::File, data: &[u8], offset: u64) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        file.write_at(data, offset)
    }
}

#[cfg(windows)]
impl LocalFile {
    fn new(file: fs::File) -> Self {
        Self(file)
    }

    fn get_file(&self) -> &fs::File {
        &self.0
    }

    fn read_at(file: &fs::File, data: &mut [u8], offset: u64) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        file.seek_read(data, offset)
    }

    fn write_at(file: &fs::File, data: &[u8], offset: u64) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        file.seek_write(data, offset)
    }
}

#[cfg(not(any(unix, windows)))]
impl LocalFile {
    fn new(file: fs::File) -> Self {
        Self(file.into())
    }

    fn get_file(&self) -> std::sync::MutexGuard<fs::File> {
        self.0.lock().unwrap()
    }

    fn read_at(file: &mut fs::File, data: &mut [u8], offset: u64) -> io::Result<usize> {
        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(offset))?;
        file.read(data)
    }

    fn write_at(file: &mut fs::File, data: &[u8], offset: u64) -> io::Result<usize> {
        use std::io::{Seek, SeekFrom, Write};
        file.seek(SeekFrom::Start(offset))?;
        file.write(data)
    }
}

#[cfg(unix)]
impl RawFile for LocalFile {
    fn read_block(&self, data: &mut [u8], block: u64) -> Result<u64> {
        Ok(
            Self::read_at(&mut self.get_file(), data, block * data.len() as u64)
                .context("failed to read from local file")
                .kind(ErrorKind::IOError)? as u64,
        )
    }

    fn write_block(&mut self, data: &[u8], block_end: usize, block: u64) -> Result<()> {
        let mut file = self.get_file();
        let mut offset = block * data.len() as u64;
        let mut data = &data[..block_end];
        while !data.is_empty() {
            match Self::write_at(&mut file, data, offset) {
                Ok(0) => {
                    bail!(@IOError "failed to write whole buffer");
                }
                Ok(n) => {
                    data = &data[n..];
                    offset += n as u64;
                }
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    return Err(e
                        .wrap()
                        .context("failed to write to file")
                        .with_kind(ErrorKind::IOError))
                }
            }
        }

        Ok(())
    }

    fn set_len(&mut self, len: u64, _block_size: u64) -> Result<()> {
        self.get_file()
            .set_len(len)
            .context("failed to resize local file")
            .kind(ErrorKind::IOError)?;
        Ok(())
    }

    fn set_metadata(&self, _meta: RawFileMeta) -> Result<()> {
        Ok(())
    }

    fn metadata(&self) -> Result<RawFileMeta> {
        Ok(RawFileMeta::from_std(
            self.get_file()
                .metadata()
                .context("failed to get local file's metadata")
                .kind(ErrorKind::IOError)?,
        ))
    }
}
