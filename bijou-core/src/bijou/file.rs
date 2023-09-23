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

use crate::{path::Path, BijouFs, FileMeta, LowLevelFile, OpenOptions, Result};
use std::io::{self, Read, Seek, Write};

fn wrap<T>(f: impl FnOnce() -> Result<T>) -> io::Result<T> {
    f().map_err(|err| err.into())
}

/// An object providing access to an open file on the filesystem.
///
/// This corresponds to [`std::fs::File`].
pub struct File {
    inner: LowLevelFile,
    position: u64,
}

impl File {
    pub(crate) fn new(inner: LowLevelFile) -> Self {
        Self { inner, position: 0 }
    }

    /// Attempts to open a file in read-only mode.
    ///
    /// This corresponds to [`std::fs::File::open`].
    pub fn open(fs: &BijouFs, path: impl AsRef<Path>) -> Result<Self> {
        OpenOptions::new().read(true).open(fs, path)
    }

    /// Opens a file in write-only mode.
    ///
    /// This corresponds to [`std::fs::File::create`].
    pub fn create(fs: &BijouFs, path: impl AsRef<Path>) -> Result<Self> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(fs, path)
    }

    /// Creates a new file in read-write mode; error if the file exists.
    ///
    /// This corresponds to [`std::fs::File::create_new`].
    pub fn create_new(fs: &BijouFs, path: impl AsRef<Path>) -> Result<Self> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(fs, path)
    }

    /// Queries metadata about the underlying file.
    pub fn metadata(&self) -> Result<FileMeta> {
        self.inner.metadata()
    }

    /// Truncates or extends the underlying file, updating the size of this file to become size.
    pub fn set_len(&mut self, size: u64) -> Result<()> {
        self.inner.set_len(size)
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        wrap(|| {
            let read = self.inner.read(buf, self.position)?;
            self.position += read;
            Ok(read as usize)
        })
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        wrap(|| {
            let written = self.inner.write(buf, self.position)?;
            self.position += written;
            Ok(written as usize)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for File {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        wrap(|| {
            self.position = match pos {
                io::SeekFrom::Start(pos) => pos,
                io::SeekFrom::End(offset) => self
                    .metadata()?
                    .size
                    .checked_add_signed(offset)
                    .expect("position overflow"),
                io::SeekFrom::Current(offset) => self
                    .position
                    .checked_add_signed(offset)
                    .expect("position overflow"),
            };

            Ok(self.position)
        })
    }
}
