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

use crate::{
    bail,
    error::Context,
    fs::{DirItem, FileKind},
    path::{Component, Path, PathBuf},
    Bijou, ErrorKind, File, FileId, FileMeta, Result,
};
use std::{
    io::{Read, Write},
    sync::Arc,
};

/// High level wrapper for [`Bijou`].
pub struct BijouFs {
    pub(crate) bijou: Arc<Bijou>,
}

impl BijouFs {
    /// Create a new `BijouFs` for the given Bijou.
    pub fn new(bijou: Arc<Bijou>) -> Self {
        Self { bijou }
    }

    /// Creates a new, empty directory at the provided path.
    ///
    /// This corresponds to [`std::fs::create_dir`].
    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<()> {
        let (parent, name) = self.bijou.resolve_parent_nonroot(path.as_ref())?;
        self.bijou
            .make_node(parent, name, FileKind::Directory, None, None)?;
        Ok(())
    }

    /// Recursively creates a directory and all of its parent components if they are missing.
    ///
    /// This corresponds to [`std::fs::create_dir_all`].
    pub fn create_dir_all(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let mut stack = vec![FileId::ROOT];
        let mut comps = path.components();
        let mut symlink_depth = 0;
        while let Some(comp) = comps.next() {
            match comp {
                Component::RootDir => {
                    stack.truncate(1);
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    if stack.len() > 1 {
                        stack.pop();
                    }
                }
                Component::Normal(name) => {
                    let parent = *stack.last().unwrap();
                    let id = match self.bijou.resolve_inner(
                        stack.clone(),
                        Path::new(name),
                        &mut symlink_depth,
                    ) {
                        Ok(id) => {
                            let meta = self.bijou.get_meta(id)?;
                            if meta.kind == FileKind::Directory {
                                id
                            } else {
                                bail!(@NotADirectory "`{}` is not a directory", &path.as_str()[..path.as_str().len() - comps.as_path().as_str().len()]);
                            }
                        }
                        Err(err) if err.kind() == ErrorKind::NotFound => {
                            self.bijou
                                .make_node(parent, name, FileKind::Directory, None, None)?
                                .id
                        }
                        Err(err) => return Err(err),
                    };
                    stack.push(id);
                }
            }
        }
        Ok(())
    }

    /// Creates a new hard link on the filesystem.
    ///
    /// This corresponds to [`std::fs::hard_link`].
    pub fn hard_link(&self, original: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<()> {
        let (parent, name) = self.bijou.resolve_parent_nonroot(link.as_ref())?;
        self.bijou
            .link(self.bijou.resolve(original)?, parent, name)?;
        Ok(())
    }

    /// Given a path, queries the file system to get information about a file, directory, etc.
    ///
    /// This corresponds to [`std::fs::metadata`].
    pub fn metadata(&self, path: impl AsRef<Path>) -> Result<FileMeta> {
        self.bijou.get_meta(self.bijou.resolve(path)?)
    }

    /// Reads the entire contents of a file into a bytes vector.
    ///
    /// This corresponds to [`std::fs::read`].
    pub fn read(&self, path: impl AsRef<Path>) -> Result<Vec<u8>> {
        let mut file = File::open(self, path.as_ref())?;
        let size = file.metadata().map_or(0, |m| m.size as usize);
        let mut bytes = Vec::with_capacity(size);
        file.read_exact(&mut bytes)
            .context("failed to read buffer")
            .kind(ErrorKind::IOError)?;
        Ok(bytes)
    }

    /// Returns an iterator over the entries within a directory.
    ///
    /// This corresponds to [`std::fs::read_dir`].
    pub fn read_dir(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<impl Iterator<Item = Result<(String, DirItem)>> + '_> {
        let mut iter = self.bijou.read_dir(self.bijou.resolve(path.as_ref())?)?;
        iter.reset();

        Ok(iter.filter(|item| {
            item.as_ref()
                .map_or(true, |item| item.0 != "." && item.0 != "..")
        }))
    }

    /// Reads a symbolic link, returning the file that the link points to.
    ///
    /// This corresponds to [`std::fs::read_link`].
    pub fn read_link(&self, path: impl AsRef<Path>) -> Result<PathBuf> {
        let path = path.as_ref();
        let target = self.bijou.read_link(self.bijou.resolve(path)?)?;
        Ok(path.join(Path::new(&target)))
    }

    /// Reads the entire contents of a file into a string.
    ///
    /// This corresponds to [`std::fs::read_to_string`].
    pub fn read_to_string(&self, path: impl AsRef<Path>) -> Result<String> {
        self.read(path.as_ref())
            .and_then(|bytes| String::from_utf8(bytes).context("invalid string"))
    }

    /// Removes an empty directory (or file).
    ///
    /// This corresponds to [`std::fs::remove_file`] and [`std::fs::remove_dir`].
    pub fn remove(&self, path: impl AsRef<Path>) -> Result<()> {
        let (parent, name) = self.bijou.resolve_parent_nonroot(path.as_ref())?;
        self.bijou.unlink(parent, name)?;
        Ok(())
    }

    fn remove_all_inner(&self, parent: FileId, name: &str) -> Result<()> {
        match self.bijou.unlink(parent, name) {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotEmpty => {
                let current = self.bijou.lookup(parent, name)?;
                for item in self.bijou.read_dir(current)? {
                    let item = item?;
                    if item.0 != "." && item.0 != ".." {
                        self.remove_all_inner(current, &item.0)?;
                    }
                }
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Removes a directory at this path, after removing all its contents.
    ///
    /// This corresponds to [`std::fs::remove_dir_all`].
    pub fn remove_all(&self, path: impl AsRef<Path>) -> Result<()> {
        let (parent, name) = self.bijou.resolve_parent_nonroot(path.as_ref())?;
        self.remove_all_inner(parent, name)
    }

    /// Rename a file or directory to a new name, replacing the original file if to already exists.
    ///
    /// This corresponds to [`std::fs::rename`].
    pub fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
        let (parent, name) = self.bijou.resolve_parent_nonroot(from.as_ref())?;
        let (new_parent, new_name) = self.bijou.resolve_parent_nonroot(to.as_ref())?;
        self.bijou.rename(parent, name, new_parent, new_name)?;
        Ok(())
    }

    /// Creates a new symbolic link on the filesystem.
    ///
    /// This corresponds to [`std::fs::hard_link`].
    pub fn soft_link(&self, original: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<()> {
        let (parent, name) = self.bijou.resolve_parent_nonroot(link.as_ref())?;
        self.bijou.make_node(
            parent,
            name,
            FileKind::Symlink,
            Some(original.as_ref().as_str().to_owned()),
            None,
        )?;
        Ok(())
    }

    /// Query the metadata about a file without following symlinks.
    ///
    /// This corresponds to [`std::fs::symlink_metadata`].
    pub fn symlink_metadata(&self, path: impl AsRef<Path>) -> Result<FileMeta> {
        let (parent, name) = self.bijou.resolve_parent_nonroot(path.as_ref())?;
        self.bijou.get_meta(self.bijou.lookup(parent, name)?)
    }

    /// Write a slice as the entire contents of a file.
    ///
    /// This corresponds to [`std::fs::write`].
    pub fn write(&self, path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<()> {
        let mut file = File::create(self, path.as_ref())?;
        file.write_all(contents.as_ref())
            .context("failed to write buffer")
            .kind(ErrorKind::IOError)
    }
}
