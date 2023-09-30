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

mod file;
mod fs;

pub use file::File;
pub use fs::BijouFs;

#[cfg(feature = "fuse")]
mod fuse;
#[cfg(feature = "fuse")]
pub use fuse::BijouFuse;

use crate::{
    algo::Algorithm,
    anyhow, bail,
    crypto::{cast_key, crypto_error, split_nonce_tag, xchacha20_siv},
    db::{consts, Database, DatabaseKey, RawKeyType},
    error::ResultExt,
    fs::{
        config::Config, obtain_metadata, path::Component, DirItem, FileKind, Inode, LowLevelFile,
        RawFileMeta, RawFileSystem, UnixPerms,
    },
    id_lock::IdLock,
    path::Path,
    serde_ext,
    sodium::{
        aead::XCHACHA20_POLY1305_IETF as AEAD,
        kdf::BLAKE2B as KDF,
        pwhash::{Limit, ARGON2_ID13 as PWHASH},
        utils,
    },
    Context, ErrorKind, FileId, FileMeta, OpenOptions, Result, SecretBytes,
};
use bijou_rocksdb::{
    DBIteratorWithThreadMode, DBPinnableSlice, DBWithThreadMode, Direction, IteratorMode,
    ReadOptions, SingleThreaded, WriteBatch,
};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use ring::{
    error::Unspecified,
    hkdf::{self, KeyType, Prk},
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path as StdPath, PathBuf as StdPathBuf},
    sync::{atomic::AtomicU32, Arc},
};
use tracing::{info, trace};

pub const SYMBOLIC_MAX_DEPTH: u32 = 40;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyStore {
    version: u32,

    #[serde(with = "serde_ext::base64")]
    salt: [u8; PWHASH.salt_len],
    #[serde(with = "serde_ext::base64")]
    nonce: [u8; AEAD.nonce_len],
    #[serde(with = "serde_ext::base64")]
    tag: [u8; AEAD.tag_len],

    ops_limit: usize,
    mem_limit: usize,

    #[serde(with = "serde_ext::base64")]
    master_key: [u8; KDF.key_len],
}

/// The main Bijou interface providing low level APIs.
///
/// For high level usage, see [`BijouFs`] and [`BijouFuse`].
pub struct Bijou {
    path: StdPathBuf,

    db: Arc<Database>,
    raw_fs: Arc<dyn RawFileSystem + Send + Sync>,
    algo: Arc<dyn Algorithm + Send + Sync>,

    config: Config,

    content_key: hkdf::Prk,
    file_name_key: Option<SecretBytes>,

    /// For files, this is acquired whenever the file is being
    /// read/written. Note that this is not necessarily acquired
    /// when the file is being opened. This conforms to the typical
    /// Unix semantics.
    ///
    /// For directories, this is acquired when its children are
    /// being modified (add, unlink, etc.).
    file_lock: Arc<IdLock<RawFileMeta>>,

    /// The currently opened file handles count for each file.
    ///
    /// The GC thread will periodically check files in the GC pool.
    /// If the file doesn't have opened handles anymore, the GC thread
    /// will remove it.
    file_open_counts: Arc<DashMap<FileId, Arc<AtomicU32>>>,
}

impl Bijou {
    const KDF_CTX: [u8; 8] = *b"@bijoufs";

    /// Create a new Bijou.
    ///
    /// The `path` should either be an empty directory or non-existent.
    ///
    /// `password` should be convertible to [`SecretBytes`] (e.g.
    /// [`Vec<u8>`]). Otherwise, you may use [`SecretBytes::move_from`]
    /// to create a [`SecretBytes`] from a mutable byte slice. This
    /// is to prevent the password from being copied around in memory.
    /// For more details, see [`SecretBytes`].
    pub fn create(
        path: impl AsRef<StdPath>,
        password: impl Into<SecretBytes>,
        config: Config,
        ops_limit: Limit,
        mem_limit: Limit,
    ) -> Result<()> {
        info!("creating Bijou");

        let password = password.into();

        let path = path.as_ref();
        if path.exists() {
            if !path.is_dir() || path.read_dir().wrap()?.next().is_some() {
                bail!(@AlreadyExists "not an empty directory: {}", path.display());
            }
        } else {
            std::fs::create_dir(path)
                .context("failed to create directory")
                .kind(ErrorKind::AlreadyExists)?;
        }

        // This is not made into SecretBytes because we'll encrypt it inplace later.
        let master_key = KDF.gen_key();
        let prk = KDF.prk(master_key.clone(), Self::KDF_CTX.as_slice());
        let config_key = prk.derive(0, AEAD.key_len)?;

        let salt = utils::gen_rand_bytes::<{ PWHASH.salt_len }>();

        let mut key = [0; AEAD.key_len];
        PWHASH.derive_key(&mut key, &password, &salt, ops_limit, mem_limit)?;
        drop(password);
        let nonce = utils::gen_rand_bytes::<{ AEAD.nonce_len }>();
        let mut tag = [0; AEAD.tag_len];

        let mut encrypted_master_key = [0; KDF.key_len];
        AEAD.encrypt(
            &mut encrypted_master_key,
            &mut tag,
            &master_key,
            Some(b"bijou"),
            &nonce,
            &key,
        )?;
        drop(master_key);

        let keystore = KeyStore {
            version: 0,

            salt,
            nonce,
            tag,

            ops_limit: ops_limit.eval(PWHASH.ops_limits),
            mem_limit: mem_limit.eval(PWHASH.mem_limits),

            master_key: encrypted_master_key,
        };
        (|| {
            serde_json::to_writer_pretty(
                std::fs::File::create(path.join("keystore.json")).wrap()?,
                &keystore,
            )
            .wrap()
        })()
        .context("failed to save keystore.json")?;

        let mut bytes = serde_json::to_vec(&config).wrap()?;
        let nonce = utils::gen_rand_bytes::<{ AEAD.nonce_len }>();
        let mut tag = [0; AEAD.tag_len];
        AEAD.encrypt_inplace(&mut bytes, &mut tag, &nonce, None, &config_key)?;
        drop(config_key);
        bytes = nonce
            .into_iter()
            .chain(bytes.into_iter())
            .chain(tag.into_iter())
            .collect::<Vec<_>>();
        std::fs::write(path.join("config.json"), bytes).context("failed to save config.json")?;

        Ok(())
    }

    /// Open an existing Bijou.
    ///
    /// `password` should be convertible to [`SecretBytes`] (e.g.
    /// [`Vec<u8>`]). Otherwise, you may use [`SecretBytes::move_from`]
    /// to create a [`SecretBytes`] from a mutable byte slice. This
    /// is to prevent the password from being copied around in memory.
    /// For more details, see [`SecretBytes`].
    pub fn open(path: impl Into<StdPathBuf>, password: impl Into<SecretBytes>) -> Result<Self> {
        let password = password.into();

        let path = path.into();
        if !path.is_dir() {
            bail!(@NotFound "directory not found: {}", path.display());
        }

        let file_lock = Arc::default();

        let mut keystore: KeyStore = (|| {
            serde_json::from_reader(std::fs::File::open(path.join("keystore.json")).wrap()?).wrap()
        })()
        .context("failed to read keystore.json")?;
        if keystore.version > 0 {
            bail!(@IncompatibleVersion "keystore version {} is not supported", keystore.version);
        }

        let mut key = [0; AEAD.key_len];
        PWHASH.derive_key(
            &mut key,
            &password,
            &keystore.salt,
            Limit::Custom(keystore.ops_limit),
            Limit::Custom(keystore.mem_limit),
        )?;

        let mut master_key: SecretBytes = SecretBytes::move_from(&mut keystore.master_key);
        AEAD.decrypt_inplace(
            &mut master_key,
            &keystore.tag,
            Some(b"bijou"),
            &keystore.nonce,
            &key,
        )
        .context("incorrect password")?;
        let mk = KDF.prk(master_key, Self::KDF_CTX.as_slice());

        let config_key = mk.derive(0, AEAD.key_len)?;
        let content_key_bytes = mk.derive(1, hkdf::KeyType::len(&hkdf::HKDF_SHA256))?;

        let content_key = Prk::new_less_safe(hkdf::HKDF_SHA256, &content_key_bytes);
        drop(content_key_bytes);

        let mut config =
            std::fs::read(path.join("config.json")).context("failed to read config.json")?;
        // Safety
        //
        // libsodium uses char* under the hood, which
        // does not require any alignment guarantees.
        let (nonce, config, tag) = split_nonce_tag(&mut config, AEAD.nonce_len, AEAD.tag_len);
        AEAD.decrypt_inplace(config, tag, None, nonce, &config_key)?;
        drop(config_key);
        let config: Config = serde_json::from_slice(config).context("failed to parse config")?;

        info!("config: {config:?}");

        let file_name_key = if config.encrypt_file_name {
            Some(mk.derive(2, hkdf::KeyType::len(&hkdf::HKDF_SHA256))?)
        } else {
            None
        };

        let db_key = if config.encrypt_db {
            Some(mk.derive(3, Database::KEYBYTES)?)
        } else {
            None
        };

        let data_dir = path.join("data");
        if !data_dir.is_dir() {
            std::fs::create_dir_all(&data_dir).context("failed to create data directory")?;
        }

        let db = Arc::new(Database::open(path.join("db"), db_key)?);
        let raw_fs = config
            .storage
            .build(&db, &data_dir)
            .context("failed to build storage")?;

        info!("launching Bijou");

        let file_open_counts = Arc::new(DashMap::<FileId, Arc<AtomicU32>>::new());

        let mut result = Self {
            path,

            db,
            raw_fs,
            algo: config.to_algorithm()?,

            config,

            content_key,
            file_name_key,

            file_lock,
            file_open_counts,
        };
        result.init()?;
        Ok(result)
    }

    /// Returns the local path of this Bijou.
    pub fn path(&self) -> &StdPath {
        &self.path
    }

    fn child_key<T>(&self, key: DatabaseKey<T>, name: &str) -> Result<DatabaseKey<DirItem>> {
        if let Some(file_name_key) = &self.file_name_key {
            if name != "." && name != ".." {
                // TODO cache
                let mut name = name.as_bytes().to_vec();
                let tag = xchacha20_siv::encrypt_detached(
                    &mut name,
                    key.key.as_slice(),
                    cast_key(file_name_key),
                )
                .map_err(crypto_error)?;
                name.extend(tag.0);
                return Ok(key.derive(consts::DIR_DERIVE).derive(&name).typed());
            }
        }

        Ok(key
            .derive(consts::DIR_DERIVE)
            .derive(name.as_bytes())
            .typed())
    }

    fn init(&mut self) -> Result<()> {
        let root_id = FileId::ROOT;
        let root_key = self.get_key(root_id);
        if !root_key.exists()? {
            let now = Utc::now();
            let attrs = FileMeta {
                id: root_id,
                kind: FileKind::Directory,

                size: 0,

                accessed: now,
                modified: now,

                nlinks: 2,

                perms: if self.config.unix_perms {
                    Some(UnixPerms {
                        mode: 0o755,
                        uid: 0,
                        gid: 0,
                    })
                } else {
                    None
                },
            };

            let mut batch = self.db.batch();
            root_key.put_batch(&mut batch, &attrs)?;
            self.child_key(root_key.clone(), ".")?.put_batch(
                &mut batch,
                &DirItem {
                    id: root_id,
                    kind: FileKind::Directory,
                },
            )?;
            self.child_key(root_key, "..")?.put_batch(
                &mut batch,
                &DirItem {
                    id: root_id,
                    kind: FileKind::Directory,
                },
            )?;

            batch.commit()?;
        }

        Ok(())
    }

    /// Returns the root inode.
    pub fn root(&self) -> Inode {
        Inode::ROOT
    }

    fn allocate_id(&self) -> Result<FileId> {
        let mut id = FileId::gen();

        while self.get_key(id).exists()? {
            // Unlikely
            id = FileId::gen();
        }
        Ok(id)
    }

    /// Looks up a file by name.
    ///
    /// Returns the inode and its generation.
    pub fn lookup(&self, parent: FileId, name: &str) -> Result<FileId> {
        Ok(self
            .child_key(self.get_key(parent), name)?
            .get()?
            .kind(ErrorKind::NotFound)?
            .id)
    }

    fn get_key(&self, file: FileId) -> DatabaseKey<FileMeta> {
        self.db.key(consts::FILE_ROOT).derive(file).typed()
    }

    fn get_raw_meta(&self, key: &DatabaseKey<FileMeta>) -> Result<FileMeta> {
        key.get()?.kind(ErrorKind::NotFound)
    }

    /// Returns the metadata of the given file.
    pub fn get_meta(&self, file: FileId) -> Result<FileMeta> {
        obtain_metadata(&self.get_key(file), self.algo.as_ref(), || {
            self.raw_fs.stat(file)
        })
    }

    /// Creates a new file (or directory, symlink, etc.).
    ///
    /// `symlink` must not be `None` if `kind` is `FileKind::Symlink`.
    pub fn make_node(
        &self,
        parent: FileId,
        name: &str,
        kind: FileKind,
        symlink: Option<String>,
        perms: Option<UnixPerms>,
    ) -> Result<FileMeta> {
        trace!(%parent, name, ?kind, "make node");
        let lock = self.file_lock.get(parent);
        let _guard = lock.write().unwrap();

        let mut batch = self.db.batch();

        let parent_key = self.get_key(parent);
        let child_key = self.child_key(parent_key.clone(), name)?;
        if child_key.exists()? {
            bail!(@AlreadyExists? "file already exists: {name}");
        }

        let now = Utc::now();

        let mut parent_meta = self.get_raw_meta(&parent_key)?;
        parent_meta.modified = now;
        parent_meta.nlinks += (kind == FileKind::Directory) as u32;
        parent_key.put_batch(&mut batch, &parent_meta)?;

        let id = self.allocate_id()?;
        let key = self.get_key(id);
        let meta = FileMeta {
            id,
            kind,

            size: 0,

            accessed: now,
            modified: now,

            nlinks: if kind == FileKind::Directory { 2 } else { 1 },

            perms: perms.filter(|_| self.config.unix_perms),
        };
        key.put_batch(&mut batch, &meta)?;

        match kind {
            FileKind::Directory => {
                self.child_key(key.clone(), ".")?.put_batch(
                    &mut batch,
                    &DirItem {
                        id,
                        kind: FileKind::Directory,
                    },
                )?;
                self.child_key(key, "..")?.put_batch(
                    &mut batch,
                    &DirItem {
                        id: parent,
                        kind: FileKind::Directory,
                    },
                )?;
            }
            FileKind::Symlink => {
                let Some(target) = symlink else {
                    bail!(@InvalidInput "symlink target must not be None");
                };
                key.derive(consts::SYMLINK_DERIVE)
                    .typed::<String>()
                    .put_batch(&mut batch, &target)?;
            }
            _ => {}
        }

        child_key.put_batch(
            &mut batch,
            &DirItem {
                id,
                kind: meta.kind,
            },
        )?;

        batch.commit()?;

        if kind == FileKind::File {
            self.raw_fs.create(id)?;
        }

        Ok(meta)
    }

    /// Creates a hard link for the given file.
    pub fn link(&self, file: FileId, parent: FileId, name: &str) -> Result<FileMeta> {
        trace!(%parent, name, "link");

        let lock = self.file_lock.get(parent);
        let _guard = lock.write().unwrap();

        let mut batch = self.db.batch();

        let key = self.get_key(file);
        let mut meta = self.get_raw_meta(&key)?;
        if meta.kind == FileKind::Directory {
            bail!(@InvalidInput? "creating hard link to directory");
        }
        meta.nlinks += 1;
        key.put_batch(&mut batch, &meta)?;

        let parent_key = self.get_key(parent);
        let child_key = self.child_key(parent_key, name)?;
        if child_key.exists()? {
            bail!(@AlreadyExists? "file already exists: {name}");
        }
        child_key.put_batch(
            &mut batch,
            &DirItem {
                id: file,
                kind: meta.kind,
            },
        )?;

        batch.commit()?;

        Ok(meta)
    }

    fn derive_key(&self, file: FileId) -> Result<SecretBytes> {
        let mut bytes = SecretBytes::allocate(self.algo.key_size());
        struct DummyKey(usize);
        impl KeyType for DummyKey {
            fn len(&self) -> usize {
                self.0
            }
        }
        (|| -> Result<(), Unspecified> {
            self.content_key
                .expand(&[file.as_ref()], DummyKey(self.algo.key_size()))?
                .fill(&mut bytes)
        })()
        .map_err(|_| anyhow!(@CryptoError "failed to derive key"))?;

        Ok(bytes)
    }

    fn open_inner(&self, meta: FileMeta, options: &OpenOptions) -> Result<LowLevelFile> {
        let flags = options.to_flags();
        let raw_file = self
            .raw_fs
            .open(meta.id, options.clone().read(true).to_flags())?;
        let key = self.get_key(meta.id);

        Ok(LowLevelFile::new(
            raw_file,
            Arc::clone(&self.algo),
            self.algo.key(self.derive_key(meta.id)?)?,
            key,
            flags,
            self.file_lock
                .get_or_try_insert(meta.id, || self.raw_fs.stat(meta.id))?,
            Arc::clone(&self.file_open_counts.entry(meta.id).or_default()),
        ))
    }

    /// Opens a file directly.
    ///
    /// As its parameters imply, this method **does not support
    /// creating the file**.
    ///
    /// See also [`open_file`].
    ///
    /// [`open_file`]: Bijou::open_file
    pub fn open_file_direct(&self, file: FileId, options: &OpenOptions) -> Result<LowLevelFile> {
        let meta = self.get_raw_meta(&self.get_key(file))?;
        self.open_inner(meta, options)
    }

    /// Opens a file, and creates it if necessary.
    ///
    /// See also [`open_file_direct`].
    ///
    /// [`open_file_direct`]: Bijou::open_file_direct
    pub fn open_file(
        &self,
        parent: FileId,
        name: &str,
        options: &OpenOptions,
        perms: Option<UnixPerms>,
    ) -> Result<LowLevelFile> {
        if options.truncate && !options.write {
            bail!(@InvalidInput? "cannot specify truncate without write")
        }
        match self.child_key(self.get_key(parent), name)?.get()? {
            Some(item) => {
                if options.create_new {
                    bail!(@AlreadyExists? "requiring create_new but file already exists: {name}");
                }
                self.open_file_direct(item.id, options)
            }
            None => {
                if options.create || options.create_new {
                    let meta = self.make_node(parent, name, FileKind::File, None, perms)?;
                    self.open_inner(meta, options)
                } else {
                    bail!(@NotFound? "file not found: {name}");
                }
            }
        }
    }

    pub(crate) fn resolve_inner(
        &self,
        mut stack: Vec<FileId>,
        path: &Path,
        depth: &mut u32,
    ) -> Result<FileId> {
        for comp in path.components() {
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
                other => {
                    let id = self.lookup(*stack.last().unwrap(), other.as_str())?;
                    let id = match self.read_link(id) {
                        Ok(path) => {
                            *depth += 1;
                            if *depth > SYMBOLIC_MAX_DEPTH {
                                bail!(@FilesystemLoop? "too many levels of symbolic links");
                            }
                            // symlink
                            self.resolve_inner(stack.clone(), Path::new(&path), depth)?
                        }
                        Err(err) if err.kind() == ErrorKind::InvalidInput => {
                            // not a symlink
                            id
                        }
                        Err(err) => return Err(err),
                    };
                    stack.push(id);
                }
            }
        }

        Ok(stack.into_iter().rev().next().unwrap())
    }

    /// Resolves a path to a file.
    pub fn resolve(&self, path: impl AsRef<Path>) -> Result<FileId> {
        self.resolve_inner(vec![FileId::ROOT], path.as_ref(), &mut 0)
    }

    /// Resolves a path, returning its parent and its name.
    ///
    /// If the path is `/`, returns `(FileId::ROOT, None)`.
    ///
    /// Different from [`resolve`], this method does not require
    /// the path to exist.
    ///
    /// [`resolve`]: Bijou::resolve
    pub fn resolve_parent<'a>(&self, path: &'a Path) -> Result<(FileId, Option<&'a str>)> {
        let mut stack = vec![(FileId::ROOT, "")];
        let mut current_name = None;
        let mut symlink_depth = 0;
        for comp in path.components() {
            match comp {
                Component::RootDir => {
                    stack.truncate(1);
                    current_name = None;
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    if stack.len() == 1 {
                        current_name = None;
                    } else {
                        current_name = Some(stack.pop().unwrap().1);
                    }
                }
                Component::Normal(name) => {
                    if let Some(parent_name) = current_name {
                        let parent = self.resolve_inner(
                            stack.iter().map(|it| it.0).collect(),
                            Path::new(parent_name),
                            &mut symlink_depth,
                        )?;
                        stack.push((parent, parent_name));
                    }
                    current_name = Some(name);
                }
            }
        }
        Ok((stack.into_iter().rev().next().unwrap().0, current_name))
    }

    /// Resolves a path, returning its parent and its name.
    ///
    /// Different from [`resolve_parent`], this will throw an error
    /// if the path is `/`.
    ///
    /// [`resolve_parent`]: Bijou::resolve_parent
    pub fn resolve_parent_nonroot<'a>(&self, path: &'a Path) -> Result<(FileId, &'a str)> {
        let (parent, name) = self.resolve_parent(path)?;
        let Some(name) = name else {
            bail!(@InvalidInput "expected non-root path, got `{path}`");
        };
        Ok((parent, name))
    }

    /// Returns an iterator of the entries of the given directory.
    ///
    /// Note that [`DirIterator::reset`] must be called before
    /// the iterator is used.
    ///
    /// The content will only be updated when the iterator is reset.
    /// Before that, the content is a snapshot of the directory
    /// at the time of the last call to [`DirIterator::reset`].
    ///
    /// The results include `.` and `..`.
    pub fn read_dir(&self, id: FileId) -> Result<DirIterator> {
        let key = self.get_key(id);
        if key.get()?.kind(ErrorKind::NotFound)?.kind != FileKind::Directory {
            bail!(@NotADirectory "not a directory");
        }
        let mut opts = ReadOptions::default();
        opts.set_iterate_upper_bound(key.clone().derive(consts::DIR_DERIVE_UPPER).key.to_vec());
        Ok(DirIterator {
            key: key.derive(consts::DIR_DERIVE).key,
            inner: self.db.0.iterator_opt(IteratorMode::Start, opts),
            // inner: self.db.0.prefix_iterator(&key.derive(consts::DIR_DERIVE).key),
            decrypt: self.file_name_key.as_ref().map(|key| (id, cast_key(key))),
        })
    }

    fn unlink_inner(
        &self,
        batch: &mut WriteBatch,
        parent: FileId,
        name: &str,
    ) -> Result<Option<FileId>> {
        trace!(%parent, name, "unlink");

        let child = self.lookup(parent, name)?;

        let key = self.get_key(child);
        let mut meta = self.get_raw_meta(&key)?;
        let is_dir = meta.kind == FileKind::Directory;

        if is_dir && self.read_dir(child)?.reset().nth(2).is_some() {
            bail!(@NotEmpty? "trying to unlink non-empty directory: {name}");
        }

        let parent_key = self.get_key(parent);
        let mut parent_meta = self.get_raw_meta(&parent_key)?;

        parent_meta.modified = Utc::now();
        parent_meta.nlinks -= is_dir as u32;
        parent_key.put_batch(batch, &parent_meta)?;

        self.child_key(parent_key, name)?.delete_batch(batch);

        if meta.kind == FileKind::Directory {
            meta.nlinks = 0;

            self.child_key(key.clone(), ".")?.delete_batch(batch);
            self.child_key(key.clone(), "..")?.delete_batch(batch);

            // Directory can always be deleted directly
            // since they don't have hardlinks.
            key.delete_batch(batch);
        } else {
            // TODO can symlinks have hardlink?

            // For files, we reduce its nlinks by 1.
            // If it reaches zero, we put it into the GC pool.
            assert!(meta.nlinks > 0);
            meta.nlinks -= 1;

            if meta.nlinks == 0 {
                key.delete_batch(batch);
                // batch.delete_range(
                // key.clone().derive(consts::XATTR_DERIVE).key,
                // key.clone().derive(consts::XATTR_DERIVE_UPPER).key,
                // );
                for item in key.range_iter(consts::XATTR_DERIVE, consts::XATTR_DERIVE_UPPER) {
                    let item = item.wrap()?;
                    batch.delete(&item.0);
                }
                if meta.kind == FileKind::Symlink {
                    key.derive(consts::SYMLINK_DERIVE).delete_batch(batch);
                } else {
                    self.raw_fs.unlink(child)?;
                }
            } else {
                key.put_batch(batch, &meta)?;
            }
        }

        Ok(if meta.nlinks == 0 { Some(child) } else { None })
    }

    /// Unlinks a file.
    ///
    /// Returns the removed file if it is a file and has no more
    /// hardlinks. Otherwise, returns `None`.
    pub fn unlink(&self, parent: FileId, name: &str) -> Result<Option<FileId>> {
        let parent_lock = self.file_lock.get(parent);
        let _guard = parent_lock.write().unwrap();

        let mut batch = self.db.batch();
        let removed = self.unlink_inner(&mut batch, parent, name)?;
        batch.commit()?;

        Ok(removed)
    }

    /// Renames a file.
    ///
    /// Returns the removed file if it is a file and has no more
    /// hardlinks. Otherwise, returns `None`.
    pub fn rename(
        &self,
        parent: FileId,
        name: &str,
        new_parent: FileId,
        new_name: &str,
    ) -> Result<Option<FileId>> {
        trace!(%parent, name, %new_parent, new_name, "rename");

        if parent == new_parent && name == new_name {
            return Ok(None);
        }

        let parent_key = self.get_key(parent);
        let new_parent_key = self.get_key(new_parent);

        let parent_lock = self.file_lock.get(parent);
        let new_parent_lock = self.file_lock.get(new_parent);
        let _guard = parent_lock.write().unwrap();
        let _guard2 = if parent == new_parent {
            None
        } else {
            Some(new_parent_lock.write().unwrap())
        };

        let mut batch = self.db.batch();

        let old_child_dir_key = self.child_key(parent_key.clone(), name)?;
        let new_child_dir_key = self.child_key(new_parent_key.clone(), new_name)?;

        let dir_item = old_child_dir_key.get()?.kind(ErrorKind::NotFound)?;
        let child = self.get_key(dir_item.id);
        let meta = self.get_raw_meta(&child)?;

        let mut removed = None;

        if new_child_dir_key.exists()? {
            removed = self.unlink_inner(&mut batch, new_parent, new_name)?;
        }

        old_child_dir_key.delete_batch(&mut batch);
        new_child_dir_key.put_batch(&mut batch, &dir_item)?;

        let now = Utc::now();

        if meta.kind == FileKind::Directory {
            self.child_key(child, "..")?.put_batch(
                &mut batch,
                &DirItem {
                    id: new_parent,
                    kind: FileKind::Directory,
                },
            )?;
        }

        let mut parent_meta = self.get_raw_meta(&parent_key)?;
        parent_meta.nlinks -= (meta.kind == FileKind::Directory) as u32;
        parent_meta.modified = now;
        parent_key.put_batch(&mut batch, &parent_meta)?;

        let mut new_parent_meta = self.get_raw_meta(&new_parent_key)?;
        new_parent_meta.nlinks += (meta.kind == FileKind::Directory) as u32;
        new_parent_meta.modified = now;
        new_parent_key.put_batch(&mut batch, &new_parent_meta)?;

        batch.commit()?;

        Ok(removed)
    }

    /// Sets the size of a file.
    ///
    /// If `len` is larger than the current size, the file will be
    /// extended with zeros. Otherwise, the file will be truncated.
    pub fn set_len(&self, file: FileId, len: u64) -> Result<()> {
        trace!(%file, len, "set length");
        self.open_file_direct(file, OpenOptions::new().write(true))?
            .set_len(len)
    }

    /// Reads the target of a symlink.
    pub fn read_link(&self, file: FileId) -> Result<String> {
        trace!(%file, "read link");
        let key = self.get_key(file);
        let meta = self.get_raw_meta(&key)?;
        if meta.kind != FileKind::Symlink {
            bail!(@InvalidInput? "not a symlink");
        }

        key.derive(consts::SYMLINK_DERIVE)
            .typed::<String>()
            .get()?
            .kind(ErrorKind::NotFound)
    }

    /// Sets atime and mtime of a file.
    pub fn set_times(
        &self,
        file: FileId,
        accessed: DateTime<Utc>,
        modified: DateTime<Utc>,
    ) -> Result<()> {
        let key = self.get_key(file);
        let mut meta = self.get_raw_meta(&key)?;
        meta.accessed = accessed;
        meta.modified = modified;
        key.put(&meta)?;

        Ok(())
    }

    /// Sets the permissions of a file.
    pub fn set_perms(
        &self,
        id: FileId,
        mode: Option<u16>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<()> {
        let key = self.get_key(id);
        let mut meta = self.get_raw_meta(&key)?;
        meta.perms = Some(UnixPerms {
            mode: mode
                .or_else(|| meta.perms.as_ref().map(|it| it.mode))
                .unwrap_or(0o640),
            uid: uid
                .or_else(|| meta.perms.as_ref().map(|it| it.uid))
                .unwrap_or(0),
            gid: gid
                .or_else(|| meta.perms.as_ref().map(|it| it.gid))
                .unwrap_or(0),
        });
        key.put(&meta)?;

        Ok(())
    }

    /// Sets extended attribute (xattr) of a file.
    pub fn set_xattr(&self, id: FileId, name: &str, value: &[u8]) -> Result<()> {
        self.get_key(id)
            .derive(consts::XATTR_DERIVE)
            .derive(name)
            .write(value)
    }

    /// Returns extended attribute (xattr) of a file.
    pub fn get_xattr<R>(
        &self,
        id: FileId,
        name: &str,
        cb: impl FnOnce(Result<Option<DBPinnableSlice>>) -> R,
    ) -> R {
        if self.config.disable_xattr_gets {
            return cb(Err(anyhow!(@Unsupported "xattr gets are disabled")));
        }
        cb(self
            .get_key(id)
            .derive(consts::XATTR_DERIVE)
            .derive(name)
            .read())
    }

    /// Removes extended attribute (xattr) of a file.
    pub fn remove_xattr(&self, id: FileId, name: &str) -> Result<()> {
        self.get_key(id)
            .derive(consts::XATTR_DERIVE)
            .derive(name)
            .delete()
    }

    // TODO cache
    /// Returns all extended attributes (xattr) of a file.
    pub fn xattrs(&self, id: FileId) -> Result<Vec<String>> {
        let mut result = Vec::new();
        let key = self.get_key(id);
        let iter = key.range_iter(consts::XATTR_DERIVE, consts::XATTR_DERIVE_UPPER);
        let len =
            consts::FILE_ROOT.len() + std::mem::size_of::<FileId>() + consts::XATTR_DERIVE.len();
        for entry in iter {
            let (key, _value) = entry.wrap()?;
            let name = &key[len..];
            result.push(String::from_utf8(name.to_vec()).unwrap());
        }

        Ok(result)
    }
}

/// Iterator of directory entries, created by [`Bijou::read_dir`].
pub struct DirIterator<'db> {
    key: RawKeyType,
    inner: DBIteratorWithThreadMode<'db, DBWithThreadMode<SingleThreaded>>,
    decrypt: Option<(FileId, &'db xchacha20_siv::Key)>,
}
impl DirIterator<'_> {
    pub fn reset(&mut self) -> &mut Self {
        self.inner
            .set_mode(IteratorMode::From(&self.key, Direction::Forward));
        self
    }
}
impl Iterator for DirIterator<'_> {
    type Item = Result<(String, DirItem)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|result| {
            let (mut key, value) = result.wrap()?;
            let name = &mut key[consts::FILE_ROOT.len()
                + std::mem::size_of::<FileId>()
                + consts::DIR_DERIVE.len()..];
            if let Some((id, key)) = &self.decrypt {
                if name != b"." && name != b".." {
                    assert!(name.len() > xchacha20_siv::ABYTES);
                    let (name, tag) = name.split_at_mut(name.len() - xchacha20_siv::ABYTES);
                    xchacha20_siv::decrypt_inplace(name, cast_key(tag), id.as_ref(), key)
                        .map_err(|_| anyhow!(@CryptoError "failed to decrypt filename"))?;
                    return Ok((
                        String::from_utf8(name.to_vec()).unwrap(),
                        postcard::from_bytes(&value).wrap()?,
                    ));
                }
            }
            Ok((
                String::from_utf8(name.to_vec()).unwrap(),
                postcard::from_bytes(&value).wrap()?,
            ))
        })
    }
}
