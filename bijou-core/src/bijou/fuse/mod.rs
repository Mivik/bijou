mod inode_table;

use crate::{
    begin_span,
    bijou::DirIterator,
    error::Context,
    fs::{time, DirItem, FileId, FileKind, FileMeta, Inode, LowLevelFile, UnixPerms},
    Bijou, OpenOptions, Result,
};
use chrono::{DateTime, Utc};
use fuser::{
    consts::{FOPEN_DIRECT_IO, FOPEN_KEEP_CACHE},
    mount2, FileAttr, Filesystem, MountOption, Request, TimeOrNow,
};
use inode_table::InodeTable;
use std::{
    cell::RefCell,
    ffi::{CString, OsStr},
    os::unix::prelude::OsStrExt,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};
use threadpool::ThreadPool;
use tracing::info;

const TTL: Duration = Duration::from_secs(1);

fn kind_to_fuse(kind: FileKind) -> fuser::FileType {
    match kind {
        FileKind::File => fuser::FileType::RegularFile,
        FileKind::Symlink => fuser::FileType::Symlink,
        FileKind::Directory => fuser::FileType::Directory,
    }
}

fn parse_open_options(flags: i32) -> Option<OpenOptions> {
    let mut opts = OpenOptions::new();
    match flags & libc::O_ACCMODE {
        libc::O_RDONLY => {
            opts.read(true);
        }
        libc::O_WRONLY => {
            opts.write(true);
        }
        libc::O_RDWR => {
            opts.read(true).write(true);
        }
        _ => {
            return None;
        }
    }
    if flags & libc::O_CREAT != 0 {
        opts.create(true);
    }
    if flags & libc::O_APPEND != 0 {
        opts.append(true);
    }
    Some(opts)
}

fn ptr_to_file(ptr: u64) -> &'static RwLock<LowLevelFile> {
    unsafe { &*(ptr as *const RwLock<LowLevelFile>) }
}

fn drop_as<T>(ptr: u64) {
    unsafe {
        let ptr = ptr as *mut T;
        ptr.drop_in_place();
        std::alloc::dealloc(ptr as _, std::alloc::Layout::new::<T>());
    }
}

struct Shared {
    table: RwLock<InodeTable>,
    uid: u32,
    gid: u32,
}

impl Shared {
    fn get_id(&self, inode: u64) -> FileId {
        self.table.read().unwrap().get_id(Inode(inode))
    }

    fn meta_to_fuse(&self, bijou: &Bijou, meta: FileMeta) -> (FileAttr, u64) {
        let perms = meta
            .perms
            .filter(|_| bijou.config.unix_perms)
            .unwrap_or(UnixPerms {
                mode: 0o777,
                uid: self.uid,
                gid: self.gid,
            });
        let (inode, gen) = self.table.write().unwrap().get_or_insert(meta.id, false);
        (
            FileAttr {
                ino: inode.0,
                size: meta.size,
                blocks: (meta.size + 511) / 512,
                blksize: 512,
                atime: time::date_time_to_system_time(&meta.accessed),
                mtime: time::date_time_to_system_time(&meta.modified),
                ctime: SystemTime::UNIX_EPOCH,
                crtime: SystemTime::UNIX_EPOCH,
                kind: kind_to_fuse(meta.kind),
                perm: perms.mode,
                nlink: meta.nlinks as _,
                uid: if meta.id == FileId::ROOT {
                    self.uid
                } else {
                    perms.uid
                },
                gid: if meta.id == FileId::ROOT {
                    self.gid
                } else {
                    perms.gid
                },
                rdev: 0,
                flags: 0,
            },
            gen,
        )
    }
}

fn to_perms(req: &Request, mode: u32) -> UnixPerms {
    UnixPerms {
        mode: mode as _,
        uid: req.uid(),
        gid: req.gid(),
    }
}

/// A Fuse wrapper for Bijou.
pub struct BijouFuse {
    bijou: Arc<Bijou>,
    shared: Arc<Shared>,

    thread_pool: ThreadPool,
}

thread_local! {
    static READ_BUFFER: RefCell<Vec<u8>> = RefCell::default();
}

impl BijouFuse {
    /// Creates a new `FuseWrapper` for the given Bijou.
    pub fn new(bijou: Arc<Bijou>) -> Self {
        Self {
            bijou,
            shared: Arc::new(Shared {
                table: RwLock::new(InodeTable::new()),
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
            }),

            thread_pool: ThreadPool::default(),
        }
    }

    fn clone_bijou(&self) -> Arc<Bijou> {
        Arc::clone(&self.bijou)
    }

    #[allow(clippy::too_many_arguments)]
    fn make_node(
        &self,
        req: &Request,
        mode: u32,
        parent: u64,
        name: &OsStr,
        kind: FileKind,
        symlink: Option<String>,
        reply: fuser::ReplyEntry,
    ) {
        let bijou = self.clone_bijou();
        let shared = Arc::clone(&self.shared);
        let perms = to_perms(req, mode);
        let name = name.to_string_lossy().into_owned();
        self.thread_pool.execute(move || {
            let result = {
                let id = shared.get_id(parent);
                bijou
                    .make_node(id, &name, kind, symlink, Some(perms))
                    .and_then(|meta| {
                        shared.table.write().unwrap().add(meta.id);
                        Ok(meta)
                    })
            };
            match result {
                Ok(meta) => {
                    let (attr, gen) = shared.meta_to_fuse(&bijou, meta);
                    reply.entry(&TTL, &attr, gen)
                }
                Err(err) => reply.error(err.to_libc()),
            }
        });
    }

    fn open_inner<T>(
        &mut self,
        id: FileId,
        flags: i32,
        reply: T,
        cb: impl FnOnce(T, u64, u32),
        error: impl FnOnce(T, libc::c_int),
    ) {
        let Some(opts) = parse_open_options(flags) else {
            error(reply, libc::EINVAL);
            return;
        };
        let bijou = &self.bijou;
        match bijou.open_file_direct(id, &opts) {
            Ok(file) => cb(
                reply,
                Box::into_raw(Box::new(RwLock::new(file))) as u64,
                if opts.write {
                    FOPEN_DIRECT_IO
                } else {
                    FOPEN_KEEP_CACHE
                },
            ),
            Err(err) => error(reply, err.to_libc()),
        }
    }

    /// Mounts the Bijou at the given mountpoint.
    pub fn mount(self, mount_point: impl AsRef<std::path::Path>) -> Result<()> {
        let mountpoint = mount_point.as_ref();
        info!("mounting Bijou at {}", mountpoint.display());
        mount2(
            self,
            mountpoint,
            &[
                MountOption::AutoUnmount,
                MountOption::FSName("bijou".to_owned()),
                MountOption::AllowOther,
                MountOption::DefaultPermissions,
            ],
        )
        .context("failed to mount Fuse filesystem")?;

        Ok(())
    }
}

#[doc(hidden)]
impl Filesystem for BijouFuse {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEntry) {
        let _span = begin_span("lookup");
        let bijou = &self.bijou;
        let id = self.shared.get_id(parent);
        let result = match bijou.lookup(id, &name.to_string_lossy()) {
            Ok(file) => bijou.get_meta(file).map(|meta| {
                self.shared
                    .table
                    .write()
                    .unwrap()
                    .get_or_insert(meta.id, true);
                meta
            }),
            Err(err) => Err(err.take_it_easy()),
        };
        match result {
            Ok(meta) => {
                let (attr, gen) = self.shared.meta_to_fuse(bijou, meta);
                reply.entry(&TTL, &attr, gen);
            }
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn forget(&mut self, _req: &Request, inode: u64, nlookup: u64) {
        self.shared
            .table
            .write()
            .unwrap()
            .forget(Inode(inode), nlookup);
    }

    fn getattr(&mut self, _req: &Request, inode: u64, reply: fuser::ReplyAttr) {
        let bijou = &self.bijou;
        match bijou.get_meta(self.shared.get_id(inode)) {
            Ok(meta) => {
                reply.attr(&TTL, &self.shared.meta_to_fuse(bijou, meta).0);
            }
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        inode: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<fuser::TimeOrNow>,
        mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: fuser::ReplyAttr,
    ) {
        let bijou = &self.bijou;
        let id = self.shared.get_id(inode);
        if let Some(size) = size {
            if let Err(err) = bijou.set_len(id, size) {
                reply.error(err.to_libc());
                return;
            }
        }

        if atime.is_some() || mtime.is_some() {
            fn convert(time: Option<TimeOrNow>) -> DateTime<Utc> {
                let time = time.map_or(SystemTime::UNIX_EPOCH, |time| match time {
                    TimeOrNow::SpecificTime(time) => time,
                    TimeOrNow::Now => SystemTime::now(),
                });
                time::system_time_to_date_time(&time)
            }
            if let Err(err) = bijou.set_times(id, convert(atime), convert(mtime)) {
                reply.error(err.to_libc());
                return;
            }
        }

        if mode.is_some() || uid.is_some() || gid.is_some() {
            if let Err(err) = bijou.set_perms(id, mode.map(|it| it as u16), uid, gid) {
                reply.error(err.to_libc());
                return;
            }
        }

        match bijou.get_meta(self.shared.get_id(inode)) {
            Ok(meta) => {
                reply.attr(&TTL, &self.shared.meta_to_fuse(bijou, meta).0);
            }
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn mknod(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: fuser::ReplyEntry,
    ) {
        let _span = begin_span("mknod");
        let kind = match mode & libc::S_IFMT {
            libc::S_IFREG => FileKind::File,
            libc::S_IFDIR => FileKind::Directory,
            libc::S_IFLNK => FileKind::Symlink,
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };
        self.make_node(req, mode, parent, name, kind, None, reply);
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        self.make_node(req, mode, parent, name, FileKind::Directory, None, reply);
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let bijou = &self.bijou;
        let name = name.to_string_lossy();
        match bijou.unlink(self.shared.get_id(parent), &name) {
            Ok(removed) => {
                if let Some(removed) = removed {
                    self.shared.table.write().unwrap().unlink(removed);
                }
                reply.ok()
            }
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        self.unlink(req, parent, name, reply);
    }

    fn open(&mut self, _req: &Request, inode: u64, flags: i32, reply: fuser::ReplyOpen) {
        self.open_inner(
            self.shared.get_id(inode),
            flags,
            reply,
            |reply, fh, flags| reply.opened(fh, flags),
            |reply, err| reply.error(err),
        );
    }

    fn read(
        &mut self,
        _req: &Request,
        _inode: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        let file = ptr_to_file(fh);
        self.thread_pool.execute(move || {
            READ_BUFFER.with(|it| {
                let mut buffer = it.borrow_mut();
                buffer.resize(size as usize, 0);
                match file.read().unwrap().read(&mut buffer, offset as _) {
                    Ok(read) => {
                        reply.data(&buffer[..read as usize]);
                    }
                    Err(err) => reply.error(err.to_libc()),
                }
            });
        });
    }

    fn write(
        &mut self,
        _req: &Request,
        _inode: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyWrite,
    ) {
        let file = ptr_to_file(fh);
        // TODO parallelize
        match file.write().unwrap().write(data, offset as _) {
            Ok(written) => reply.written(written as _),
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _inode: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        drop_as::<RwLock<LowLevelFile>>(fh);
        reply.ok();
    }

    fn opendir(&mut self, _req: &Request, inode: u64, _flags: i32, reply: fuser::ReplyOpen) {
        let bijou = &self.bijou;
        match bijou.read_dir(self.shared.get_id(inode)) {
            Ok(iter) => reply.opened(
                Box::leak(Box::new(DirHandle {
                    iter,
                    buf: Vec::new(),
                    filled: false,
                })) as *mut _ as u64,
                FOPEN_KEEP_CACHE | (1 << 3),
            ),
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        _inode: u64,
        fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectory,
    ) {
        let _span = begin_span("readdir");
        let handle = unsafe { &mut *(fh as *mut DirHandle) };
        handle.fill(
            None,
            offset,
            reply,
            |reply, offset, kind, name, _attr| reply.add(Inode::DUMMY.0, offset, kind, name),
            fuser::ReplyDirectory::ok,
            fuser::ReplyDirectory::error,
        );
    }

    fn readdirplus(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        reply: fuser::ReplyDirectoryPlus,
    ) {
        let handle = unsafe { &mut *(fh as *mut DirHandle) };
        handle.fill(
            Some(self),
            offset,
            reply,
            |reply, offset, _kind, name, attr| {
                let (attr, gen) = attr.unwrap();
                reply.add(attr.ino, offset, name, &TTL, &attr, gen)
            },
            fuser::ReplyDirectoryPlus::ok,
            fuser::ReplyDirectoryPlus::error,
        );
    }

    fn releasedir(
        &mut self,
        _req: &Request,
        _inode: u64,
        fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        drop_as::<DirHandle>(fh);
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: fuser::ReplyStatfs) {
        let mut stats = unsafe {
            let mut buf = std::mem::MaybeUninit::uninit();
            let path = CString::new(self.bijou.path().as_os_str().as_bytes()).unwrap();
            if libc::statvfs(path.as_ptr() as _, buf.as_mut_ptr()) < 0 {
                reply.error(*libc::__errno_location());
                return;
            }
            buf.assume_init()
        };
        stats.f_namemax = 1 << 24; // arbitrary value
        reply.statfs(
            stats.f_blocks,
            stats.f_bfree,
            stats.f_bavail,
            stats.f_files,
            stats.f_ffree,
            stats.f_bsize as _,
            stats.f_namemax as _,
            stats.f_frsize as _,
        );
    }

    fn access(&mut self, _req: &Request, inode: u64, _mask: i32, reply: fuser::ReplyEmpty) {
        let bijou = &self.bijou;
        match bijou.get_meta(self.shared.get_id(inode)) {
            Ok(_) => reply.ok(),
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        _flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        let name = name.to_string_lossy().into_owned();
        let new_name = new_name.to_string_lossy().into_owned();
        let bijou = self.clone_bijou();
        let shared = Arc::clone(&self.shared);
        self.thread_pool.execute(move || {
            match bijou.rename(
                shared.get_id(parent),
                &name,
                shared.get_id(new_parent),
                &new_name,
            ) {
                Ok(removed) => {
                    if let Some(removed) = removed {
                        shared.table.write().unwrap().unlink(removed);
                    }
                    reply.ok()
                }
                Err(err) => reply.error(err.to_libc()),
            }
        });
    }

    fn symlink(
        &mut self,
        req: &Request,
        parent: u64,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: fuser::ReplyEntry,
    ) {
        self.make_node(
            req,
            0o775,
            parent,
            link_name,
            FileKind::Symlink,
            Some(target.display().to_string()),
            reply,
        );
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: fuser::ReplyCreate,
    ) {
        let bijou = &self.bijou;
        let result = {
            let id = self.shared.get_id(parent);
            bijou.make_node(
                id,
                &name.to_string_lossy(),
                FileKind::File,
                None,
                Some(to_perms(req, mode)),
            )
        };
        match result {
            Ok(meta) => {
                let id = meta.id;
                self.shared.table.write().unwrap().add(id);
                let (attr, gen) = self.shared.meta_to_fuse(bijou, meta);
                self.open_inner(
                    id,
                    flags,
                    reply,
                    |reply, fh, flags| reply.created(&TTL, &attr, gen, fh, flags),
                    |reply, err| reply.error(err),
                );
            }
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn setxattr(
        &mut self,
        _req: &Request,
        inode: u64,
        name: &OsStr,
        value: &[u8],
        _flags: i32,
        position: u32,
        reply: fuser::ReplyEmpty,
    ) {
        let _span = begin_span("setxattr");
        if position != 0 {
            reply.error(libc::EINVAL);
            return;
        }

        let bijou = &self.bijou;
        match bijou.set_xattr(self.shared.get_id(inode), &name.to_string_lossy(), value) {
            Ok(_) => reply.ok(),
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn getxattr(
        &mut self,
        _req: &Request,
        inode: u64,
        name: &OsStr,
        size: u32,
        reply: fuser::ReplyXattr,
    ) {
        let _span = begin_span("getxattr");
        let bijou = &self.bijou;
        bijou.get_xattr(
            self.shared.get_id(inode),
            &name.to_string_lossy(),
            |bytes| match bytes {
                Ok(bytes) => {
                    if let Some(bytes) = bytes {
                        if size == 0 {
                            reply.size(bytes.len() as _);
                            return;
                        }
                        if bytes.len() > size as usize {
                            reply.error(libc::ERANGE);
                            return;
                        }
                        reply.data(&bytes);
                    } else {
                        reply.error(libc::ENODATA);
                    }
                }
                Err(err) => reply.error(err.to_libc()),
            },
        );
    }

    fn removexattr(&mut self, _req: &Request, inode: u64, name: &OsStr, reply: fuser::ReplyEmpty) {
        let _span = begin_span("removexattr");
        let bijou = &self.bijou;
        match bijou.remove_xattr(self.shared.get_id(inode), &name.to_string_lossy()) {
            Ok(_) => reply.ok(),
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn listxattr(&mut self, _req: &Request, inode: u64, size: u32, reply: fuser::ReplyXattr) {
        let _span = begin_span("listxattr");
        let bijou = &self.bijou;
        match bijou.xattrs(self.shared.get_id(inode)) {
            Ok(attrs) => {
                let len = attrs.len() as u32;
                if size == 0 {
                    reply.size(len);
                    return;
                }
                if len > size {
                    reply.error(libc::ERANGE);
                    return;
                }
                let mut buf = Vec::with_capacity(attrs.iter().map(|attr| attr.len() + 1).sum());
                for attr in attrs {
                    buf.extend_from_slice(attr.as_bytes());
                    buf.push(0);
                }
                reply.data(&buf);
            }
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn readlink(&mut self, _req: &Request, inode: u64, reply: fuser::ReplyData) {
        let bijou = &self.bijou;
        match bijou.read_link(self.shared.get_id(inode)) {
            Ok(target) => reply.data(target.as_str().as_bytes()),
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn link(
        &mut self,
        _req: &Request,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let bijou = &self.bijou;
        match bijou.link(
            self.shared.get_id(ino),
            self.shared.get_id(newparent),
            &newname.to_string_lossy(),
        ) {
            Ok(meta) => {
                self.shared
                    .table
                    .write()
                    .unwrap()
                    .get_or_insert(meta.id, true);
                let (attr, gen) = self.shared.meta_to_fuse(bijou, meta);
                reply.entry(&TTL, &attr, gen);
            }
            Err(err) => reply.error(err.to_libc()),
        }
    }

    fn destroy(&mut self) {
        info!("destroy() called");
    }
}

struct DirBufItem {
    name: String,
    item: DirItem,
    attr_and_gen: Option<(FileAttr, u64)>,
}
struct DirHandle<'db> {
    iter: DirIterator<'db>,
    buf: Vec<DirBufItem>,
    filled: bool,
}
impl DirHandle<'_> {
    pub fn fill<T>(
        &mut self,
        fuse: Option<&BijouFuse>,
        offset: i64,
        mut reply: T,
        cb: impl Fn(&mut T, i64, fuser::FileType, &str, Option<(fuser::FileAttr, u64)>) -> bool,
        ok: impl FnOnce(T),
        error: impl FnOnce(T, libc::c_int),
    ) {
        assert!(offset >= 0);
        let mut offset = offset as usize;
        if offset == 0 {
            self.iter.reset();
            self.buf.clear();
            self.filled = false;
        }
        loop {
            let DirBufItem {
                name,
                item,
                attr_and_gen,
            } = match self.buf.get(offset) {
                Some(entry) => entry,
                None => {
                    if self.filled {
                        break;
                    }
                    let Some(item) = self.iter.next() else {
                        self.filled = true;
                        break;
                    };
                    let (name, item) = match item {
                        Ok(item) => item,
                        Err(err) => {
                            error(reply, err.to_libc());
                            return;
                        }
                    };

                    let attr_and_gen = match fuse
                        .as_ref()
                        .map(|fuse| {
                            fuse.bijou
                                .get_meta(item.id)
                                .map(|meta| fuse.shared.meta_to_fuse(&fuse.bijou, meta))
                        })
                        .transpose()
                    {
                        Ok(val) => val,
                        Err(err) => {
                            error(reply, err.to_libc());
                            return;
                        }
                    };
                    self.buf.push(DirBufItem {
                        name,
                        item,
                        attr_and_gen,
                    });

                    self.buf.last().unwrap()
                }
            };

            offset += 1;
            if name != "." && name != ".." {
                if let Some(fuse) = fuse.as_ref() {
                    // Increase lookup
                    fuse.shared
                        .table
                        .write()
                        .unwrap()
                        .get_or_insert(item.id, true);
                }
            }
            if cb(
                &mut reply,
                offset as _,
                kind_to_fuse(item.kind),
                name,
                *attr_and_gen,
            ) {
                ok(reply);
                return;
            }
        }

        ok(reply);
    }
}
