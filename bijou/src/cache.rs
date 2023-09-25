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
    db::{consts, Database, DatabaseKey},
    fs::FileId,
    id_lock::IdLock,
    Context, ErrorKind, Result,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Condvar, Mutex, RwLock, RwLockWriteGuard},
    time::Duration,
};
use tracing::error;

#[derive(Default)]
struct State<T> {
    updated: HashMap<FileId, T>,
    immediate: bool,
    stopped: bool,
}

/// An in-memory cache for per-file metadata stored in database.
/// A derivation is used to separate different types of metadata.
///
/// When creating a [`CachedStorageKey`] using [`key`], if the metadata
/// exists in the cache, it will be returned immediately. Otherwise,
/// the metadata will be automatically fetched from the database.
///
/// Updates to the metadata are automatically batched and persisted.
/// See [`CachedStorageKey`] for more details.
///
/// See also [`CachedStorageKey`].
///
/// [`key`]: CachedStorage::key
// TODO gc
pub struct CachedStorage<T> {
    db: Arc<Database>,
    lock: IdLock<T>,
    shared: Arc<(Mutex<State<T>>, Condvar)>,
    derive: &'static [u8],
}
impl<T> CachedStorage<T>
where
    T: Serialize + DeserializeOwned + Clone + Default + Send + std::fmt::Debug + 'static,
{
    const BATCH_DELAY: Duration = Duration::from_millis(100);

    pub fn new(db: Arc<Database>, derive: &'static [u8]) -> Self {
        let shared = Arc::new((Mutex::default(), Condvar::new()));
        std::thread::spawn({
            let db = Arc::clone(&db);
            let shared = Arc::clone(&shared);
            move || loop {
                let (lock, cvar) = &*shared;
                let guard = lock.lock().unwrap();
                let mut guard = cvar
                    .wait_while(guard, |guard: &mut State<T>| {
                        !guard.stopped && guard.updated.is_empty()
                    })
                    .unwrap();
                if guard.stopped {
                    break;
                }
                if !guard.immediate {
                    drop(guard);
                    std::thread::sleep(Self::BATCH_DELAY);
                    guard = lock.lock().unwrap();
                } else {
                    guard.immediate = false;
                }
                for (id, value) in guard.updated.drain() {
                    if let Err(err) = db
                        .key(consts::FILE_ROOT)
                        .derive(id)
                        .derive(derive)
                        .typed()
                        .put(&value)
                    {
                        error!("failed to persist object: {}", err);
                    }
                }
            }
        });
        Self {
            db,
            lock: IdLock::new(),
            shared,
            derive,
        }
    }

    fn db_key(&self, id: FileId) -> DatabaseKey<T> {
        self.db
            .key(consts::FILE_ROOT)
            .derive(id)
            .derive(self.derive)
            .typed()
    }

    fn fetch(&self, id: FileId) -> Result<T> {
        self.db_key(id).get()?.kind(ErrorKind::NotFound)
    }

    pub fn store(&self, id: FileId, meta: T) {
        self.lock.insert(id, meta.clone());
        let mut guard = self.shared.0.lock().unwrap();
        guard.updated.insert(id, meta);
        guard.immediate = true;
        self.shared.1.notify_one();
    }

    pub fn touch(&self, id: FileId) {
        self.store(id, T::default());
    }

    pub fn stat(&self, id: FileId) -> Result<T> {
        self.lock
            .get_opt(id)
            .map_or_else(|| self.fetch(id), |lock| Ok(lock.read().unwrap().clone()))
    }

    pub fn exists(&self, id: FileId) -> Result<bool> {
        self.db_key(id).exists()
    }

    pub fn delete(&self, id: FileId) -> Result<()> {
        self.db_key(id).delete()
    }

    /// Hello
    pub fn key(&self, id: FileId) -> Result<CachedStorageKey<T>> {
        Ok(CachedStorageKey {
            id,
            lock: self.lock.get_or_try_insert(id, || self.fetch(id))?,
            shared: Arc::clone(&self.shared),
        })
    }
}

/// A key for a [`CachedStorage`]. Access and modifications
/// are controlled internally by a [`RwLock`].
///
/// Changes are submitted by [`update`].
///
/// [`update`]: CachedStorageKey::update
pub struct CachedStorageKey<T> {
    id: FileId,
    lock: Arc<RwLock<T>>,
    shared: Arc<(Mutex<State<T>>, Condvar)>,
}

impl<T> CachedStorageKey<T>
where
    T: Clone + Send + 'static,
{
    /// Returns a write guard for the metadata.
    pub fn write(&self) -> RwLockWriteGuard<T> {
        self.lock.write().unwrap()
    }

    /// Updates the metadata. Changes are batched instead
    /// of immediately persisted.
    pub fn update(&self, guard: RwLockWriteGuard<T>) {
        self.shared
            .0
            .lock()
            .unwrap()
            .updated
            .insert(self.id, guard.clone());
        self.shared.1.notify_one();
    }
}
