use crate::fs::FileId;
use dashmap::{mapref::entry::Entry, DashMap};
use std::{
    ops::Deref,
    sync::{Arc, RwLock},
};

/// A concurrent map from `FileId` to `Arc<RwLock<V>>`.
pub struct IdLock<V = ()>(DashMap<FileId, Arc<RwLock<V>>>);
impl<V> Default for IdLock<V> {
    fn default() -> Self {
        Self::new()
    }
}
impl<V> IdLock<V> {
    pub fn new() -> Self {
        Self(DashMap::new())
    }

    /// Get the value associated with the given `id`. Tries
    /// to insert a new value if `id` is not present.
    pub fn get_or_try_insert<E>(
        &self,
        id: FileId,
        f: impl FnOnce() -> Result<V, E>,
    ) -> Result<Arc<RwLock<V>>, E> {
        Ok(match self.0.entry(id) {
            Entry::Occupied(entry) => Arc::clone(entry.get()),
            Entry::Vacant(entry) => {
                let value = Arc::new(RwLock::new(f()?));
                entry.insert(Arc::clone(&value));
                value
            }
        })
    }

    /// Inserts a new value for the given `id`, overwriting
    /// the existing one.
    pub fn insert(&self, id: FileId, value: V) {
        match self.0.entry(id) {
            Entry::Occupied(entry) => {
                *entry.get().write().unwrap() = value;
            }
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(RwLock::new(value)));
            }
        }
    }
}

impl<V: Default> IdLock<V> {
    /// Get the value associated with the given `id`. Inserts
    /// default value if `id` is not present.
    pub fn get(&self, id: FileId) -> Arc<RwLock<V>> {
        Arc::clone(self.0.entry(id).or_default().deref())
    }

    /// Get the value associated with the given `id`.
    /// 
    /// Returns `None` if `id` is not present.
    pub fn get_opt(&self, id: FileId) -> Option<Arc<RwLock<V>>> {
        self.0.get(&id).map(|it| Arc::clone(&it))
    }
}
