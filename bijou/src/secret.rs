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

use sodiumoxide::utils;
use std::ops::{Deref, DerefMut};

/// A wrapper around a byte array that is locked in memory
/// and is automatically zeroed out when dropped.
///
/// Please note that this is not aligned, and thus cannot
/// be used under some circumstances.
pub struct SecretBytes(Box<[u8]>);
impl SecretBytes {
    /// Creates a new [`SecretBytes`] from a byte array.
    pub fn new(mut bytes: Box<[u8]>) -> Self {
        // TODO handle this error
        utils::mlock(&mut bytes).unwrap();
        Self(bytes)
    }

    /// Creates a new [`SecretBytes`] from a byte slice,
    /// zeroing out the original slice.
    pub fn move_from(bytes: &mut [u8]) -> Self {
        let result = bytes.to_vec().into();
        utils::memzero(bytes);
        result
    }

    /// Allocates a new [`SecretBytes`] in heap with the given length.
    pub fn allocate(len: usize) -> Self {
        Self::new(vec![0; len].into_boxed_slice())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for SecretBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        utils::munlock(&mut self.0).unwrap();
    }
}
