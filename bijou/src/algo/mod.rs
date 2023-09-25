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

mod ring_aead;
mod xchacha20poly1305_ietf;
mod xsalsa20;

pub use ring_aead::*;
pub use xchacha20poly1305_ietf::*;
pub use xsalsa20::*;

use crate::{Result, SecretBytes};

/// An algorithm that encrypts and decrypts blocks of data.
///
/// The plaintext is divided into multiple data blocks, and each data
/// block is accompanied by some metadata during encryption or decryption,
/// and then stored in the underlying storage.
///
/// A block has the following structure:
/// ```
/// [header][content][tag]
/// ```
///
/// When implementing this trait, you should make sure that a null buffers (
/// buffer with all bytes set to 0) always encrypt / decrypt to null buffers.
/// This corresponds to the file gaps in the underlying storage.
pub trait Algorithm {
    fn header_size(&self) -> u64;
    fn content_size(&self) -> u64;
    fn tag_size(&self) -> u64;

    fn key_size(&self) -> usize;

    /// Obtain a key for this algorithm.
    fn key(&self, key: SecretBytes) -> Result<Box<dyn AlgoKey + Send + Sync>>;

    #[inline]
    fn block_size(&self) -> u64 {
        self.header_size() + self.content_size() + self.tag_size()
    }

    #[inline]
    fn metadata_size(&self) -> u64 {
        self.header_size() + self.tag_size()
    }

    /// Calculates the size of the plaintext from the size of the ciphertext.
    /// This is the inverse function of `Algorithm::ciphertext_size`.
    fn plaintext_size(&self, ciphertext_size: u64) -> u64 {
        let metadata_size = self.metadata_size();
        let content_size = self.content_size();

        let blocks = ciphertext_size / (content_size + metadata_size);
        let rem = ciphertext_size % (content_size + metadata_size);
        blocks * content_size + rem.saturating_sub(metadata_size)
    }

    /// Calculates the size of the ciphertext from the size of the plaintext.
    /// This is the inverse function of `Algorithm::plaintext_size`.
    fn ciphertext_size(&self, plaintext_size: u64) -> u64 {
        let metadata_size = self.metadata_size();
        let block_size = self.content_size();

        let blocks = plaintext_size / block_size;
        let rem = plaintext_size % block_size;
        blocks * (block_size + metadata_size) + if rem == 0 { 0 } else { metadata_size + rem }
    }
}

/// A key for an algorithm. Can be used to encrypt and
/// decrypt data blocks.
///
/// Implementations should take care that the key is
/// properly erased from memory when dropped.
pub trait AlgoKey {
    /// Encrypts the buffer inplace.
    ///
    /// The caller should make sure that `buffer.len() >= metadata_size`.
    fn encrypt(&self, block: u64, buffer: &mut [u8]) -> Result<()>;

    /// Decrypts the buffer inplace.
    ///
    /// The caller should make sure that `buffer.len() >= metadata_size`.
    fn decrypt(&self, block: u64, buffer: &mut [u8]) -> Result<()>;
}

/// Checks if the given bytes are all 0.
pub(crate) fn is_nil(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}
