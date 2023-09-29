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

use super::{is_nil, AlgoKey, Algorithm};
use crate::{crypto::crypto_error, move_to_heap, sodium::utils::rand_bytes, Result, SecretBytes};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, MAX_TAG_LEN, NONCE_LEN};

/// General wrapper for ring AEAD algorithms.
pub struct RingAead {
    algo: &'static ring::aead::Algorithm,
    block_size: u64,
}

impl RingAead {
    pub fn new(algo: &'static ring::aead::Algorithm, block_size: u64) -> Result<Self> {
        Ok(Self { algo, block_size })
    }
}

impl Algorithm for RingAead {
    fn header_size(&self) -> u64 {
        NONCE_LEN as u64
    }

    fn content_size(&self) -> u64 {
        self.block_size
    }

    fn tag_size(&self) -> u64 {
        // TODO this can change in the future
        MAX_TAG_LEN as u64
    }

    fn key_size(&self) -> usize {
        self.algo.key_len()
    }

    fn key(&self, key: SecretBytes) -> Result<Box<dyn AlgoKey + Send + Sync>> {
        let key = LessSafeKey::new(UnboundKey::new(self.algo, &key).unwrap());
        Ok(Box::new(Key(move_to_heap!(key))))
    }
}

fn split(data: &mut [u8]) -> (&mut [u8; NONCE_LEN], &mut [u8]) {
    let (nonce, data) = data.split_at_mut(NONCE_LEN);
    unsafe { (&mut *(nonce.as_mut_ptr() as *mut _), data) }
}

// ring's key is not heap allocated, and have to
// be moved to the heap to disallow implicit copy.
struct Key(Box<LessSafeKey>);
impl AlgoKey for Key {
    fn encrypt(&self, block: u64, buffer: &mut [u8]) -> Result<()> {
        let (nonce, data) = split(buffer);

        rand_bytes(nonce);
        while is_nil(nonce) {
            rand_bytes(nonce);
        }

        let (data, tag_bytes) = data.split_at_mut(data.len() - MAX_TAG_LEN);

        let tag = self
            .0
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(block.to_le_bytes()),
                data,
            )
            .map_err(crypto_error)?;
        tag_bytes.copy_from_slice(tag.as_ref());

        Ok(())
    }

    fn decrypt(&self, block: u64, buffer: &mut [u8]) -> Result<()> {
        let (nonce, data) = split(buffer);
        if is_nil(nonce) {
            data.fill(0);
        } else {
            self.0
                .open_in_place(
                    Nonce::assume_unique_for_key(*nonce),
                    Aad::from(block.to_le_bytes()),
                    data,
                )
                .map_err(crypto_error)?;
        }

        Ok(())
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // ring does not zero out memory automatically
        // so we have to do that on our own.
        *self.0 = LessSafeKey::new(UnboundKey::new(self.0.algorithm(), &[0; 32]).unwrap());
    }
}
