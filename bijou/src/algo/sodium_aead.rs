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
use crate::{
    crypto::split_nonce_tag,
    sodium::{aead, utils::rand_bytes},
    Result, SecretBytes,
};

/// General wrapper for libsodium AEAD algorithms.
pub struct SodiumAead {
    algo: &'static aead::Algorithm,
    block_size: u64,
}

impl SodiumAead {
    pub fn new(algo: &'static aead::Algorithm, block_size: u64) -> Result<Self> {
        Ok(Self { algo, block_size })
    }
}

impl Algorithm for SodiumAead {
    fn header_size(&self) -> u64 {
        self.algo.nonce_len as _
    }

    fn content_size(&self) -> u64 {
        self.block_size
    }

    fn tag_size(&self) -> u64 {
        // TODO this can change in the future
        self.algo.tag_len as _
    }

    fn key_size(&self) -> usize {
        self.algo.key_len as _
    }

    fn key(&self, key: SecretBytes) -> Result<Box<dyn AlgoKey + Send + Sync>> {
        Ok(Box::new(Key {
            algo: self.algo,
            key,
        }))
    }
}

struct Key {
    algo: &'static aead::Algorithm,
    key: SecretBytes,
}
impl AlgoKey for Key {
    fn encrypt(&self, block: u64, buffer: &mut [u8]) -> Result<()> {
        let (nonce, data, tag) = split_nonce_tag(buffer, self.algo.nonce_len, self.algo.tag_len);

        rand_bytes(nonce);
        while is_nil(nonce) {
            rand_bytes(nonce);
        }

        self.algo
            .encrypt_inplace(data, tag, nonce, Some(&block.to_le_bytes()), &self.key)?;

        Ok(())
    }

    fn decrypt(&self, block: u64, buffer: &mut [u8]) -> Result<()> {
        let (nonce, data, tag) = split_nonce_tag(buffer, self.algo.nonce_len, self.algo.tag_len);

        if is_nil(nonce) {
            data.fill(0);
        } else {
            self.algo
                .decrypt_inplace(data, tag, Some(&block.to_le_bytes()), nonce, &self.key)?;
        }

        Ok(())
    }
}
