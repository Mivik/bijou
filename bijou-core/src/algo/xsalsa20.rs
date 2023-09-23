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
    crypto::{cast_key, split_nonce_tag},
    Result, SecretBytes,
};
use sodiumoxide::crypto::stream;

/// XSalsa20 stream cipher.
///
/// Backed by libsodium.
pub struct XSalsa20 {
    block_size: u64,
}

impl XSalsa20 {
    pub fn new(block_size: u64) -> Self {
        Self { block_size }
    }
}

impl Algorithm for XSalsa20 {
    fn header_size(&self) -> u64 {
        stream::NONCEBYTES as u64
    }

    fn content_size(&self) -> u64 {
        self.block_size
    }

    fn tag_size(&self) -> u64 {
        0
    }

    fn key_size(&self) -> usize {
        stream::KEYBYTES
    }

    fn key(&self, key: SecretBytes) -> Result<Box<dyn AlgoKey + Send + Sync>> {
        Ok(Box::new(Key(key)))
    }
}

fn split(data: &mut [u8]) -> (&mut stream::Nonce, &mut [u8]) {
    // Safety
    //
    // libsodium uses char* under the hood, which
    // does not require any alignment guarantees.
    let (nonce, data, _) = unsafe { split_nonce_tag::<stream::Nonce, ()>(data) };
    (nonce, data)
}

struct Key(SecretBytes);
impl AlgoKey for Key {
    fn encrypt(&self, block: u64, buffer: &mut [u8]) -> Result<()> {
        let (nonce, data) = split(buffer);
        *nonce = stream::gen_nonce();
        while is_nil(&nonce.0) {
            *nonce = stream::gen_nonce();
        }

        stream::stream_xor_ic_inplace(data, nonce, block, cast_key(&self.0));

        Ok(())
    }

    fn decrypt(&self, block: u64, buffer: &mut [u8]) -> Result<()> {
        let (nonce, data) = split(buffer);
        if is_nil(&nonce.0) {
            data.fill(0);
        } else {
            stream::stream_xor_ic_inplace(data, nonce, block, cast_key(&self.0));
        }

        Ok(())
    }
}
