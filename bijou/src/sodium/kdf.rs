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

use crate::{error::anyhow, Result};
use std::borrow::Cow;

use libsodium_sys::{
    crypto_kdf_blake2b_CONTEXTBYTES, crypto_kdf_blake2b_KEYBYTES,
    crypto_kdf_blake2b_derive_from_key,
};

use crate::SecretBytes;

use super::utils;

type DeriveFromKey = unsafe extern "C" fn(
    subkey: *mut libc::c_uchar,
    subkey_len: usize,
    subkey_id: u64,
    ctx: *const libc::c_char,
    key: *const libc::c_uchar,
) -> libc::c_int;

pub struct Algorithm {
    pub key_len: usize,
    pub context_len: usize,

    derive_from_key: DeriveFromKey,
}

impl Algorithm {
    pub fn prk<'a>(
        &self,
        key: impl Into<SecretBytes>,
        context: impl Into<Cow<'a, [u8]>>,
    ) -> Prk<'a> {
        let context = context.into();
        assert_eq!(self.context_len, context.len());
        Prk {
            key: key.into(),
            context,

            derive_from_key: self.derive_from_key,
        }
    }

    pub fn gen_key(&self) -> SecretBytes {
        utils::gen_secret(self.key_len)
    }
}

pub struct Prk<'a> {
    key: SecretBytes,
    context: Cow<'a, [u8]>,

    derive_from_key: DeriveFromKey,
}

impl Prk<'_> {
    pub fn derive_into(&self, key: &mut [u8], id: u64) -> Result<()> {
        unsafe {
            if (self.derive_from_key)(
                key.as_mut_ptr() as _,
                key.len(),
                id,
                self.context.as_ptr() as _,
                self.key.as_ptr() as _,
            ) == 0
            {
                Ok(())
            } else {
                Err(anyhow!(@CryptoError "failed to derive key"))
            }
        }
    }

    pub fn derive(&self, id: u64, key_len: usize) -> Result<SecretBytes> {
        let mut result = SecretBytes::allocate(key_len);
        self.derive_into(&mut result, id)?;
        Ok(result)
    }
}

pub const BLAKE2B: Algorithm = Algorithm {
    key_len: crypto_kdf_blake2b_KEYBYTES as _,
    context_len: crypto_kdf_blake2b_CONTEXTBYTES as _,

    derive_from_key: crypto_kdf_blake2b_derive_from_key,
};
