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
use libsodium_sys::*;

pub struct Algorithm {
    pub nonce_len: usize,
    pub key_len: usize,

    xor_inplace_ic: unsafe extern "C" fn(
        c: *mut libc::c_uchar,
        m: *const libc::c_uchar,
        mlen: libc::c_ulonglong,
        n: *const libc::c_uchar,
        ic: u64,
        k: *const libc::c_uchar,
    ) -> libc::c_int,
}

impl Algorithm {
    fn check(&self, nonce: &[u8], key: &[u8]) {
        assert_eq!(self.nonce_len, nonce.len());
        assert_eq!(self.key_len, key.len());
    }

    pub fn xor_inplace_ic(&self, data: &mut [u8], nonce: &[u8], ic: u64, key: &[u8]) -> Result<()> {
        self.check(nonce, key);
        unsafe {
            if (self.xor_inplace_ic)(
                data.as_mut_ptr() as _,
                data.as_ptr() as _,
                data.len() as _,
                nonce.as_ptr() as _,
                ic,
                key.as_ptr() as _,
            ) == 0
            {
                Ok(())
            } else {
                Err(anyhow!(@CryptoError "failed to xor inplace"))
            }
        }
    }

    #[inline]
    pub fn xor_inplace(&self, data: &mut [u8], nonce: &[u8], key: &[u8]) -> Result<()> {
        self.xor_inplace_ic(data, nonce, 0, key)
    }
}

pub const XSALSA20: Algorithm = Algorithm {
    nonce_len: crypto_stream_xsalsa20_NONCEBYTES as _,
    key_len: crypto_stream_xsalsa20_KEYBYTES as _,

    xor_inplace_ic: crypto_stream_xsalsa20_xor_ic,
};

pub const XCHACHA20: Algorithm = Algorithm {
    nonce_len: crypto_stream_xchacha20_NONCEBYTES as _,
    key_len: crypto_stream_xchacha20_KEYBYTES as _,

    xor_inplace_ic: crypto_stream_xchacha20_xor_ic,
};
