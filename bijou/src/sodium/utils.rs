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

use crate::{error::anyhow, Result, SecretBytes};
use libsodium_sys::*;

pub fn memzero(bytes: &mut [u8]) {
    unsafe {
        sodium_memzero(bytes.as_mut_ptr() as _, bytes.len());
    }
}

pub fn mlock(bytes: &mut [u8]) -> Result<()> {
    unsafe {
        if sodium_mlock(bytes.as_mut_ptr() as _, bytes.len()) == 0 {
            Ok(())
        } else {
            Err(anyhow!(@CryptoError "failed to lock memory"))
        }
    }
}

pub fn munlock(bytes: &mut [u8]) -> Result<()> {
    unsafe {
        if sodium_munlock(bytes.as_mut_ptr() as _, bytes.len()) == 0 {
            Ok(())
        } else {
            Err(anyhow!(@CryptoError "failed to unlock memory"))
        }
    }
}

pub fn memcmp(x: &[u8], y: &[u8]) -> bool {
    if x.len() != y.len() {
        return false;
    }

    unsafe {
        sodium_memcmp(x.as_ptr() as _, y.as_ptr() as _, x.len() as _) == 0
    }
}

pub fn rand_bytes(buf: &mut [u8]) {
    unsafe {
        randombytes_buf(buf.as_mut_ptr() as _, buf.len() as _);
    }
}

pub fn gen_secret(len: usize) -> SecretBytes {
    let mut result = SecretBytes::allocate(len);
    rand_bytes(&mut result);
    result
}

pub fn gen_rand_bytes<const N: usize>() -> [u8; N] {
    let mut result = [0; N];
    rand_bytes(&mut result);
    result
}
