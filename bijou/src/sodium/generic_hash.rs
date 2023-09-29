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
use std::mem;

fn unwrap_key(key: Option<&[u8]>) -> (*const u8, usize) {
    match key {
        Some(key) => (key.as_ptr(), key.len()),
        None => (std::ptr::null(), 0),
    }
}

pub fn hash(output: &mut [u8], data: &[u8], key: Option<&[u8]>) -> Result<()> {
    unsafe {
        let (key, key_len) = unwrap_key(key);
        if crypto_generichash(
            output.as_mut_ptr() as _,
            output.len(),
            data.as_ptr() as _,
            data.len() as _,
            key,
            key_len,
        ) == 0
        {
            Ok(())
        } else {
            Err(anyhow!(@CryptoError "failed to hash"))
        }
    }
}

pub struct State {
    state: crypto_generichash_state,
    out_len: usize,
}
impl State {
    pub fn new(out_len: usize, key: Option<&[u8]>) -> Result<State> {
        let (key, key_len) = unwrap_key(key);

        let mut state = mem::MaybeUninit::uninit();

        let result =
            unsafe { crypto_generichash_init(state.as_mut_ptr(), key as _, key_len, out_len as _) };

        if result == 0 {
            Ok(Self {
                state: unsafe { state.assume_init() },
                out_len,
            })
        } else {
            Err(anyhow!(@CryptoError "failed to initialize hash state"))
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            if crypto_generichash_update(&mut self.state, data.as_ptr(), data.len() as _) == 0 {
                Ok(())
            } else {
                Err(anyhow!(@CryptoError "failed to update hash"))
            }
        }
    }

    pub fn finalize(mut self, output: &mut [u8]) -> Result<()> {
        assert_eq!(self.out_len, output.len());
        unsafe {
            if crypto_generichash_final(
                &mut self.state,
                output.as_mut_ptr() as _,
                self.out_len,
            ) == 0
            {
                Ok(())
            } else {
                Err(anyhow!(@CryptoError "failed to finalize"))
            }
        }
    }
}
