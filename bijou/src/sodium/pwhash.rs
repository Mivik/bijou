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

use libsodium_sys::*;
use crate::{Result, error::anyhow};

#[derive(Debug, Clone, Copy)]
pub enum Limit {
    Interactive,
    Moderate,
    Sensitive,
    Custom(usize),
}

impl Limit {
    pub fn eval(&self, limits: [usize; 3]) -> usize {
        match self {
            Self::Interactive => limits[0],
            Self::Moderate => limits[1],
            Self::Sensitive => limits[2],
            Self::Custom(val) => *val,
        }
    }
}

pub struct Algorithm {
    pub salt_len: usize,

    pub ops_limits: [usize; 3],
    pub mem_limits: [usize; 3],

    derive_key: unsafe extern "C" fn(
        out: *mut libc::c_uchar,
        outlen: libc::c_ulonglong,
        passwd: *const libc::c_char,
        passwdlen: libc::c_ulonglong,
        salt: *const libc::c_uchar,
        opslimit: libc::c_ulonglong,
        memlimit: usize,
        alg: libc::c_int,
    ) -> libc::c_int,
}

impl Algorithm {
    fn check(&self, salt: &[u8]) {
        assert_eq!(self.salt_len, salt.len());
    }

    pub fn derive_key(
        &self,
        key: &mut [u8],
        password: &[u8],
        salt: &[u8],
        ops_limit: Limit,
        mem_limit: Limit,
    ) -> Result<()> {
        self.check(salt);
        unsafe {
            if (self.derive_key)(
                key.as_mut_ptr() as _,
                key.len() as _,
                password.as_ptr() as _,
                password.len() as _,
                salt.as_ptr() as _,
                ops_limit.eval(self.ops_limits) as _,
                mem_limit.eval(self.mem_limits) as _,
                crypto_pwhash_ALG_ARGON2ID13 as _,
            ) == 0
            {
                Ok(())
            } else {
                Err(anyhow!(@CryptoError "failed to derive key from password"))
            }
        }
    }
}

pub const ARGON2_ID13: Algorithm = Algorithm {
    salt_len: crypto_pwhash_argon2id_SALTBYTES as _,

    ops_limits: [
        crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE as _,
        crypto_pwhash_argon2id_OPSLIMIT_MODERATE as _,
        crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE as _,
    ],
    mem_limits: [
        crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE as _,
        crypto_pwhash_argon2id_MEMLIMIT_MODERATE as _,
        crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE as _,
    ],

    derive_key: crypto_pwhash_argon2id,
};
