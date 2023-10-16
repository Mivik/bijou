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
use std::ptr;

pub struct Algorithm {
    pub tag_len: usize,
    pub nonce_len: usize,
    pub key_len: usize,

    encrypt: unsafe extern "C" fn(
        c: *mut libc::c_uchar,
        mac: *mut libc::c_uchar,
        maclen_p: *mut libc::c_ulonglong,
        m: *const libc::c_uchar,
        mlen: libc::c_ulonglong,
        ad: *const libc::c_uchar,
        adlen: libc::c_ulonglong,
        nsec: *const libc::c_uchar,
        npub: *const libc::c_uchar,
        k: *const libc::c_uchar,
    ) -> libc::c_int,

    decrypt: unsafe extern "C" fn(
        m: *mut libc::c_uchar,
        nsec: *mut libc::c_uchar,
        c: *const libc::c_uchar,
        clen: libc::c_ulonglong,
        mac: *const libc::c_uchar,
        ad: *const libc::c_uchar,
        adlen: libc::c_ulonglong,
        npub: *const libc::c_uchar,
        k: *const libc::c_uchar,
    ) -> libc::c_int,
}

macro_rules! impl_encrypt {
    ($self:ident, $output:ident, $tag:ident, $message:ident, $ad: ident, $nonce: ident, $key: ident) => {{
        $self.check($tag, $nonce, $key);
        let (ad, ad_len) = $ad.map_or_else(|| (ptr::null(), 0), |ad| (ad.as_ptr(), ad.len()));
        unsafe {
            if ($self.encrypt)(
                $output.as_mut_ptr() as _,
                $tag.as_mut_ptr() as _,
                (&mut 0u64) as *mut _,
                $message.as_ptr() as _,
                $message.len() as _,
                ad as _,
                ad_len as _,
                ptr::null(),
                $nonce.as_ptr(),
                $key.as_ptr(),
            ) == 0
            {
                Ok(())
            } else {
                Err(anyhow!(@CryptoError "failed to encrypt"))
            }
        }
    }};
}

macro_rules! impl_decrypt {
    ($self:ident, $output:ident, $message:ident, $tag:ident, $ad:ident, $nonce: ident, $key: ident) => {{
        $self.check($tag, $nonce, $key);
        let (ad, ad_len) = $ad.map_or_else(|| (ptr::null(), 0), |ad| (ad.as_ptr(), ad.len()));
        unsafe {
            if ($self.decrypt)(
                $output.as_mut_ptr() as _,
                ptr::null_mut(),
                $message.as_ptr() as _,
                $message.len() as _,
                $tag.as_ptr() as _,
                ad as _,
                ad_len as _,
                $nonce.as_ptr(),
                $key.as_ptr(),
            ) == 0
            {
                Ok(())
            } else {
                Err(anyhow!(@CryptoError "failed to decrypt"))
            }
        }
    }};
}

impl Algorithm {
    fn check(&self, tag: &[u8], nonce: &[u8], key: &[u8]) {
        assert_eq!(self.tag_len, tag.len());
        assert_eq!(self.nonce_len, nonce.len());
        assert_eq!(self.key_len, key.len());
    }

    pub fn encrypt(
        &self,
        output: &mut [u8],
        tag: &mut [u8],
        message: &[u8],
        ad: Option<&[u8]>,
        nonce: &[u8],
        key: &[u8],
    ) -> Result<()> {
        impl_encrypt!(self, output, tag, message, ad, nonce, key)
    }

    pub fn encrypt_inplace(
        &self,
        message: &mut [u8],
        tag: &mut [u8],
        nonce: &[u8],
        ad: Option<&[u8]>,
        key: &[u8],
    ) -> Result<()> {
        impl_encrypt!(self, message, tag, message, ad, nonce, key)
    }

    pub fn decrypt(
        &self,
        output: &mut [u8],
        message: &[u8],
        tag: &[u8],
        ad: Option<&[u8]>,
        nonce: &[u8],
        key: &[u8],
    ) -> Result<()> {
        impl_decrypt!(self, output, message, tag, ad, nonce, key)
    }

    pub fn decrypt_inplace(
        &self,
        message: &mut [u8],
        tag: &[u8],
        ad: Option<&[u8]>,
        nonce: &[u8],
        key: &[u8],
    ) -> Result<()> {
        impl_decrypt!(self, message, message, tag, ad, nonce, key)
    }
}

pub const XCHACHA20_POLY1305_IETF: Algorithm = Algorithm {
    key_len: crypto_aead_xchacha20poly1305_ietf_KEYBYTES as _,
    nonce_len: crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as _,
    tag_len: crypto_aead_xchacha20poly1305_ietf_ABYTES as _,

    encrypt: crypto_aead_xchacha20poly1305_ietf_encrypt_detached,
    decrypt: crypto_aead_xchacha20poly1305_ietf_decrypt_detached,
};
