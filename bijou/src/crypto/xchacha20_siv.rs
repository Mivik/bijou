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

//! Translation of <https://github.com/jedisct1/libsodium-xchacha20-siv>, without nonce.

use crate::{Result, sodium::{generic_hash, stream::XCHACHA20, utils}, error::anyhow};

pub const ABYTES: usize = 32;
pub const KEYBYTES: usize = 32;

#[repr(transparent)]
pub struct Key(pub [u8; KEYBYTES]);

#[repr(transparent)]
pub struct Tag(pub [u8; ABYTES]);

fn s2v_dbl256(d: &mut [u8; 32]) {
    let mut t = *d;
    for v in &mut t {
        *v <<= 1;
    }
    for i in (1..32).rev() {
        t[i - 1] |= d[i] >> 7;
    }
    let mask = !(d[0] >> 7).wrapping_sub(1);
    t[30] ^= 0x04 & mask;
    t[31] ^= 0x25 & mask;
    *d = t;
}

fn s2v_xor(d: &mut [u8; 32], h: &[u8]) {
    for (d, m) in d.iter_mut().zip(h.iter()) {
        *d ^= *m;
    }
}

fn s2v(iv: &mut [u8; ABYTES], m: &[u8], ad: &[u8], ka: &[u8; ABYTES]) -> Result<()> {
    const ZERO: [u8; ABYTES] = [0; ABYTES];

    let mut d = [0; ABYTES];
    generic_hash::hash(&mut d, &ZERO, Some(ka))?;

    s2v_dbl256(&mut d);
    generic_hash::hash(iv, ad, Some(ka))?;
    s2v_xor(&mut d, iv);

    let mut state = generic_hash::State::new(ABYTES, Some(ka))?;

    if m.len() >= ABYTES {
        state.update(&m[..m.len() - ABYTES])?;
        s2v_xor(&mut d, &m[m.len() - ABYTES..]);
    } else {
        s2v_dbl256(&mut d);
        s2v_xor(&mut d, m);
        d[m.len()] ^= 0x80;
    }
    state.update(&d)?;
    state.finalize(iv)?;

    Ok(())
}

fn derive_keys(key: &Key) -> Result<([u8; ABYTES], [u8; XCHACHA20.key_len])> {
    let mut ka = [0; 32];
    let mut ke = [0; 32];
    let mut result = [0; 64];
    generic_hash::hash(&mut result, b"", Some(&key.0))?;
    ka.copy_from_slice(&result[..32]);
    ke.copy_from_slice(&result[32..]);

    Ok((ka, ke))
}

pub fn encrypt_detached(c: &mut [u8], ad: &[u8], k: &Key) -> Result<Tag> {
    let (ka, ke) = derive_keys(k)?;

    let mut mac = [0; ABYTES];
    s2v(&mut mac, c, ad, &ka)?;

    XCHACHA20.xor_inplace(c, &mac[..24], &ke)?;

    Ok(Tag(mac))
}

pub fn decrypt_inplace(c: &mut [u8], tag: &Tag, ad: &[u8], k: &Key) -> Result<()> {
    let (ka, ke) = derive_keys(k)?;

    XCHACHA20.xor_inplace(c, &tag.0[..24], &ke)?;

    let mut mac2 = [0; ABYTES];
    s2v(&mut mac2, c, ad, &ka)?;
    if !utils::memcmp(&tag.0, &mac2) {
        return Err(anyhow!(@CryptoError "authentication failed"));
    }

    Ok(())
}
