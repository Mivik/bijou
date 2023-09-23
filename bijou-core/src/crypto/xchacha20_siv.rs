//! Translation of <https://github.com/jedisct1/libsodium-xchacha20-siv>, without nonce.

use super::cast_key;
use crate::Result;
use sodiumoxide::{
    crypto::{generichash, stream::xchacha20},
    utils,
};

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

fn hash_into(d: &mut [u8], message: &[u8], key: &[u8]) -> Result<(), ()> {
    let digest = generichash::hash(message, Some(d.len()), Some(key))?;
    d.copy_from_slice(digest.as_ref());
    Ok(())
}

fn s2v(iv: &mut [u8; ABYTES], m: &[u8], ad: &[u8], ka: &[u8; ABYTES]) -> Result<(), ()> {
    const ZERO: [u8; ABYTES] = [0; ABYTES];

    let mut d = [0; ABYTES];
    hash_into(&mut d, &ZERO, ka)?;

    s2v_dbl256(&mut d);
    hash_into(iv, ad, ka)?;
    s2v_xor(&mut d, iv);

    let mut state = generichash::State::new(Some(ABYTES), Some(ka))?;

    if m.len() >= ABYTES {
        state.update(&m[..m.len() - ABYTES])?;
        s2v_xor(&mut d, &m[m.len() - ABYTES..]);
    } else {
        s2v_dbl256(&mut d);
        s2v_xor(&mut d, m);
        d[m.len()] ^= 0x80;
    }
    state.update(&d)?;
    iv.copy_from_slice(state.finalize()?.as_ref());

    Ok(())
}

fn derive_keys(key: &Key) -> Result<([u8; ABYTES], xchacha20::Key), ()> {
    let mut ka = [0; 32];
    let mut ke = [0; 32];
    let digest = generichash::hash(b"", Some(64), Some(&key.0))?;
    ka.copy_from_slice(&digest.as_ref()[..32]);
    ke.copy_from_slice(&digest.as_ref()[32..]);

    Ok((ka, xchacha20::Key(ke)))
}

pub fn encrypt_detached(c: &mut [u8], ad: &[u8], k: &Key) -> Result<Tag, ()> {
    let (ka, ke) = derive_keys(k)?;

    let mut mac = [0; ABYTES];
    s2v(&mut mac, c, ad, &ka)?;

    xchacha20::stream_xor_inplace(c, cast_key(&mac[..24]), &ke);

    Ok(Tag(mac))
}

pub fn decrypt_inplace(c: &mut [u8], tag: &Tag, ad: &[u8], k: &Key) -> Result<(), ()> {
    let (ka, ke) = derive_keys(k)?;

    xchacha20::stream_xor_inplace(c, cast_key(&tag.0[..24]), &ke);

    let mut mac2 = [0; ABYTES];
    s2v(&mut mac2, c, ad, &ka)?;
    if !utils::memcmp(&tag.0, &mac2) {
        return Err(());
    }

    Ok(())
}
