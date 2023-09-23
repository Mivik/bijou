use super::{is_nil, AlgoKey, Algorithm};
use crate::{
    anyhow,
    crypto::{cast_key, split_nonce_tag},
    Result, SecretBytes,
};
use sodiumoxide::crypto::aead;

/// Implementation of XChaCha20-Poly1305-IETF.
///
/// Backed by libsodium.
pub struct XChaCha20Poly1305IETF {
    block_size: u64,
}

impl XChaCha20Poly1305IETF {
    pub fn new(block_size: u64) -> Self {
        Self { block_size }
    }
}

impl Algorithm for XChaCha20Poly1305IETF {
    fn header_size(&self) -> u64 {
        aead::NONCEBYTES as u64
    }

    fn content_size(&self) -> u64 {
        self.block_size
    }

    fn tag_size(&self) -> u64 {
        aead::TAGBYTES as u64
    }

    fn key_size(&self) -> usize {
        aead::KEYBYTES
    }

    fn key(&self, key: SecretBytes) -> Result<Box<dyn AlgoKey + Send + Sync>> {
        Ok(Box::new(Key(key)))
    }
}

fn split(data: &mut [u8]) -> (&mut aead::Nonce, &mut [u8], &mut aead::Tag) {
    // Safety
    //
    // libsodium uses char* under the hood, which
    // does not require any alignment guarantees.
    unsafe { split_nonce_tag(data) }
}

struct Key(SecretBytes);
impl AlgoKey for Key {
    fn encrypt(&self, block: u64, buffer: &mut [u8]) -> Result<()> {
        let (nonce, data, tag) = split(buffer);
        *nonce = aead::gen_nonce();
        while is_nil(&nonce.0) {
            *nonce = aead::gen_nonce();
        }

        *tag = aead::seal_detached(data, Some(&block.to_le_bytes()), nonce, cast_key(&self.0));

        Ok(())
    }

    fn decrypt(&self, block: u64, buffer: &mut [u8]) -> Result<()> {
        let (nonce, data, tag) = split(buffer);
        if is_nil(&nonce.0) {
            assert!(is_nil(&tag.0));
            data.fill(0);
        } else {
            aead::open_detached(
                data,
                Some(&block.to_le_bytes()),
                tag,
                nonce,
                cast_key(&self.0),
            )
            .map_err(|_| anyhow!(@CryptoError "failed to decrypt block"))?;
        }

        Ok(())
    }
}
