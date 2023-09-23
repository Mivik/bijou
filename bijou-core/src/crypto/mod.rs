pub mod xchacha20_siv;

use crate::{anyhow, Error};
use sodiumoxide::utils;
use std::{alloc, mem, ptr, slice};

pub(crate) unsafe fn unsafe_move_to_heap_partially<T>(value: &mut T) -> Box<T> {
    let value = value as *mut _ as *mut u8;

    let layout = alloc::Layout::new::<T>();
    let ptr = alloc::alloc(layout);
    ptr::copy_nonoverlapping(value, ptr, layout.size());
    utils::memzero(slice::from_raw_parts_mut(value, layout.size()));

    Box::from_raw(ptr as *mut T)
}

/// Safely moves a variable to heap, zeroing out the original variable.
#[macro_export]
#[doc(hidden)]
macro_rules! move_to_heap {
    ($t:ident) => {{
        // This is simply rebinding and will not cause a move (memcpy).
        let mut src = $t;
        let result = unsafe { $crate::crypto::unsafe_move_to_heap_partially(&mut src) };
        #[allow(clippy::forget_non_drop)]
        std::mem::forget(src);
        result
    }};
}

pub(crate) fn cast_key<K>(key: &[u8]) -> &K {
    assert_eq!(key.len(), std::mem::size_of::<K>());
    unsafe { &*(key.as_ptr() as *const K) }
}

/// This is unsafe because it does not guarantee that
/// the results are properly aligned.
pub(crate) unsafe fn split_nonce_tag<N, T>(data: &mut [u8]) -> (&mut N, &mut [u8], &mut T) {
    let (nonce, rest) = data.split_at_mut(mem::size_of::<N>());
    let (data, tag) = rest.split_at_mut(rest.len() - mem::size_of::<T>());
    (
        &mut *(nonce.as_mut_ptr() as *mut N),
        data,
        &mut *(tag.as_mut_ptr() as *mut T),
    )
}

pub(crate) fn crypto_error<T>(_: T) -> Error {
    anyhow!(@CryptoError "crypto error")
}
