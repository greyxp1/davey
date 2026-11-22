use std::{ptr, ptr::NonNull};

use aead::{Error, Result};
use aws_lc_sys::{
  EVP_AEAD_CTX, EVP_AEAD_CTX_free, EVP_AEAD_CTX_new, EVP_AEAD_CTX_open_gather,
  EVP_AEAD_CTX_seal_scatter, EVP_aead_aes_128_gcm,
};
use sha2::digest::InvalidLength;

use super::AES_GCM_127_TRUNCATED_TAG_BYTES;

pub struct AeadCipher(NonNull<EVP_AEAD_CTX>);

// SAFETY: AWS-LC documents AES-128-GCM seal/open as thread-safe for a shared context.
// Only this owner can free the context, after all borrows have ended.
unsafe impl Send for AeadCipher {}
// SAFETY: shared references cannot free or mutate the context.
unsafe impl Sync for AeadCipher {}

impl AeadCipher {
  pub fn new(key: &[u8]) -> std::result::Result<Self, InvalidLength> {
    // SAFETY: AWS-LC copies the key and returns either a new owned context or null.
    let context = unsafe {
      EVP_AEAD_CTX_new(
        EVP_aead_aes_128_gcm(),
        key.as_ptr(),
        key.len(),
        AES_GCM_127_TRUNCATED_TAG_BYTES,
      )
    };
    NonNull::new(context).map(Self).ok_or(InvalidLength)
  }

  pub fn encrypt(
    &mut self,
    input: &[u8],
    buffer: &mut [u8],
    nonce: &[u8],
    aad: &[u8],
  ) -> Result<[u8; AES_GCM_127_TRUNCATED_TAG_BYTES]> {
    let mut tag = [0; AES_GCM_127_TRUNCATED_TAG_BYTES];
    let mut tag_len = 0;
    if input.len() != buffer.len() {
      return Err(Error);
    }
    // SAFETY: input and output have equal lengths and the Rust slices do not alias.
    // The tag has its own buffer, and there is no extra plaintext input.
    let sealed = unsafe {
      EVP_AEAD_CTX_seal_scatter(
        self.0.as_ptr(),
        buffer.as_mut_ptr(),
        tag.as_mut_ptr(),
        &mut tag_len,
        tag.len(),
        nonce.as_ptr(),
        nonce.len(),
        input.as_ptr(),
        input.len(),
        ptr::null(),
        0,
        aad.as_ptr(),
        aad.len(),
      )
    };
    if sealed == 1 && tag_len == tag.len() {
      Ok(tag)
    } else {
      Err(Error)
    }
  }

  pub fn decrypt(
    &mut self,
    input: &[u8],
    buffer: &mut [u8],
    nonce: &[u8],
    aad: &[u8],
    tag: &[u8],
  ) -> Result<()> {
    if input.len() != buffer.len() {
      return Err(Error);
    }
    // SAFETY: AWS-LC writes at most the ciphertext length. The input and output
    // slices do not alias. The detached tag, nonce, and AAD are read-only.
    let opened = unsafe {
      EVP_AEAD_CTX_open_gather(
        self.0.as_ptr(),
        buffer.as_mut_ptr(),
        nonce.as_ptr(),
        nonce.len(),
        input.as_ptr(),
        input.len(),
        tag.as_ptr(),
        tag.len(),
        aad.as_ptr(),
        aad.len(),
      )
    };
    if opened == 1 { Ok(()) } else { Err(Error) }
  }
}

impl Drop for AeadCipher {
  fn drop(&mut self) {
    // SAFETY: the context was allocated by AWS-LC and is owned by this cipher.
    unsafe { EVP_AEAD_CTX_free(self.0.as_ptr()) };
  }
}
