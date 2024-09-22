use pqc_kyber::*;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Error as AesGcmError;
use std::fmt;
use std::str;
use zeroize::Zeroize;
use base64::{encode, decode};
use mle1::{decrypt as mle_decrypt, encrypt as mle_encrypt};
use std::collections::HashMap;

#[derive(Debug)]
pub enum CustomError {
    AesGcm(AesGcmError),
    Io(std::io::Error),
    Other(String),
}

impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustomError::AesGcm(e) => write!(f, "AES-GCM error: {}", e),
            CustomError::Io(e) => write!(f, "IO error: {}", e),
            CustomError::Other(e) => write!(f, "Other error: {}", e),
        }
    }
}

impl std::error::Error for CustomError {}

impl From<AesGcmError> for CustomError {
    fn from(err: AesGcmError) -> CustomError {
        CustomError::AesGcm(err)
    }
}

impl From<std::io::Error> for CustomError {
    fn from(err: std::io::Error) -> CustomError {
        CustomError::Io(err)
    }
}

const NONCE_LEN: usize = 12;

pub struct Ciphertext {
    pub data: Vec<u8>,
    #[allow(dead_code)]
    pub nonce: Vec<u8>
}

// Triple Kyber key encapsulation
pub fn triple_encapsulation(
    public_key: &PublicKey,
    rng: &mut (impl rand::Rng + rand::CryptoRng)
) -> Result<(Vec<Ciphertext>, Vec<u8>), KyberError> {
    let mut shared_secrets = vec![];
    let mut ciphertexts = vec![];

    // First encapsulation
    let (ciphertext1, shared_secret1) = encapsulate(public_key, rng)?;
    shared_secrets.push(shared_secret1);
    ciphertexts.push(Ciphertext { data: ciphertext1.to_vec(), nonce: vec![0; NONCE_LEN] });

    // Second encapsulation
    let (ciphertext2, shared_secret2) = encapsulate(public_key, rng)?;
    shared_secrets.push(shared_secret2);
    ciphertexts.push(Ciphertext { data: ciphertext2.to_vec(), nonce: vec![0; NONCE_LEN] });

    // Third encapsulation
    let (ciphertext3, shared_secret3) = encapsulate(public_key, rng)?;
    shared_secrets.push(shared_secret3);
    ciphertexts.push(Ciphertext { data: ciphertext3.to_vec(), nonce: vec![0; NONCE_LEN] });

    // Combine the shared secrets into one final key
    let final_shared_secret = shared_secrets.concat();

    // Zeroize shared_secrets after use
    shared_secrets.zeroize();
    
    Ok((ciphertexts, final_shared_secret))
}

// Triple Kyber key decapsulation
pub fn triple_decapsulation(
    secret_key: &SecretKey,
    ciphertexts: &Vec<Ciphertext>
) -> Result<Vec<u8>, KyberError> {
    let mut shared_secrets = vec![];

    // Decapsulate each ciphertext
    for ciphertext in ciphertexts {
        let shared_secret = decapsulate(&ciphertext.data, secret_key)?;
        shared_secrets.push(shared_secret);
    }

    // Combine the shared secrets into the final decryption key
    let final_shared_secret = shared_secrets.concat();

    // Zeroize shared_secrets after use
    shared_secrets.zeroize();

    Ok(final_shared_secret)
}

// AES Encryption
fn aes_encrypt(shared_key: &[u8], data: &[u8], mult: usize) -> Result<Vec<u8>, AesGcmError> {
    let mut encrypted_data = data.to_vec();
    for _ in 0..mult {
        let key = Key::<Aes256Gcm>::try_from(&shared_key[0..32]).map_err(|_| aes_gcm::Error)?; // AES-256 key
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::try_from(&shared_key[32..(32 + NONCE_LEN)])
            .map_err(|_| aes_gcm::Error)?; // Part of the key used as nonce
        encrypted_data = cipher.encrypt(&nonce, &*encrypted_data)?;
    }
    Ok(encrypted_data)
}

// AES Decryption
fn aes_decrypt(shared_key: &[u8], data: &[u8], mult: usize) -> Result<Vec<u8>, AesGcmError> {
    let mut decrypted_data = data.to_vec();
    for _ in 0..mult {
        let key = Key::<Aes256Gcm>::try_from(&shared_key[0..32]).map_err(|_| aes_gcm::Error)?; // AES-256 key
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::try_from(&shared_key[32..(32 + NONCE_LEN)])
            .map_err(|_| aes_gcm::Error)?; // Part of the key used as nonce
        decrypted_data = cipher.decrypt(&nonce, &*decrypted_data)?;
    }
    Ok(decrypted_data)
}

// Fractal Encryption Layer (recursive)
fn fractal_encrypt(shared_key: &[u8], data: &[u8], depth: usize, mult: usize) -> Result<Vec<u8>, AesGcmError> {
    if (depth == 0) && (mult == 0) {
        return Ok(data.to_vec());
    }

    let mut encrypted_data = data.to_vec();
    for _ in 0..mult {
        let key = Key::<Aes256Gcm>::try_from(&shared_key[0..32]).map_err(|_| aes_gcm::Error)?; // AES-256 key
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::try_from(&shared_key[32..(32 + NONCE_LEN)])
            .map_err(|_| aes_gcm::Error)?; // Part of the key used as nonce
        encrypted_data = cipher.encrypt(&nonce, &*encrypted_data)?;
    }

    if depth == 0 {
        return Ok(encrypted_data);
    }

    fractal_encrypt(shared_key, &encrypted_data, depth - 1, mult)
}

// Fractal Decryption Layer (reverse recursion)
fn fractal_decrypt(shared_key: &[u8], data: &[u8], depth: usize, mult: usize) -> Result<Vec<u8>, AesGcmError> {
    if (depth == 0) && (mult == 0) {
        return Ok(data.to_vec());
    }

    let mut decrypted_data = data.to_vec();
    for _ in 0..mult {
        let key = Key::<Aes256Gcm>::try_from(&shared_key[0..32]).map_err(|_| aes_gcm::Error)?; // AES-256 key
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::try_from(&shared_key[32..(32 + NONCE_LEN)])
            .map_err(|_| aes_gcm::Error)?; // Part of the key used as nonce
        decrypted_data = cipher.decrypt(&nonce, &*decrypted_data)?;
    }

    if depth == 0 {
        return Ok(decrypted_data);
    }

    fractal_decrypt(shared_key, &decrypted_data, depth - 1, mult)
}

// Encryption
pub fn enc(data: &[u8], key: &[u8], depth: usize, mult: usize, mle_key: &str) -> Result<String, AesGcmError> {
    // MLE-1 Encryption
    let data_str = str::from_utf8(&data).map_err(|_e| AesGcmError)?;
    let mle_encrypted_data = mle_encrypt(data_str, mle_key);

    // Fractal with depth
    let fractal_encrypted_data = fractal_encrypt(key, mle_encrypted_data.as_bytes(), depth, 0)?;
    
    // AES with mult
    let aes_data = aes_encrypt(key, &fractal_encrypted_data, mult)?;
    
    // Base64 encode the final encrypted data
    let base64_encoded_data = encode(&aes_data);
    
    // Return the final encrypted data as a Base64 encoded string
    Ok(base64_encoded_data)
}

// Decryption
pub fn dec(data: &str, key: &[u8], depth: usize, mult: usize, mle_key: &str) -> Result<Vec<u8>, AesGcmError> {
    // Base64 decode the input data
    let base64_decoded_data = decode(data).map_err(|_| AesGcmError)?;
    
    // AES with mult
    let aes_data = aes_decrypt(key, &base64_decoded_data, mult)?;
    
    // Fractal with depth
    let decrypted_data = fractal_decrypt(key, &aes_data, depth, 0)?;
    
    // MLE-1 Decryption
    let decrypted_data_str = str::from_utf8(&decrypted_data).map_err(|_e| AesGcmError)?;
    let mle_decrypted_data = mle_decrypt(decrypted_data_str, mle_key, &HashMap::new());
    
    // Return the final decrypted data
    Ok(mle_decrypted_data.into())
}

pub fn laqf_encrypt(depth: usize, mult: usize, data: Option<String>, mle_key: &str, key: &[u8]) -> Result<String, AesGcmError> {
    let data = data.unwrap_or_else(|| "Hello, World!".to_string());
    enc(data.as_bytes(), key, depth, mult, mle_key)
}

pub fn laqf_decrypt(depth: usize, mult: usize, data: Option<String>, mle_key: &str, key: &[u8]) -> Result<Vec<u8>, AesGcmError> {
    let data = data.unwrap_or_else(|| "Hello, World!".to_string());
    dec(&data, key, depth, mult, mle_key)
}

#[allow(dead_code)]
fn main() {
    // rust-analyzer is complaining about the lack of a main function.
    // This is a library crate, so it doesn't need a main function.
    // This function is only here to satisfy rust-analyzer.
}
