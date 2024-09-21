use pqc_kyber::*;
use rand::rngs::OsRng;
use aes_gcm::{Aes256Gcm, Key, Nonce}; // AES-GCM for symmetric encryption
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Error as AesGcmError;
use std::fmt;
use std::str;
use clap::Parser;
use zeroize::Zeroize; // Import the Zeroize trait

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value_t = 3)]
    depth: usize,
}

#[derive(Debug)]
enum CustomError {
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

struct Ciphertext {
    pub data: Vec<u8>,
    #[allow(dead_code)]
    pub nonce: Vec<u8>
}

// Triple Kyber key encapsulation
fn triple_encapsulation(
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
fn triple_decapsulation(
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

// Heisenberg Uncertainty Principle Cipher
fn heisenberg_cipher(data: &[u8]) -> Vec<u8> {
    // Simple example: Shift each byte by its index mod 256
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte.wrapping_add(i as u8))
        .collect()
}

// Heisenberg Uncertainty Principle Decipher
fn heisenberg_decipher(data: &[u8]) -> Vec<u8> {
    // Simple example: Reverse the shift applied in heisenberg_cipher
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte.wrapping_sub(i as u8))
        .collect()
}

// Update the fractal_encrypt function to include Heisenberg cipher
fn fractal_encrypt_with_heisenberg(shared_key: &[u8], data: &[u8], depth: usize) -> Result<Vec<u8>, AesGcmError> {
    // Apply Heisenberg cipher first
    let heisenberg_data = heisenberg_cipher(data);
    fractal_encrypt(shared_key, &heisenberg_data, depth)
}

// Update the fractal_decrypt function to include Heisenberg cipher
fn fractal_decrypt_with_heisenberg(shared_key: &[u8], data: &[u8], depth: usize) -> Result<Vec<u8>, AesGcmError> {
    let decrypted_data = fractal_decrypt(shared_key, data, depth)?;
    // Apply Heisenberg decryption (inverse operation)
    Ok(heisenberg_decipher(&decrypted_data))
}

// Fractal Encryption Layer (recursive)
fn fractal_encrypt(shared_key: &[u8], data: &[u8], depth: usize) -> Result<Vec<u8>, AesGcmError> {
    if depth == 0 {
        return Ok(data.to_vec());
    }
    
    let key = Key::<Aes256Gcm>::try_from(&shared_key[0..32]).map_err(|_| aes_gcm::Error)?; // AES-256 key
    let cipher = Aes256Gcm::new(&key);
    
    let nonce = Nonce::try_from(&shared_key[32..(32 + NONCE_LEN)])
        .map_err(|_| aes_gcm::Error)?; // Part of the key used as nonce

    // Encrypt the data
    let encrypted_data = cipher.encrypt(&nonce, data)?;

    // Recursively encrypt
    fractal_encrypt(shared_key, &encrypted_data, depth - 1)
}

// Fractal Decryption Layer (reverse recursion)
fn fractal_decrypt(shared_key: &[u8], data: &[u8], depth: usize) -> Result<Vec<u8>, AesGcmError> {
    if depth == 0 {
        return Ok(data.to_vec());
    }
    
    let key = Key::<Aes256Gcm>::try_from(&shared_key[0..32]).map_err(|_| aes_gcm::Error)?; // AES-256 key
    let cipher = Aes256Gcm::new(&key);
    
    let nonce = Nonce::try_from(&shared_key[32..(32 + NONCE_LEN)])
        .map_err(|_| aes_gcm::Error)?; // Part of the key used as nonce

    // Decrypt the data
    let decrypted_data = cipher.decrypt(&nonce, data)?;

    // Recursively decrypt
    fractal_decrypt(shared_key, &decrypted_data, depth - 1)
}

fn laqf(depth: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // Generate Kyber key pairs for two entities (can be more in a real-world application)
    let _entity_1_keys = match keypair(&mut rng) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("Failed to generate keypair for entity 1: {}", e);
            return Err(Box::new(CustomError::Other(e.to_string())));
        }
    };

    let entity_2_keys = match keypair(&mut rng) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("Failed to generate keypair for entity 2: {}", e);
            return Err(Box::new(CustomError::Other(e.to_string())));
        }
    };

    // Entity 1 performs triple encapsulation using Entity 2's public key
    let (ciphertexts, mut shared_secret_1) = match triple_encapsulation(&entity_2_keys.public, &mut rng) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Failed to perform triple encapsulation: {}", e);
            return Err(Box::new(CustomError::Other(e.to_string())));
        }
    };

    // Entity 2 decapsulates using its secret key
    let mut shared_secret_2 = match triple_decapsulation(&entity_2_keys.secret, &ciphertexts) {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("Failed to perform triple decapsulation: {}", e);
            return Err(Box::new(CustomError::Other(e.to_string())));
        }
    };

    // Check that both entities have the same shared key
    if shared_secret_1 != shared_secret_2 {
        eprintln!("Shared secrets do not match");
        return Err(Box::new(CustomError::Other("Shared secrets do not match".to_string())));
    }

    // Example data to be encrypted (can be any payload)
    let data = "Top-secret NASA mission data.";

    // Entity 1 encrypts the data using fractal encryption
    let encrypted_data = match fractal_encrypt_with_heisenberg(&shared_secret_1, data.as_bytes(), depth) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to encrypt data: {}", e);
            return Err(Box::new(CustomError::from(e)));
        }
    };

    // Entity 2 decrypts the data using fractal decryption with Heisenberg cipher
    let decrypted_data = match fractal_decrypt_with_heisenberg(&shared_secret_2, &encrypted_data, depth) {
        Ok(data) => String::from_utf8(data)?,
        Err(e) => {
            eprintln!("Failed to decrypt data: {}", e);
            return Err(Box::new(CustomError::from(e)));
        }
    };

    // Zeroize shared secrets after usage
    shared_secret_1.zeroize();
    shared_secret_2.zeroize();

    // Ensure the decrypted data matches the original
    if data != decrypted_data {
        eprintln!("Decrypted data does not match the original");
        return Err(Box::new(CustomError::Other("Decrypted data does not match the original".to_string())));
    }

    // ORIGINAL
    println!("Original data: {:?}", data);

    // ENCRYPTED
    println!("Encrypted data: {:?}", encrypted_data);

    // DECRYPTED
    println!("Decrypted data: {:?}", decrypted_data);

    println!("LAQ-Fort encryption and decryption with fractal layer successful!");
    Ok(())
}

// General-purpose LAQ-Fort encryption and decryption with fractal layer
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    laqf(args.depth)
}
