use pqc_kyber::*;
use rand::rngs::OsRng;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Error as AesGcmError;
use std::fmt;
use std::str;
use clap::Parser;
use zeroize::Zeroize;
use base64::{encode, decode};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short, long, default_value_t = 3)]
    depth: usize,

    #[clap(short, long, default_value_t = 8)]
    mult: usize,
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
fn enc(data: &[u8], key: &[u8], depth: usize, mult: usize) -> Result<String, AesGcmError> {
    // Fractal with depth
    let fractal_encrypted_data = fractal_encrypt(key, data, depth, 0)?;
    // AES with mult
    let aes_data = aes_encrypt(key, &fractal_encrypted_data, mult)?;
    // Base64 encode the final encrypted data
    let base64_encoded_data = encode(&aes_data);
    // Return the final encrypted data as a Base64 encoded string
    Ok(base64_encoded_data)
}

// Decryption
fn dec(data: &str, key: &[u8], depth: usize, mult: usize) -> Result<Vec<u8>, AesGcmError> {
    // Base64 decode the input data
    let base64_decoded_data = decode(data).map_err(|_| AesGcmError)?;
    // AES with mult
    let aes_data = aes_decrypt(key, &base64_decoded_data, mult)?;
    // Fractal with depth
    let decrypted_data = fractal_decrypt(key, &aes_data, depth, 0)?;
    // Return the final decrypted data
    Ok(decrypted_data)
}

fn laqf(depth: usize, mult: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // Generate Kyber key pairs for two entities (can be more in a real-world application)
    let _entity_1_keys = match keypair(&mut rng) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("\x1b[1;31mFailed to generate keypair for entity 1: {}\x1b[0m", e);
            return Err(Box::new(CustomError::Other(e.to_string())));
        }
    };

    let entity_2_keys = match keypair(&mut rng) {
        Ok(keys) => keys,
        Err(e) => {
            eprintln!("\x1b[1;31mFailed to generate keypair for entity 2: {}\x1b[0m", e);
            return Err(Box::new(CustomError::Other(e.to_string())));
        }
    };

    // Entity 1 performs triple encapsulation using Entity 2's public key
    let (ciphertexts, mut shared_secret_1) = match triple_encapsulation(&entity_2_keys.public, &mut rng) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("\x1b[1;31mFailed to perform triple encapsulation: {}\x1b[0m", e);
            return Err(Box::new(CustomError::Other(e.to_string())));
        }
    };

    // Entity 2 decapsulates using its secret key
    let mut shared_secret_2 = match triple_decapsulation(&entity_2_keys.secret, &ciphertexts) {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("\x1b[1;31mFailed to perform triple decapsulation: {}\x1b[0m", e);
            return Err(Box::new(CustomError::Other(e.to_string())));
        }
    };

    // Check that both entities have the same shared key
    if shared_secret_1 != shared_secret_2 {
        eprintln!("\x1b[1;31mShared secrets do not match\x1b[0m");
        return Err(Box::new(CustomError::Other("Shared secrets do not match".to_string())));
    }

    // Example data to be encrypted (can be any payload)
    let data = "Top-secret NASA mission data.";

    // Entity 1 encrypts the data using enc function
    let encrypted_data = match enc(data.as_bytes(), &shared_secret_1, depth, mult) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("\x1b[1;31mFailed to encrypt data: {}\x1b[0m", e);
            return Err(Box::new(CustomError::from(e)));
        }
    };

    // Entity 2 decrypts the data using dec function
    let decrypted_data = match dec(&encrypted_data, &shared_secret_2, depth, mult) {
        Ok(data) => String::from_utf8(data)?,
        Err(e) => {
            eprintln!("\x1b[1;31mFailed to decrypt data: {}\x1b[0m", e);
            return Err(Box::new(CustomError::from(e)));
        }
    };

    // Zeroize shared secrets after usage
    shared_secret_1.zeroize();
    shared_secret_2.zeroize();

    // Ensure the decrypted data matches the original
    if data != decrypted_data {
        eprintln!("\x1b[1;31mDecrypted data does not match the original\x1b[0m");
        return Err(Box::new(CustomError::Other("Decrypted data does not match the original".to_string())));
    }

    // ORIGINAL
    println!("Original data: {:?}", data);

    // ENCRYPTED
    println!("Encrypted data: {:?}", encrypted_data);

    // DECRYPTED
    println!("Decrypted data: {:?}", decrypted_data);

    println!("\x1b[1;32mLAQ-Fort encryption and decryption with fractal layer successful!\x1b[0m");
    Ok(())
}

// General-purpose LAQ-Fort encryption and decryption with fractal layer
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("Depth: {}, Mult: {}", args.depth, args.mult);
    laqf(args.depth, args.mult)?;
    Ok(())
}