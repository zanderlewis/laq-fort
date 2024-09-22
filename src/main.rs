use laqfort::*;
use zeroize::Zeroize;
use std::str;
use clap::Parser;
use pqc_kyber::{keypair, Keypair};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(short, long, default_value_t = 3)]
    pub depth: usize,

    #[clap(short, long, default_value_t = 8)]
    pub mult: usize,

    // Data to be encrypted
    #[clap(long)]
    pub data: Option<String>,
}

fn main() {
    let args = Args::parse();
    let mut rng = rand::thread_rng();
    let Keypair { public, mut secret } = keypair(&mut rng).unwrap();
    let (ciphertexts, mut shared_key) = triple_encapsulation(&public, &mut rng).unwrap();
    triple_decapsulation(&secret, &ciphertexts).unwrap();
    let key = &shared_key;
    let depth = args.depth;
    let mult = args.mult;
    let mle_key = "mle_key";
    let data = args.data;
    let encrypted_data = laqf_encrypt(depth, mult, data, mle_key, key).unwrap();
    let decrypted_data = laqf_decrypt(depth, mult, Some(encrypted_data.clone()), mle_key, key).unwrap();
    println!("Encrypted data: {}", encrypted_data);
    println!("Decrypted data: {}", str::from_utf8(&decrypted_data).unwrap());

    // MLE wrong key decrypt
    let wrong_mle_key = "wrong_mle_key";
    let decrypted_data = laqf_decrypt(depth, mult, Some(encrypted_data.clone()), wrong_mle_key, key).unwrap();
    println!("Wrong MLE key decrypted data: {}", str::from_utf8(&decrypted_data).unwrap());

    // Zeroize the shared key after use
    shared_key.zeroize();

    // Zeroize the secret key after use
    secret.zeroize();
}