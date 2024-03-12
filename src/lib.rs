pub mod error;

use uuid::Uuid;
use error::Error;
use rand::rngs::StdRng;
use rand::SeedableRng;
use secp256k1::{PublicKey, SecretKey};
use secp256k1::rand::thread_rng;
use tiny_keccak::{Hasher, Keccak};

pub fn get_address_from_public_key(pubkey: &PublicKey) -> Vec<u8> {
    let pubkey_bytes = &pubkey.serialize_uncompressed()[1..65];
    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(pubkey_bytes);
    hasher.finalize(&mut hash);
    hash[12..32].to_vec()
}

pub fn get_address_space_size(uid: &[u8]) -> u64 {
    2u64.pow((uid.len() * 8) as u32)
}

pub fn generate_safe_uid() -> [u8; 16] {
    Uuid::new_v4()
        .as_bytes()
        .to_owned()
}

#[derive(Debug)]
pub struct Keypair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
    pub address: Address,
}

#[derive(Debug)]
pub struct Address([u8;20]);
impl ToString for Address {
    fn to_string(&self) -> String {
        let mut base = String::from("0x");
        base.push_str(&hex::encode(self.0));
        base
    }
}

impl Keypair {
    pub fn from_secret_key_str(private_key: &str) -> Result<Self, Error> {
        let trimmed = match private_key.strip_prefix("0x") {
            Some(t) => t,
            None => private_key
        };
        if trimmed.len() != 64 {
            return Err(Error::SecretKeyLenMismatch)
        }
        let decoded = hex::decode(trimmed)?;
        if decoded.len() != 32 {
            return Err(Error::SecretKeyLenMismatch);
        }
        Ok(Self::from_secret_key(&decoded[0..32])?)
    }

    pub fn from_secret_key(x: &[u8]) -> Result<Self, Error> {
        let secret_key = SecretKey::from_slice(x)?;
        let public_key = PublicKey::from_secret_key(secp256k1::SECP256K1, &secret_key);
        let address = get_address_from_public_key(&public_key);
        Ok(Self {
            secret_key, public_key, address: Address(address.try_into().unwrap())
        })
    }

    pub fn generate_new<T : secp256k1::rand::Rng + ?Sized>(rng_core: &mut T) -> Self {
        let (secret_key, public_key) = secp256k1::generate_keypair(rng_core);
        let address = get_address_from_public_key(&public_key);
        Self {
            secret_key, public_key, address: Address(address.try_into().expect("Wrong address length"))
        }
    }

    pub fn generate_new_with_thread_rng() -> Self {
        Self::generate_new(&mut thread_rng())
    }

    pub fn get_address(&self) -> &Address {
        &self.address
    }

    pub fn get_secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn export_secret_key_as_hex_string(&self) -> String {
        self.secret_key.display_secret().to_string()
    }

    pub fn export_public_key_as_hex_string(&self) -> String {
        self.public_key.to_string()
    }

    fn apply_pub_hash(&self, input: &[u8]) -> [u8; 32] {
        let mut hash = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(input);
        hasher.finalize(&mut hash);
        hash
    }

    fn child_seed(&self, uid: &[u8]) -> StdRng {
        if uid.len() < 16 {
            println!("UID should be of at least 16 bytes");
        }
        let mut hash = [0u8; 32];
        let pubkey = &self.public_key.serialize_uncompressed()[1..65];
        let pubkey_hash: [u8; 32] = self.apply_pub_hash(pubkey);
        let mut hasher = Keccak::v256();
        hasher.update(uid);
        hasher.update(&pubkey_hash);
        hasher.finalize(&mut hash);
        StdRng::from_seed(hash)
    }

    fn derive_child(&self, uid: &[u8]) -> Result<Keypair, Error> {
        let mut rng = self.child_seed(uid); // Child Seed
        let (secret_key, public_key) = secp256k1::generate_keypair(&mut rng);
        let addr = get_address_from_public_key(&public_key);
        Ok(Keypair{
            secret_key,
            public_key,
            address: Address(addr.try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::{hashes::sha256, Message};

    use crate::{Keypair, get_address_space_size, generate_safe_uid};

    #[test]
    fn generate_uid_size_0() { // Insecure UID
        let uid = b"12";
        let mut base = String::from("0x");
        base.push_str(&hex::encode(uid));
        println!("Insecure UID: {}", base);
        assert_eq!(65536, get_address_space_size(uid));
    }

    #[test]
    fn generate_uid_size_1() { // Secure UID
        let uid = generate_safe_uid();
        let mut base = String::from("0x");
        base.push_str(&hex::encode(uid));
        println!("Secure UID: {}", base);
    }

    #[test]
    fn generate_new() {
        let key = Keypair::generate_new_with_thread_rng();
        println!("{:#?}", key);
        assert!(key.address.to_string().starts_with("0x"));
    }

    #[test]
    #[should_panic]
    fn from_secret_key_string_0() {
        Keypair::from_secret_key_str("this is not a private key, probably").unwrap();
    }

    #[test]
    fn from_secret_key_string_1() {
        let key = Keypair::from_secret_key_str(
            "742a504d9674cf3c3a6f2ade3b3780660559209ee45279c230a534ca35187b9e"
        ).unwrap();
        assert_eq!(
            key.export_secret_key_as_hex_string(),
            "742a504d9674cf3c3a6f2ade3b3780660559209ee45279c230a534ca35187b9e".to_string()
        );
        assert_eq!(
            key.get_address().to_string(),
            "0x55555556e84ad25e7d3288da2122f0784e27213d".to_string()
        );
    }

    #[test]
    fn derivation_0() {
        let root = Keypair::generate_new_with_thread_rng();
        let uid = generate_safe_uid();
        let child = root.derive_child(&uid).unwrap();
        println!("Root Address: {}", root.get_address().to_string());
        println!("Child Address: {}", child.get_address().to_string());

        let msg = Message::from_hashed_data::<sha256::Hash>("sample-data".as_bytes());
        let sig = child.secret_key.sign_ecdsa(msg);
        assert!(sig.verify(&msg, &child.public_key).is_ok());
        assert!(sig.verify(&msg, &root.public_key).is_err());
        let mut seed = root.child_seed(&uid);
        let (_, reconstructed_child_pub_key) = secp256k1::generate_keypair(&mut seed);
        assert!(sig.verify(&msg, &reconstructed_child_pub_key).is_ok());
    }

    #[test]
    fn derivation_1() {
        let root = Keypair::generate_new_with_thread_rng();
        let uid = generate_safe_uid();
        let child = root.derive_child(&uid).unwrap();
        println!("Root Address: {}", root.get_address().to_string());
        println!("Child Address: {}", child.get_address().to_string());

        // Generate Child Seed (used in derivation) & fetch it's public key
        let mut seed = root.child_seed(&uid);
        let (_, reconstructed_child_pub_key) = secp256k1::generate_keypair(&mut seed);

        // Child Gen log & signature
        let msg1 = Message::from_hashed_data::<sha256::Hash>("sample-data".as_bytes());
        let sig1 = child.secret_key.sign_ecdsa(msg1);
        assert!(sig1.verify(&msg1, &child.public_key).is_ok());
        assert!(sig1.verify(&msg1, &reconstructed_child_pub_key).is_ok());
        assert!(sig1.verify(&msg1, &root.public_key).is_err());

        // Root Signature on-top
        let mut msg_sig = Vec::new();
        msg_sig.extend_from_slice(&sig1.serialize_compact().to_vec());
        msg_sig.extend_from_slice(&msg1.to_string().as_bytes());
        let msg2 = Message::from_hashed_data::<sha256::Hash>(&msg_sig);
        let sig2 = root.secret_key.sign_ecdsa(msg2);
        assert!(sig2.verify(&msg2, &child.public_key).is_err());
        assert!(sig1.verify(&msg2, &reconstructed_child_pub_key).is_err());
        assert!(sig2.verify(&msg2, &root.public_key).is_ok());
    }
}
