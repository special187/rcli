use crate::{process_genpass, TextSignFormat};
use anyhow::Result;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::io::Read;

pub trait TextSigner {
    // Sign the data from the reader and return the signature
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    fn verify(&self, reader: &mut dyn Read, signature: &[u8]) -> Result<bool>;
}

pub trait TextTryNew<T> {
    fn new(key: [u8; 32]) -> Self;
    fn try_new(key: impl AsRef<[u8]>) -> Result<Self>
    where
        Self: Sized,
    {
        let key = key.as_ref();
        let key = key[..32].try_into()?;
        Ok(Self::new(key))
    }
}

struct Blake3 {
    key: [u8; 32],
}

impl TextTryNew<Blake3> for Blake3 {
    fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
}

impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        // todo: improve performance by reading in chunks
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(blake3::keyed_hash(&self.key, &buf).as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, signature: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = blake3::keyed_hash(&self.key, &buf);
        let sig = sig.as_bytes();
        Ok(sig == signature)
    }
}
impl Blake3 {
    pub fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("auto_gen_blake3_key.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

struct Ed25519Signer {
    key: SigningKey,
}

impl TextTryNew<Ed25519Signer> for Ed25519Signer {
    fn new(key: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&key);
        Self { key }
    }
}

impl Ed25519Signer {
    pub fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk: VerifyingKey = (&sk).into();
        let mut map = HashMap::new();
        map.insert("auto_gen_ed25519.sk", sk.as_bytes().to_vec());
        map.insert("auto_gen_ed25519.pk", pk.as_bytes().to_vec());
        Ok(map)
    }
}

impl TextSigner for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = self.key.sign(&buf);
        Ok(sig.to_bytes().to_vec())
    }
}

struct Ed25519Verifier {
    key: VerifyingKey,
}

impl Ed25519Verifier {
    fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = key[..32].try_into()?;
        let key = VerifyingKey::from_bytes(&key)?;
        Ok(Self { key })
    }
}

impl TextVerifier for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, signature: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = Signature::from_bytes(signature.try_into()?);
        let ret = self.key.verify(&buf, &sig).is_ok();
        Ok(ret)
    }
}

pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8],
    format: TextSignFormat,
) -> Result<Vec<u8>> {
    let signer: Box<dyn TextSigner> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Signer::try_new(key)?),
    };
    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sign: &[u8],
    format: TextSignFormat,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        TextSignFormat::Blake3 => Box::new(Blake3::try_new(key)?),
        TextSignFormat::Ed25519 => Box::new(Ed25519Verifier::try_new(key)?),
    };
    verifier.verify(reader, sign)
}

pub fn process_text_key_generate(format: TextSignFormat) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        TextSignFormat::Blake3 => Blake3::generate(),
        TextSignFormat::Ed25519 => Ed25519Signer::generate(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{get_content, get_reader};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const KEY: &[u8] = include_bytes!("../../fixtures/blake3_key.txt");
    #[test]
    fn test_process_text_sign_blake3() -> Result<()> {
        let mut reader = get_reader("fixtures/file.txt")?;
        let expected_sig = get_content("fixtures/blake3_sign.txt")?;
        let format = TextSignFormat::Blake3;
        let sig = process_text_sign(&mut reader, KEY, format)?;
        let encode = URL_SAFE_NO_PAD.encode(sig);
        assert_eq!(String::from_utf8(expected_sig)?, encode);
        Ok(())
    }

    #[test]
    fn test_process_text_verify_blake3() -> Result<()> {
        let mut reader = get_reader("fixtures/file.txt")?;
        let encoded_sig = get_content("fixtures/blake3_sign.txt")?;
        let sig = URL_SAFE_NO_PAD.decode(encoded_sig)?;
        let format = TextSignFormat::Blake3;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_sign_ed25519() -> Result<()> {
        let mut reader = get_reader("fixtures/file.txt")?;
        let expected_sig = get_content("fixtures/ed25519_sign.txt")?;
        let format = TextSignFormat::Ed25519;
        let sk = get_content("fixtures/ed25519.sk")?;
        let sig = process_text_sign(&mut reader, &sk, format)?;
        let encode = URL_SAFE_NO_PAD.encode(sig);
        assert_eq!(String::from_utf8(expected_sig)?, encode);
        Ok(())
    }

    #[test]
    fn test_process_text_verify_ed25519() -> Result<()> {
        let mut reader = get_reader("fixtures/file.txt")?;
        let encoded_sig = get_content("fixtures/ed25519_sign.txt")?;
        let sig = URL_SAFE_NO_PAD.decode(encoded_sig)?;
        let format = TextSignFormat::Ed25519;
        let key = get_content("fixtures/ed25519.pk")?;
        let ret = process_text_verify(&mut reader, &key, &sig, format)?;
        assert!(ret);
        Ok(())
    }
}
