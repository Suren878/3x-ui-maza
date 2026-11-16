//! RFC 9729, Ed25519 (TLS SignatureScheme 2055), empty realm.
//! This is connection-bound authentication, not a signature over each HTTP request.
use crate::{
    capsule::put_varint,
    config::{AuthorizedKey, Origin},
};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use http::HeaderValue;
use ring::{
    rand::SystemRandom,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use std::{collections::BTreeMap, path::Path, sync::Arc};
use subtle::ConstantTimeEq;

pub const LABEL: &[u8] = b"EXPORTER-HTTP-Concealed-Authentication";
pub type Export = [u8; 48];

#[derive(Clone)]
pub struct Identity {
    pub id: String,
    key: Arc<Ed25519KeyPair>,
}

impl Identity {
    pub fn from_pkcs8(id: String, bytes: &[u8]) -> Result<Self> {
        ensure!(
            !id.is_empty() && id.len() <= 64,
            "key ID must contain 1 to 64 bytes"
        );
        // Go's x509.MarshalPKCS8PrivateKey emits PKCS#8 v1 (seed only).
        // ring derives the public key for v1 and checks it when included in v2.
        let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(bytes)
            .map_err(|_| anyhow::anyhow!("invalid Ed25519 PKCS#8 key"))?;
        Ok(Self {
            id,
            key: Arc::new(key),
        })
    }

    pub fn load(id: String, path: &Path) -> Result<Self> {
        Self::from_pkcs8(id, &crate::config::read_limited(path, 8192)?)
    }

    pub fn public_key(&self) -> &[u8] {
        self.key.public_key().as_ref()
    }

    pub fn authorization(
        &self,
        origin: &Origin,
        mut export: impl FnMut(&[u8]) -> Result<Export>,
    ) -> Result<HeaderValue> {
        let material = export(&context(&self.id, self.public_key(), origin))?;
        let proof = self.key.sign(&signature_input(&material));
        let value = format!(
            "Concealed k={}, a={}, s=2055, v={}, p={}",
            B64.encode(&self.id),
            B64.encode(self.public_key()),
            B64.encode(&material[32..]),
            B64.encode(proof.as_ref())
        );
        let mut header = HeaderValue::from_str(&value)?;
        header.set_sensitive(true);
        Ok(header)
    }
}

pub fn generate_key() -> Result<Vec<u8>> {
    Ok(Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("key generation failed"))?
        .as_ref()
        .to_vec())
}

fn context(id: &str, public: &[u8], origin: &Origin) -> Vec<u8> {
    let mut output = 2055u16.to_be_bytes().to_vec();
    for part in [id.as_bytes(), public, b"https", origin.host.as_bytes()] {
        put_varint(part.len() as u64, &mut output);
        output.extend_from_slice(part);
    }
    output.extend_from_slice(&origin.port.to_be_bytes());
    put_varint(0, &mut output); // Empty realm.
    output
}

fn signature_input(material: &Export) -> Vec<u8> {
    let mut input = vec![0x20; 64];
    // Use the normative text of RFC 9729 §3.3, not its inconsistent example hex.
    input.extend_from_slice(b"HTTP Concealed Authentication\0");
    input.extend_from_slice(&material[..32]);
    input
}

pub struct PublicKeys(BTreeMap<String, [u8; 32]>);

impl PublicKeys {
    pub fn new(keys: &[AuthorizedKey]) -> Result<Self> {
        // An empty allowlist is a valid deny-all state after the final client
        // is revoked. Rejecting it would retain an already revoked identity.
        ensure!(keys.len() <= 64, "configure at most 64 client keys");
        let mut map = BTreeMap::new();
        for key in keys {
            ensure!(
                !key.id.is_empty() && key.id.len() <= 64,
                "invalid client key ID length"
            );
            let decoded: [u8; 32] = B64
                .decode(&key.public_key)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("invalid client public key"))?;
            ensure!(
                map.insert(key.id.clone(), decoded).is_none(),
                "duplicate client key ID"
            );
        }
        Ok(Self(map))
    }

    /// All supported contexts are known before h2 takes ownership of the TLS stream.
    pub fn bind(
        &self,
        origin: &Origin,
        mut export: impl FnMut(&[u8]) -> Result<Export>,
    ) -> Result<Verifier> {
        let mut entries = BTreeMap::new();
        for (id, key) in &self.0 {
            entries.insert(id.clone(), (*key, export(&context(id, key, origin))?));
        }
        Ok(Verifier(entries))
    }
}

pub struct Verifier(BTreeMap<String, ([u8; 32], Export)>);

impl Verifier {
    pub fn accepts(&self, header: Option<&HeaderValue>) -> bool {
        self.verify(header).is_some()
    }

    fn verify(&self, header: Option<&HeaderValue>) -> Option<()> {
        let text = header?.to_str().ok()?;
        if text.len() > 2048 {
            return None;
        }
        let (scheme, params) = text.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("Concealed") {
            return None;
        }
        let mut fields = BTreeMap::new();
        for param in params.split(',') {
            let (name, value) = param.trim().split_once('=')?;
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim();
            if fields.insert(name, value).is_some() {
                return None;
            }
        }
        if fields.get("s") != Some(&"2055") || fields.contains_key("realm") {
            return None;
        }
        let decode = |name: &str| B64.decode(*fields.get(name)?).ok();
        let id = String::from_utf8(decode("k")?).ok()?;
        let (public, material) = self.0.get(&id)?;
        let supplied_public = decode("a")?;
        let verification = decode("v")?;
        if !bool::from(public.as_slice().ct_eq(&supplied_public))
            || !bool::from(material[32..].ct_eq(&verification))
        {
            return None;
        }
        signature::UnparsedPublicKey::new(&signature::ED25519, public)
            .verify(&signature_input(material), &decode("p")?)
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_go_pkcs8_v1_and_derives_the_matching_public_key() {
        let seed = [7u8; 32];
        // RFC 8410 Ed25519 PrivateKeyInfo, the exact Go x509 v1 encoding.
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&seed);
        let identity = Identity::from_pkcs8("panel".into(), &der).unwrap();
        let expected = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        assert_eq!(identity.public_key(), expected.public_key().as_ref());
        der.pop();
        assert!(Identity::from_pkcs8("panel".into(), &der).is_err());
    }

    #[test]
    fn rejects_replay_wrong_key_origin_and_duplicate_parameters() {
        let identity = Identity::from_pkcs8("laptop".into(), &generate_key().unwrap()).unwrap();
        let keys = PublicKeys::new(&[AuthorizedKey {
            id: identity.id.clone(),
            public_key: B64.encode(identity.public_key()),
        }])
        .unwrap();
        let origin = Origin::parse("https://example.test").unwrap();
        let exporter = |context: &[u8]| {
            let mut out = [0; 48];
            out.copy_from_slice(ring::digest::digest(&ring::digest::SHA384, context).as_ref());
            Ok(out)
        };
        let verifier = keys.bind(&origin, exporter).unwrap();
        let header = identity.authorization(&origin, exporter).unwrap();
        assert!(verifier.accepts(Some(&header)));
        assert!(!verifier.accepts(None));
        assert!(
            !keys
                .bind(&origin, |_| Ok([1; 48]))
                .unwrap()
                .accepts(Some(&header))
        );
        assert!(
            !keys
                .bind(&Origin::parse("https://other.test").unwrap(), exporter)
                .unwrap()
                .accepts(Some(&header))
        );
        let duplicate =
            HeaderValue::from_str(&format!("{}, s=2055", header.to_str().unwrap())).unwrap();
        assert!(!verifier.accepts(Some(&duplicate)));
        let wrong = Identity::from_pkcs8("laptop".into(), &generate_key().unwrap()).unwrap();
        assert!(!verifier.accepts(Some(&wrong.authorization(&origin, exporter).unwrap())));
    }

    #[test]
    fn exporter_context_has_rfc_field_order_and_minimal_lengths() {
        let origin = Origin::parse("https://example.test:8443").unwrap();
        let data = context("x", &[7; 32], &origin);
        let mut expected = vec![8, 7, 1, b'x', 32];
        expected.extend([7; 32]);
        expected.extend_from_slice(b"\x05https\x0cexample.test\x20\xfb\x00");
        assert_eq!(data, expected);
        let input = signature_input(&[1; 48]);
        assert_eq!(&input[..64], &[32; 64]);
        assert_eq!(
            &input[64..],
            [b"HTTP Concealed Authentication\0".as_slice(), &[1; 32]].concat()
        );
    }
}
