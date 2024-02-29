use crate::{cbor_serialize_message, TrussedRequirements};
use core::mem;
use ctap_types::{cose::EcdhEsHkdf256PublicKey, ctap2::client_pin::Permissions, Error, Result};
use trussed::{
    cbor_deserialize,
    client::{Aes256Cbc, CryptoClient, HmacSha256, P256},
    syscall, try_syscall,
    types::{
        Bytes, KeyId, KeySerialization, Location, Mechanism, Message, StorageAttributes, String,
    },
};
use trussed_hkdf::{KeyOrData, OkmId};

// PIN protocol 1 supports 16 or 32 bytes, PIN protocol 2 requires 32 bytes.
const PIN_TOKEN_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug)]
pub enum PinProtocolVersion {
    V1,
    V2,
}

impl From<PinProtocolVersion> for u8 {
    fn from(version: PinProtocolVersion) -> Self {
        match version {
            PinProtocolVersion::V1 => 1,
            PinProtocolVersion::V2 => 2,
        }
    }
}

#[derive(Debug)]
pub struct PinToken {
    key_id: KeyId,
    state: PinTokenState,
}

impl PinToken {
    fn generate<T: HmacSha256>(trussed: &mut T) -> PinToken {
        let key_id =
            syscall!(trussed.generate_secret_key(PIN_TOKEN_LENGTH, Location::Volatile)).key;
        Self::new(key_id)
    }

    fn new(key_id: KeyId) -> Self {
        Self {
            key_id,
            state: Default::default(),
        }
    }

    fn delete<T: CryptoClient>(self, trussed: &mut T) {
        syscall!(trussed.delete(self.key_id));
    }

    pub fn require_permissions(&self, permissions: Permissions) -> Result<()> {
        if self.state.permissions.contains(permissions) {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    pub fn require_valid_for_rp_id(&self, rp_id: Option<&str>) -> Result<()> {
        if self.state.rp_id.is_none() || self.state.rp_id.as_deref() == rp_id {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }
}

#[derive(Debug, Default)]
struct PinTokenState {
    permissions: Permissions,
    rp_id: Option<String<256>>,
    is_user_present: bool,
    is_user_verified: bool,
    is_in_use: bool,
}

#[derive(Debug)]
pub struct PinProtocolState {
    key_agreement_key: KeyId,
    // only used to delete the old shared secret from VFS when generating a new one.  ideally, the
    // SharedSecret struct would clean up after itself.
    shared_secret: Option<SharedSecret>,

    // for protocol version 1
    pin_token_v1: PinToken,
    // for protocol version 2
    pin_token_v2: PinToken,
}

impl PinProtocolState {
    // in spec: initialize(...)
    pub fn new<T: TrussedRequirements>(trussed: &mut T) -> Self {
        Self {
            key_agreement_key: generate_key_agreement_key(trussed),
            shared_secret: None,
            pin_token_v1: PinToken::generate(trussed),
            pin_token_v2: PinToken::generate(trussed),
        }
    }

    pub fn reset<T: TrussedRequirements>(self, trussed: &mut T) {
        self.pin_token_v1.delete(trussed);
        self.pin_token_v2.delete(trussed);
        syscall!(trussed.delete(self.key_agreement_key));
        if let Some(shared_secret) = self.shared_secret {
            shared_secret.delete(trussed);
        }
    }
}

#[derive(Debug)]
pub struct PinProtocol<'a, T: TrussedRequirements> {
    trussed: &'a mut T,
    state: &'a mut PinProtocolState,
    version: PinProtocolVersion,
}

impl<'a, T: TrussedRequirements> PinProtocol<'a, T> {
    pub fn new(
        trussed: &'a mut T,
        state: &'a mut PinProtocolState,
        version: PinProtocolVersion,
    ) -> Self {
        Self {
            trussed,
            state,
            version,
        }
    }

    fn pin_token(&self) -> &PinToken {
        match self.version {
            PinProtocolVersion::V1 => &self.state.pin_token_v1,
            PinProtocolVersion::V2 => &self.state.pin_token_v2,
        }
    }

    fn pin_token_mut(&mut self) -> &mut PinToken {
        match self.version {
            PinProtocolVersion::V1 => &mut self.state.pin_token_v1,
            PinProtocolVersion::V2 => &mut self.state.pin_token_v2,
        }
    }

    pub fn regenerate(&mut self) {
        syscall!(self.trussed.delete(self.state.key_agreement_key));
        if let Some(shared_secret) = self.state.shared_secret.take() {
            shared_secret.delete(self.trussed);
        }
        self.state.key_agreement_key = generate_key_agreement_key(self.trussed);
    }

    // in spec: resetPinUvAuthToken()
    pub fn reset_pin_token(&mut self) {
        let new = PinToken::generate(self.trussed);
        mem::replace(self.pin_token_mut(), new).delete(self.trussed);
    }

    pub fn restrict_pin_token(&mut self, permissions: Permissions, rp_id: Option<String<256>>) {
        let pin_token = self.pin_token_mut();
        pin_token.state.permissions = permissions;
        pin_token.state.rp_id = rp_id;
    }

    // in spec: beginUsingPinUvAuthToken(userIsPresent)
    pub fn begin_using_pin_token(&mut self, is_user_present: bool) {
        let pin_token = self.pin_token_mut();
        pin_token.state.is_user_present = is_user_present;
        pin_token.state.is_user_verified = true;
        // TODO: set initial usage time limit
        // TODO: start and observe usage timer
        pin_token.state.is_in_use = true;
    }

    // in spec: getPublicKey
    #[must_use]
    pub fn key_agreement_key(&mut self) -> EcdhEsHkdf256PublicKey {
        let public_key = syscall!(self
            .trussed
            .derive_p256_public_key(self.state.key_agreement_key, Location::Volatile))
        .key;
        let serialized_cose_key = syscall!(self.trussed.serialize_key(
            Mechanism::P256,
            public_key,
            KeySerialization::EcdhEsHkdf256
        ))
        .serialized_key;
        let cose_key = cbor_deserialize(&serialized_cose_key).unwrap();
        syscall!(self.trussed.delete(public_key));
        cose_key
    }

    #[must_use]
    fn verify(&mut self, key: KeyId, data: &[u8], signature: &[u8]) -> bool {
        if signature.len() < 16 {
            return false;
        }
        let actual_signature = syscall!(self.trussed.sign_hmacsha256(key, data)).signature;
        let expected_signature = match self.version {
            PinProtocolVersion::V1 => &actual_signature[..16],
            PinProtocolVersion::V2 => &actual_signature,
        };
        expected_signature == signature
    }

    // in spec: verify(pinUvAuthToken, ...)
    pub fn verify_pin_token(&mut self, data: &[u8], signature: &[u8]) -> Result<&PinToken> {
        let pin_token = self.pin_token();
        if pin_token.state.is_in_use && self.verify(pin_token.key_id, data, signature) {
            Ok(self.pin_token())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    // in spec: verify(shared secret, ...)
    pub fn verify_pin_auth(
        &mut self,
        shared_secret: &SharedSecret,
        data: &[u8],
        pin_auth: &[u8],
    ) -> Result<()> {
        let key_id = shared_secret.hmac_key_id();
        if self.verify(key_id, data, pin_auth) {
            Ok(())
        } else {
            Err(Error::PinAuthInvalid)
        }
    }

    // in spec: encrypt(..., pinUvAuthToken)
    pub fn encrypt_pin_token(&mut self, shared_secret: &SharedSecret) -> Result<Bytes<32>> {
        let token = shared_secret.wrap(self.trussed, self.pin_token().key_id);
        Bytes::from_slice(&token).map_err(|_| Error::Other)
    }

    // in spec: decapsulate(...) = ecdh(...)
    // The returned key ID is valid until the next call of shared_secret or regenerate.  The caller
    // has to delete the key from the VFS after end of use.  Ideally, this should be enforced by
    // the compiler, for example by using a callback.
    pub fn shared_secret(&mut self, peer_key: &EcdhEsHkdf256PublicKey) -> Result<SharedSecret> {
        self.shared_secret_impl(peer_key)
            .ok_or(Error::InvalidParameter)
    }

    fn shared_secret_impl(&mut self, peer_key: &EcdhEsHkdf256PublicKey) -> Option<SharedSecret> {
        let serialized_peer_key = cbor_serialize_message(peer_key).ok()?;
        let peer_key = try_syscall!(self.trussed.deserialize_p256_key(
            &serialized_peer_key,
            KeySerialization::EcdhEsHkdf256,
            StorageAttributes::new().set_persistence(Location::Volatile)
        ))
        .ok()?
        .key;

        let result = try_syscall!(self.trussed.agree(
            Mechanism::P256,
            self.state.key_agreement_key,
            peer_key,
            StorageAttributes::new().set_persistence(Location::Volatile),
        ));
        syscall!(self.trussed.delete(peer_key));
        let pre_shared_secret = result.ok()?.shared_secret;

        if let Some(shared_secret) = self.state.shared_secret.take() {
            shared_secret.delete(self.trussed);
        }

        let shared_secret = self.kdf(pre_shared_secret);
        syscall!(self.trussed.delete(pre_shared_secret));

        let shared_secret = shared_secret?;
        self.state.shared_secret = Some(shared_secret.clone());
        Some(shared_secret)
    }

    fn kdf(&mut self, input: KeyId) -> Option<SharedSecret> {
        match self.version {
            PinProtocolVersion::V1 => self.kdf_v1(input),
            PinProtocolVersion::V2 => self.kdf_v2(input),
        }
    }

    // PIN protocol 1: derive a single key using SHA-256
    fn kdf_v1(&mut self, input: KeyId) -> Option<SharedSecret> {
        let key_id = syscall!(self.trussed.derive_key(
            Mechanism::Sha256,
            input,
            None,
            StorageAttributes::new().set_persistence(Location::Volatile)
        ))
        .key;
        Some(SharedSecret::V1 { key_id })
    }

    // PIN protocol 2: derive two keys using HKDF-SHA-256
    // In the spec, the keys are concatenated and the relevant part is selected during the key
    // operations.  For simplicity, we store two separate keys instead.
    fn kdf_v2(&mut self, input: KeyId) -> Option<SharedSecret> {
        fn hkdf<T: TrussedRequirements>(trussed: &mut T, okm: OkmId, info: &[u8]) -> Option<KeyId> {
            let info = Message::from_slice(info).ok()?;
            try_syscall!(trussed.hkdf_expand(okm, info, 32, Location::Volatile))
                .ok()
                .map(|reply| reply.key)
        }

        // salt: 0x00 * 32 => None
        let okm = try_syscall!(self.trussed.hkdf_extract(
            KeyOrData::Key(input),
            None,
            Location::Volatile
        ))
        .ok()?
        .okm;
        let hmac_key_id = hkdf(self.trussed, okm, b"CTAP2 HMAC key");
        let aes_key_id = hkdf(self.trussed, okm, b"CTAP2 AES key");

        syscall!(self.trussed.delete(okm.0));

        Some(SharedSecret::V2 {
            hmac_key_id: hmac_key_id?,
            aes_key_id: aes_key_id?,
        })
    }
}

#[derive(Clone, Debug)]
pub enum SharedSecret {
    V1 {
        key_id: KeyId,
    },
    V2 {
        hmac_key_id: KeyId,
        aes_key_id: KeyId,
    },
}

impl SharedSecret {
    fn aes_key_id(&self) -> KeyId {
        match self {
            Self::V1 { key_id } => *key_id,
            Self::V2 { aes_key_id, .. } => *aes_key_id,
        }
    }

    fn hmac_key_id(&self) -> KeyId {
        match self {
            Self::V1 { key_id } => *key_id,
            Self::V2 { hmac_key_id, .. } => *hmac_key_id,
        }
    }

    #[must_use]
    pub fn encrypt<T: CryptoClient>(&self, trussed: &mut T, data: &[u8]) -> Bytes<1024> {
        let key_id = self.aes_key_id();
        syscall!(trussed.encrypt(Mechanism::Aes256Cbc, key_id, data, b"", None)).ciphertext
    }

    #[must_use]
    fn wrap<T: Aes256Cbc>(&self, trussed: &mut T, key: KeyId) -> Bytes<1024> {
        let wrapping_key = self.aes_key_id();
        syscall!(trussed.wrap_key_aes256cbc(wrapping_key, key)).wrapped_key
    }

    #[must_use]
    pub fn decrypt<T: Aes256Cbc>(&self, trussed: &mut T, data: &[u8]) -> Option<Bytes<1024>> {
        let key_id = self.aes_key_id();
        decrypt(trussed, key_id, data)
    }

    pub fn delete<T: CryptoClient>(self, trussed: &mut T) {
        match self {
            Self::V1 { key_id } => {
                syscall!(trussed.delete(key_id));
            }
            Self::V2 {
                hmac_key_id,
                aes_key_id,
            } => {
                for key_id in [hmac_key_id, aes_key_id] {
                    syscall!(trussed.delete(key_id));
                }
            }
        }
    }
}

#[must_use]
fn decrypt<T: Aes256Cbc>(trussed: &mut T, key: KeyId, data: &[u8]) -> Option<Bytes<1024>> {
    try_syscall!(trussed.decrypt_aes256cbc(key, data))
        .ok()
        .and_then(|response| response.plaintext)
}

fn generate_key_agreement_key<T: P256>(trussed: &mut T) -> KeyId {
    syscall!(trussed.generate_p256_private_key(Location::Volatile)).key
}
