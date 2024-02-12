//! TODO: T

use core::cmp::Ordering;
use core::{convert::TryFrom, num::NonZeroU32};

use trussed::{
    syscall,
    types::{DirEntry, Location, Path, PathBuf},
};

use ctap_types::{
    cose::PublicKey,
    ctap2::credential_management::{CredentialProtectionPolicy, Response},
    heapless_bytes::Bytes,
    webauthn::PublicKeyCredentialDescriptor,
    Error,
};

use crate::{
    constants::MAX_RESIDENT_CREDENTIALS_GUESSTIMATE,
    credential::FullCredential,
    state::{CredentialManagementEnumerateCredentials, CredentialManagementEnumerateRps},
    Authenticator, Result, TrussedRequirements, UserPresence,
};

pub(crate) struct CredentialManagement<'a, UP, T>
where
    UP: UserPresence,
{
    authnr: &'a mut Authenticator<UP, T>,
}

impl<UP, T> core::ops::Deref for CredentialManagement<'_, UP, T>
where
    UP: UserPresence,
{
    type Target = Authenticator<UP, T>;
    fn deref(&self) -> &Self::Target {
        self.authnr
    }
}

impl<UP, T> core::ops::DerefMut for CredentialManagement<'_, UP, T>
where
    UP: UserPresence,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.authnr
    }
}

impl<'a, UP, T> CredentialManagement<'a, UP, T>
where
    UP: UserPresence,
{
    pub fn new(authnr: &'a mut Authenticator<UP, T>) -> Self {
        Self { authnr }
    }
}

/// Get the hex hashed ID of the RP from the filename of a RP directory OR a "new" RK path
fn get_id_hex(entry: &DirEntry) -> &str {
    entry
        .file_name()
        .as_str()
        .split('.')
        .next()
        .expect("Split always returns at least one empty string")
}

impl<UP, T> CredentialManagement<'_, UP, T>
where
    UP: UserPresence,
    T: TrussedRequirements,
{
    pub fn get_creds_metadata(&mut self) -> Response {
        info!("get metadata");
        let mut response: Response = Default::default();

        let max_resident_credentials = self
            .config
            .max_resident_credential_count
            .unwrap_or(MAX_RESIDENT_CREDENTIALS_GUESSTIMATE);
        response.existing_resident_credentials_count = Some(0);
        response.max_possible_remaining_residential_credentials_count =
            Some(max_resident_credentials);

        let dir = PathBuf::from(b"rk");
        let maybe_first_rp =
            syscall!(self
                .trussed
                .read_dir_first(Location::Internal, dir.clone(), None))
            .entry;

        let Some(first_rp) = maybe_first_rp else {
            return response;
        };

        let mut num_rks = 0;

        if first_rp.metadata().is_dir() {
            let (rk_count, _) = self.count_legacy_rp_rks(PathBuf::from(first_rp.path()));
            num_rks += rk_count;
        } else {
            debug_assert!(first_rp.metadata().is_file());
            num_rks += 1;
        }

        let mut previous_credential = first_rp.file_name().into();

        loop {
            // We need to restart the iteration each time because count_legacy_rp_rk has
            // its own iteration loop
            syscall!(self.trussed.read_dir_first(
                Location::Internal,
                dir.clone(),
                Some(previous_credential),
            ))
            .entry
            .unwrap();
            let maybe_next_rp = syscall!(self.trussed.read_dir_next()).entry;

            match maybe_next_rp {
                None => {
                    response.existing_resident_credentials_count = Some(num_rks);
                    response.max_possible_remaining_residential_credentials_count =
                        Some(max_resident_credentials.saturating_sub(num_rks));
                    return response;
                }
                Some(rp) => {
                    previous_credential = PathBuf::from(rp.file_name());
                    info!("counting..");

                    if rp.metadata().is_dir() {
                        let (rk_count, _) = self.count_legacy_rp_rks(rp.path().into());
                        num_rks += rk_count;
                    } else {
                        debug_assert!(rp.metadata().is_file());
                        num_rks += 1;
                    }
                }
            }
        }
    }

    pub fn first_relying_party(&mut self) -> Result<Response> {
        info!("first rp");

        let mut response = Response::default();
        let dir = PathBuf::from(b"rk");

        let maybe_first_rp =
            syscall!(self
                .trussed
                .read_dir_first(Location::Internal, dir.clone(), None))
            .entry;

        let Some(first_rp) = maybe_first_rp else {
            response.total_rps = Some(0);
            return Ok(response);
        };

        // The first one counts
        let mut total_rps = 1;

        let first_credential_data;
        if first_rp.metadata().is_dir() {
            first_credential_data = syscall!(self.trussed.read_dir_files_first(
                Location::Internal,
                first_rp.path().into(),
                None
            ))
            .data
            .expect("RP directory is expected to never be empty");

            // Restart the iteration over the directory
            syscall!(self.trussed.read_dir_first(Location::Internal, dir, None));
        } else {
            debug_assert!(first_rp.metadata().is_file());
            first_credential_data = syscall!(self
                .trussed
                .read_file(Location::Internal, first_rp.path().into()))
            .data;
        }

        let credential = FullCredential::deserialize(&first_credential_data)?;
        let rp_id_hash = syscall!(self.trussed.hash_sha256(credential.rp.id.as_ref()))
            .hash
            .to_bytes()
            .map_err(|_| Error::Other)?;

        let mut current_rp = first_rp;

        let mut current_id_hex = get_id_hex(&current_rp);

        while let Some(entry) = syscall!(self.trussed.read_dir_next()).entry {
            let id_hex = get_id_hex(&entry);
            if id_hex != current_id_hex {
                total_rps += 1;
                current_rp = entry;
                current_id_hex = get_id_hex(&current_rp)
            }
        }

        if let Some(remaining) = NonZeroU32::new(total_rps - 1) {
            self.state.runtime.cached_rp = Some(CredentialManagementEnumerateRps {
                remaining,
                rp_id_hash: rp_id_hash.clone(),
            });
        }

        response.total_rps = Some(total_rps);
        response.rp_id_hash = Some(rp_id_hash);
        response.rp = Some(credential.data.rp);
        Ok(response)
    }

    pub fn next_relying_party(&mut self) -> Result<Response> {
        let CredentialManagementEnumerateRps {
            remaining,
            rp_id_hash: last_rp_id_hash,
        } = self
            .state
            .runtime
            .cached_rp
            .clone()
            .ok_or(Error::NotAllowed)?;

        let mut hex = [b'0'; 16];
        super::format_hex(&last_rp_id_hash[..8], &mut hex);
        let filename = PathBuf::from(&hex);

        let dir = PathBuf::from(b"rk");

        let maybe_next_rp = syscall!(self.trussed.read_dir_first_alphabetical(
            Location::Internal,
            dir,
            Some(filename)
        ))
        .entry;

        let mut response = Response::default();

        let Some(current_rp) = maybe_next_rp else {
            return Err(Error::NotAllowed);
        };

        let current_id_hex = get_id_hex(&current_rp);

        debug_assert!(current_rp.file_name().as_str().as_bytes().starts_with(&hex));

        while let Some(entry) = syscall!(self.trussed.read_dir_next()).entry {
            let id_hex = get_id_hex(&entry);
            if id_hex == current_id_hex {
                continue;
            }

            let data = if entry.metadata().is_dir() {
                syscall!(self.trussed.read_dir_files_first(
                    Location::Internal,
                    entry.path().into(),
                    None
                ))
                .data
                .expect("RP dir should not be empty")
            } else {
                syscall!(self
                    .trussed
                    .read_file(Location::Internal, entry.path().into()))
                .data
            };

            let credential = FullCredential::deserialize(&data)?;
            let rp_id_hash = syscall!(self.trussed.hash_sha256(credential.rp.id.as_ref()))
                .hash
                .to_bytes()
                .map_err(|_| Error::Other)?;
            response.rp_id_hash = Some(rp_id_hash.clone());
            response.rp = Some(credential.data.rp);

            if let Some(new_remaining) = NonZeroU32::new(remaining.get() - 1) {
                self.state.runtime.cached_rp = Some(CredentialManagementEnumerateRps {
                    remaining: new_remaining,
                    rp_id_hash,
                });
            }

            return Ok(response);
        }

        return Err(Error::NotAllowed);
    }

    fn count_legacy_rp_rks(&mut self, rp_dir: PathBuf) -> (u32, Option<DirEntry>) {
        let maybe_first_rk =
            syscall!(self
                .trussed
                .read_dir_first(Location::Internal, rp_dir, None))
            .entry;

        let Some(first_rk) = maybe_first_rk else {
            warn!("empty RP directory");
            return (0, None);
        };

        // count the rest of them
        let mut num_rks = 1;
        while syscall!(self.trussed.read_dir_next()).entry.is_some() {
            num_rks += 1;
        }
        (num_rks, Some(first_rk))
    }

    pub fn first_credential(&mut self, rp_id_hash: &Bytes<32>) -> Result<Response> {
        info!("first credential");

        self.state.runtime.cached_rk = None;

        let mut hex = [b'0'; 16];
        super::format_hex(&rp_id_hash[..8], &mut hex);

        let rk_dir = PathBuf::from(b"rk");
        let rp_dir_start = PathBuf::from(&hex);

        let mut num_rks = 0;

        let mut maybe_entry = syscall!(self.trussed.read_dir_first_alphabetical(
            Location::Internal,
            rk_dir.clone(),
            Some(rp_dir_start.clone())
        ))
        .entry;

        let mut legacy_detected = false;
        let mut only_legacy = true;

        let mut first_rk = None;

        while let Some(entry) = maybe_entry {
            if !entry.file_name().as_str().as_bytes().starts_with(&hex) {
                // We got past all credentials for the relevant RP
                break;
            }

            if entry.file_name() == &*rp_dir_start {
                // This is the case where we
                debug_assert!(entry.metadata().is_dir());
                legacy_detected = true;
                // Because of the littlefs iteration order, we know that we are at the end
                break;
            }

            first_rk = first_rk.or(Some(entry));
            only_legacy = false;
            num_rks += 1;

            maybe_entry = syscall!(self.trussed.read_dir_next()).entry;
        }

        if legacy_detected {
            let (legacy_rks, first_legacy_rk) =
                self.count_legacy_rp_rks(rk_dir.join(&rp_dir_start));
            num_rks += legacy_rks;
            first_rk = first_rk.or(first_legacy_rk);
        }

        // TODO: FIX
        let first_rk = first_rk.ok_or(Error::NoCredentials)?;

        // extract data required into response
        let mut response = self.extract_response_from_credential_file(first_rk.path())?;
        response.total_credentials = Some(num_rks);

        // cache state for next call
        if let Some(num_rks) = response.total_credentials {
            if num_rks > 1 {
                // let rp_id_hash = response.rp_id_hash.as_ref().unwrap().clone();
                self.state.runtime.cached_rk = Some(CredentialManagementEnumerateCredentials {
                    remaining: num_rks - 1,
                    rp_dir: if only_legacy {
                        rk_dir.join(&PathBuf::from(&hex))
                    } else {
                        rk_dir
                    },
                    prev_filename: Some(first_rk.file_name().into()),
                    iterating_legacy: only_legacy,
                });
            }
        }

        Ok(response)
    }

    pub fn next_legacy_credential(
        &mut self,
        cache: CredentialManagementEnumerateCredentials,
    ) -> Result<Response> {
        let CredentialManagementEnumerateCredentials {
            remaining,
            rp_dir,
            prev_filename,
            iterating_legacy,
        } = cache;

        debug_assert!(iterating_legacy);

        let mut maybe_next_rk = syscall!(self.trussed.read_dir_first(
            Location::Internal,
            rp_dir.clone(),
            prev_filename.clone()
        ))
        .entry;

        if maybe_next_rk.is_none() {
            return Err(Error::NotAllowed);
        }

        if prev_filename.is_some() {
            // This is not the first iteration
            maybe_next_rk = syscall!(self.trussed.read_dir_next()).entry;
        }

        let Some(rk) = maybe_next_rk else {
            return Err(Error::NoCredentials);
        };

        let response = self.extract_response_from_credential_file(rk.path())?;

        // cache state for next call
        if remaining > 1 {
            self.state.runtime.cached_rk = Some(CredentialManagementEnumerateCredentials {
                remaining: remaining - 1,
                rp_dir,
                prev_filename: Some(PathBuf::from(rk.file_name())),
                iterating_legacy: true,
            });
        }

        Ok(response)
    }

    pub fn next_credential(&mut self) -> Result<Response> {
        info!("next credential");

        let cache = self
            .state
            .runtime
            .cached_rk
            .take()
            .ok_or(Error::NotAllowed)?;

        if cache.iterating_legacy {
            return self.next_legacy_credential(cache);
        }

        let CredentialManagementEnumerateCredentials {
            remaining,
            rp_dir,
            prev_filename,
            iterating_legacy: _,
        } = cache;

        debug_assert!(prev_filename.is_some());

        syscall!(self.trussed.read_dir_first_alphabetical(
            Location::Internal,
            rp_dir.clone(),
            prev_filename
        ))
        .entry;

        // The previous entry was already read. Skip to the next
        let Some(entry) = syscall!(self.trussed.read_dir_next()).entry else {
            return Err(Error::NoCredentials);
        };

        if entry.file_name().cmp_lfs(&rp_dir) == Ordering::Greater {
            // We reached the end of the credentials for the rp
            return Err(Error::NoCredentials);
        }

        if entry.metadata().is_dir() {
            return self.next_legacy_credential(CredentialManagementEnumerateCredentials {
                remaining,
                rp_dir: entry.path().into(),
                prev_filename: None,
                iterating_legacy: true,
            });
        }

        let response = self.extract_response_from_credential_file(entry.path())?;

        // cache state for next call
        if remaining > 1 {
            self.state.runtime.cached_rk = Some(CredentialManagementEnumerateCredentials {
                remaining: remaining - 1,
                rp_dir,
                prev_filename: Some(entry.file_name().into()),
                iterating_legacy: false,
            });
        }

        Ok(response)
    }

    fn extract_response_from_credential_file(&mut self, rk_path: &Path) -> Result<Response> {
        // user (0x06)
        // credentialID (0x07): PublicKeyCredentialDescriptor
        // publicKey (0x08): public key of the credential in COSE_Key format
        // totalCredentials (0x09): total number of credentials for this RP
        // credProtect (0x0A): credential protection policy

        let serialized = syscall!(self.trussed.read_file(Location::Internal, rk_path.into(),)).data;

        let credential = FullCredential::deserialize(&serialized)
            // this may be a confusing error message
            .map_err(|_| Error::InvalidCredential)?;

        // now fill response

        // why these contortions to get kek. sheesh
        let authnr = &mut self.authnr;
        let kek = authnr
            .state
            .persistent
            .key_encryption_key(&mut authnr.trussed)?;

        let credential_id = credential.id(&mut self.trussed, kek, None)?;

        use crate::credential::Key;
        let private_key = match credential.key {
            Key::ResidentKey(key) => key,
            _ => return Err(Error::InvalidCredential),
        };

        use crate::SigningAlgorithm;
        use trussed::types::{KeySerialization, Mechanism};

        let algorithm = SigningAlgorithm::try_from(credential.algorithm)?;
        let cose_public_key = match algorithm {
            SigningAlgorithm::P256 => {
                let public_key = syscall!(self
                    .trussed
                    .derive_p256_public_key(private_key, Location::Volatile))
                .key;
                let cose_public_key = syscall!(self.trussed.serialize_key(
                    Mechanism::P256,
                    public_key,
                    // KeySerialization::EcdhEsHkdf256
                    KeySerialization::Cose,
                ))
                .serialized_key;
                syscall!(self.trussed.delete(public_key));
                PublicKey::P256Key(ctap_types::serde::cbor_deserialize(&cose_public_key).unwrap())
            }
            SigningAlgorithm::Ed25519 => {
                let public_key = syscall!(self
                    .trussed
                    .derive_ed255_public_key(private_key, Location::Volatile))
                .key;
                let cose_public_key = syscall!(self
                    .trussed
                    .serialize_ed255_key(public_key, KeySerialization::Cose))
                .serialized_key;
                syscall!(self.trussed.delete(public_key));
                PublicKey::Ed25519Key(
                    ctap_types::serde::cbor_deserialize(&cose_public_key).unwrap(),
                )
            } // SigningAlgorithm::Totp => {
              //     PublicKey::TotpKey(Default::default())
              // }
        };
        let cred_protect = match credential.cred_protect {
            Some(x) => Some(x),
            None => Some(CredentialProtectionPolicy::Optional),
        };

        let response = Response {
            user: Some(credential.data.user),
            credential_id: Some(credential_id.into()),
            public_key: Some(cose_public_key),
            cred_protect,
            large_blob_key: credential.data.large_blob_key,
            ..Default::default()
        };

        Ok(response)
    }

    pub fn delete_credential(
        &mut self,
        credential_descriptor: &PublicKeyCredentialDescriptor,
    ) -> Result<Response> {
        info!("delete credential");
        let credential_id_hash = self.hash(&credential_descriptor.id[..]);
        let mut hex = [b'0'; 16];
        super::format_hex(&credential_id_hash[..8], &mut hex);
        let dir = PathBuf::from(b"rk");
        let filename = PathBuf::from(&hex);

        let rk_path = syscall!(self
            .trussed
            .locate_file(Location::Internal, Some(dir), filename,))
        .path
        .ok_or(Error::InvalidCredential)?;

        // DELETE
        self.delete_resident_key_by_path(&rk_path)?;

        // get rid of directory if it's now empty
        let rp_path = rk_path
            .parent()
            // by construction, RK has a parent, its RP
            .unwrap();
        self.delete_rp_dir_if_empty(rp_path);

        // just return OK
        let response = Default::default();
        Ok(response)
    }
}
