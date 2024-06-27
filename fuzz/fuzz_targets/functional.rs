#![no_main]

use fido_authenticator::{Authenticator, Config, Conforming};
use trussed_staging::virt;

use ctap_types::{
    ctap1::Authenticator as _,
    ctap1::{authenticate, register},
    ctap2::make_credential,
    ctap2::Authenticator as _,
};

use arbitrary::Arbitrary;

use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary, Eq, PartialEq)]
enum Action<'a> {
    MakeCredential {
        request: make_credential::Request<'a>,
    },
    Register {
        request: register::Request<'a>,
    },
    Authenticate {
        request: authenticate::Request<'a>,
    },
}

fuzz_target!(|actions: Vec<Action<'_>>| {
    virt::with_ram_client("fido", |client| {
        let mut authenticator = Authenticator::new(
            client,
            Conforming {},
            Config {
                max_msg_size: 0,
                skip_up_timeout: None,
                max_resident_credential_count: Some(20),
                large_blobs: None,
                nfc_transport: false,
            },
        );
        for action in actions {
            match action {
                Action::MakeCredential { request: req } => {
                    authenticator.make_credential(&req).ok();
                }
                Action::Register { request: req } => {
                    authenticator.register(&req).ok();
                }
                Action::Authenticate { request: req } => {
                    authenticator.authenticate(&req).ok();
                }
            }
        }
    });
});
