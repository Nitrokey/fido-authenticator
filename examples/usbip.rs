// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

//! USB/IP runner for fido-authenticator.
//! Run with cargo run --example usbip --features trussed/virt,dispatch

use trussed::backend::BackendId;
use trussed::types::Location;
use trussed::virt::{self, Ram};
use trussed::ClientImplementation;
use trussed_derive::{ExtensionDispatch, ExtensionId};
use trussed_hkdf::{HkdfBackend, HkdfExtension};
use trussed_usbip::ClientBuilder;

const MANUFACTURER: &str = "Nitrokey";
const PRODUCT: &str = "Nitrokey 3";
const VID: u16 = 0x20a0;
const PID: u16 = 0x42b2;

#[derive(ExtensionDispatch)]
#[dispatch(backend_id = "Backend", extension_id = "Extension")]
#[extensions(Hkdf = "HkdfExtension")]
#[cfg_attr(
    feature = "chunked",
    extensions(Chunked = "trussed_chunked::ChunkedExtension")
)]
pub struct Dispatch {
    #[cfg(feature = "chunked")]
    #[extensions("Chunked")]
    staging: trussed_staging::StagingBackend,
    #[extensions("Hkdf")]
    hkdf: HkdfBackend,
}

impl Default for Dispatch {
    fn default() -> Self {
        Self {
            #[cfg(feature = "chunked")]
            staging: Default::default(),
            hkdf: HkdfBackend,
        }
    }
}

pub enum Backend {
    #[cfg(feature = "chunked")]
    Staging,
    Hkdf,
}

#[derive(ExtensionId)]
pub enum Extension {
    #[cfg(feature = "chunked")]
    Chunked = 0,
    Hkdf = 1,
}

type VirtClient = ClientImplementation<trussed_usbip::Service<Ram, Dispatch>, Dispatch>;

struct FidoApp {
    fido: fido_authenticator::Authenticator<fido_authenticator::Conforming, VirtClient>,
}

impl trussed_usbip::Apps<'static, VirtClient, Dispatch> for FidoApp {
    type Data = ();
    fn new<B: ClientBuilder<VirtClient, Dispatch>>(builder: &B, _data: ()) -> Self {
        let large_blogs = Some(fido_authenticator::LargeBlobsConfig {
            location: Location::External,
            #[cfg(feature = "chunked")]
            max_size: 4096,
        });

        FidoApp {
            fido: fido_authenticator::Authenticator::new(
                builder.build(
                    "fido",
                    &[
                        BackendId::Core,
                        BackendId::Custom(Backend::Hkdf),
                        #[cfg(feature = "chunked")]
                        BackendId::Custom(Backend::Staging),
                    ],
                ),
                fido_authenticator::Conforming {},
                fido_authenticator::Config {
                    max_msg_size: usbd_ctaphid::constants::MESSAGE_SIZE,
                    skip_up_timeout: None,
                    max_resident_credential_count: Some(10),
                    large_blobs: large_blogs,
                    nfc_transport: false,
                },
            ),
        }
    }

    fn with_ctaphid_apps<T>(
        &mut self,
        f: impl FnOnce(&mut [&mut dyn ctaphid_dispatch::app::App<'static>]) -> T,
    ) -> T {
        f(&mut [&mut self.fido])
    }
}

fn main() {
    env_logger::init();

    let options = trussed_usbip::Options {
        manufacturer: Some(MANUFACTURER.to_owned()),
        product: Some(PRODUCT.to_owned()),
        serial_number: Some("TEST".into()),
        vid: VID,
        pid: PID,
    };
    trussed_usbip::Builder::new(virt::Ram::default(), options)
        .dispatch(Dispatch::default())
        .build::<FidoApp>()
        .exec(|_platform| {});
}
