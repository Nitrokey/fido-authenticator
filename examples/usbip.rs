// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: CC0-1.0

//! USB/IP runner for opcard.
//! Run with cargo run --example usbip --features dispatch

use littlefs2_core::path;
use trussed::{
    backend::BackendId,
    pipe::{ServiceEndpoint, TrussedChannel},
    service::Service,
    types::{CoreContext, Location},
    virt::{Platform, StoreConfig},
};
use trussed_staging::{
    virt::{BackendIds, Dispatcher},
    StagingContext,
};
use trussed_usbip::{Client, Syscall};

const MANUFACTURER: &str = "Nitrokey";
const PRODUCT: &str = "Nitrokey 3";
const VID: u16 = 0x20a0;
const PID: u16 = 0x42b2;

type VirtClient = Client<Dispatcher>;

struct FidoApp {
    fido: fido_authenticator::Authenticator<fido_authenticator::Conforming, VirtClient>,
}

impl trussed_usbip::Apps<'static, Dispatcher> for FidoApp {
    type Data = ();
    fn new(
        _service: &mut Service<Platform, Dispatcher>,
        endpoints: &mut Vec<ServiceEndpoint<'static, BackendIds, StagingContext>>,
        syscall: Syscall,
        _data: (),
    ) -> Self {
        let large_blogs = Some(fido_authenticator::LargeBlobsConfig {
            location: Location::External,
            #[cfg(feature = "chunked")]
            max_size: 4096,
        });

        static CHANNEL: TrussedChannel = TrussedChannel::new();
        let (requester, responder) = CHANNEL.split().unwrap();
        let context = CoreContext::new(path!("fido").into());
        let backends = &[
            BackendId::Core,
            BackendId::Custom(BackendIds::StagingBackend),
        ];
        endpoints.push(ServiceEndpoint::new(responder, context, backends));
        let client = Client::new(requester, syscall, None);
        FidoApp {
            fido: fido_authenticator::Authenticator::new(
                client,
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
        f: impl FnOnce(
            &mut [&mut dyn ctaphid_dispatch::app::App<
                'static,
                { ctaphid_dispatch::MESSAGE_SIZE },
            >],
        ) -> T,
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
    trussed_usbip::Builder::new(StoreConfig::ram(), options)
        .dispatch(Dispatcher::default())
        .build::<FidoApp>()
        .exec(|_platform| {});
}
