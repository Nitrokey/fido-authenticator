use trussed_derive::{ExtensionDispatch, ExtensionId};
use trussed_hkdf::{HkdfBackend, HkdfExtension};

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
