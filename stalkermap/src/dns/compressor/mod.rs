//! Stalkermap DNS Message Compressor

#[cfg(all(feature = "agnostic", any(feature = "std", feature = "tokio-dep")))]
compile_error!("Features `agnostic` and (`std`/`tokio`) cannot be enabled at the same time");

//#[cfg(feature = "agnostic")]
//pub mod agnostic;

//#[cfg(any(feature = "std", feature = "tokio-dep", doc))]
//mod standard;

//#[cfg(feature = "agnostic")]
//pub use self::agnostic::{CompressorErrors, MessageCompressor};

//#[cfg(any(feature = "std", feature = "tokio-dep", doc))]
//pub(crate) use self::standard::{DecompressorErrors, MessageCompressor};

cfg_if::cfg_if! {
    if #[cfg(any(feature = "std", feature = "tokio-dep"))] {
        mod standard;
        pub(crate) use self::standard::{DecompressorErrors, MessageCompressor};
    } else if #[cfg(feature = "agnostic")] {
        pub mod agnostic;
        pub use self::agnostic::{CompressorErrors, MessageCompressor};
    } else if #[cfg(doc)] {
        pub mod agnostic;
        pub use self::agnostic::{CompressorErrors, MessageCompressor};
    }
}
