//! Stalkermap DNS Message Compressor

#[cfg(all(feature = "agnostic", any(feature = "std", feature = "tokio-dep")))]
compile_error!("Features `agnostic` and (`std`/`tokio`) cannot be enabled at the same time");

#[cfg(feature = "agnostic")]
pub mod agnostic;

#[cfg(any(feature = "std", feature = "tokio-dep"))]
mod standard;

#[cfg(feature = "agnostic")]
pub use self::agnostic::{CompressorErrors, MessageCompressor};

#[cfg(any(feature = "std", feature = "tokio-dep"))]
#[allow(unused_imports)]
pub(crate) use self::standard::{CompressorErrors, MessageCompressor};
