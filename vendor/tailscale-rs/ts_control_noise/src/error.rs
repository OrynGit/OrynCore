// 来源：https://github.com/tailscale/tailscale-rs，ts_control_noise/src/error.rs
// commit: f4781c480e8d1376aed89f737beefe7425e8b866；BSD-3-Clause；Copyright (c) 2026 Tailscale Inc & contributors.
// 完整许可：OrynCore/vendor/tailscale-rs/LICENSE。
use zerocopy::{SizeError, TryCastError};

/// Error encountered with Noise communication.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid message format.
    #[error("invalid message format")]
    BadFormat,

    /// Handshake failed.
    #[error("handshake failed to complete")]
    HandshakeFailed,

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl<M> From<TryCastError<&[u8], M>> for Error
where
    M: ?Sized + zerocopy::TryFromBytes,
{
    fn from(_value: TryCastError<&[u8], M>) -> Self {
        Error::BadFormat
    }
}

impl<M> From<TryCastError<&mut [u8], M>> for Error
where
    M: ?Sized + zerocopy::TryFromBytes,
{
    fn from(_value: TryCastError<&mut [u8], M>) -> Self {
        Error::BadFormat
    }
}

impl<M> From<SizeError<&M, &mut [u8]>> for Error
where
    M: zerocopy::TryFromBytes,
{
    fn from(_value: SizeError<&M, &mut [u8]>) -> Self {
        Error::BadFormat
    }
}

impl From<core::str::Utf8Error> for Error {
    fn from(_value: core::str::Utf8Error) -> Self {
        Error::BadFormat
    }
}

impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        std::io::Error::other(value.to_string())
    }
}
