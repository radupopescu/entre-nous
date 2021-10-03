//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use {
    std::array::TryFromSliceError,
};

pub type Result<T> = std::result::Result<T, Error>;

/// The errors which can be produced by the library
#[derive(Debug)]
pub enum Error {
    Initialization,
    Verification,
    InvalidSignature,
    MissingVerificationKey,
    InvalidSize(TryFromSliceError),
    InvalidSliceSize,
    StreamingEncryptionInit,
    StreamingEncryptionPush,
    StreamingEncryptionFinalize,
    StreamingDecryptionInit,
    StreamingDecryptionPull,
    StreamingRead,
    StreamingWrite,
    PasswordHashing,
    Base64(base64::DecodeError),
    SRP(srp::types::SrpAuthError),
    IO(std::io::Error),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::Initialization => None,
            Error::Verification => None,
            Error::InvalidSignature => None,
            Error::MissingVerificationKey => None,
            Error::InvalidSize(ref source) => Some(source),
            Error::InvalidSliceSize => None,
            Error::StreamingEncryptionInit => None,
            Error::StreamingEncryptionPush => None,
            Error::StreamingEncryptionFinalize => None,
            Error::StreamingDecryptionInit => None,
            Error::StreamingDecryptionPull => None,
            Error::StreamingRead => None,
            Error::StreamingWrite => None,
            Error::PasswordHashing => None,
            Error::Base64(ref source) => Some(source),
            Error::SRP(ref source) => Some(source),
            Error::IO(ref source) => Some(source),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Initialization => write!(f, "Initialization error"),
            Error::Verification => write!(f, "Verification error"),
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::MissingVerificationKey => {
                write!(f, "Unable to verify signature. Missing verification key")
            }
            Error::InvalidSize(ref source) => source.fmt(f),
            Error::InvalidSliceSize => write!(f, "Invalid size of input slice"),
            Error::StreamingEncryptionInit => write!(f, "Error initializing encryption stream"),
            Error::StreamingEncryptionPush => write!(f, "Error pushing to encryption stream"),
            Error::StreamingEncryptionFinalize => write!(f, "Error finalizing encryption stream"),
            Error::StreamingDecryptionInit => write!(f, "Error initializing decryption stream"),
            Error::StreamingDecryptionPull => write!(f, "Error pulling from decryption stream"),
            Error::StreamingRead => write!(f, "Error reading from stream"),
            Error::StreamingWrite => write!(f, "Error writing to stream"),
            Error::PasswordHashing => write!(f, "Error deriving key from password"),
            Error::Base64(ref source) => source.fmt(f),
            Error::SRP(ref source) => source.fmt(f),
            Error::IO(ref source) => source.fmt(f),
        }
    }
}

impl From<TryFromSliceError> for Error {
    fn from(err: TryFromSliceError) -> Error {
        Error::InvalidSize(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        Error::Base64(err)
    }
}
impl From<srp::types::SrpAuthError> for Error {
    fn from(err: srp::types::SrpAuthError) -> Error {
        Error::SRP(err)
    }
}
