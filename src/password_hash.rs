//
// Copyright 2021 Radu Popescu <mail@radupopescu.net>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use sodiumoxide::crypto::pwhash::{
    derive_key_interactive, gen_salt as sodium_gen_salt, Salt as SodiumSalt,
};

use crate::errors::{Error, Result};

pub struct Salt(pub(crate) SodiumSalt);

impl Salt {
    pub fn new() -> Salt {
        Salt(sodium_gen_salt())
    }

    pub fn from_slice(s: &[u8]) -> Result<Salt> {
        let salt = SodiumSalt::from_slice(s).ok_or(Error::InvalidSliceSize)?;
        Ok(Salt(salt))
    }
}

pub fn derive_key<'a>(key: &'a mut [u8], password: &[u8], salt: &Salt) -> Result<&'a [u8]> {
    derive_key_interactive(key, password, &salt.0).map_err(|_| Error::PasswordHashing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() -> Result<()> {
        let password = "SECURE PASSWORD";
        let salt = Salt::new();
        let mut key_in = vec![0; 32];
        let key_out = derive_key(key_in.as_mut_slice(), password.as_bytes(), &salt)?;
        assert_eq!(key_out.len(), key_in.len());
        Ok(())
    }
}
